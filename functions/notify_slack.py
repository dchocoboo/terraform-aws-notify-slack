# -*- coding: utf-8 -*-
"""
    Notify Slack
    ------------

    Receives event payloads that are parsed and sent to Slack

"""

import base64
import json
import logging
import os
import re
import urllib.parse
import urllib.request
from enum import Enum
from typing import Any, Dict, Optional, Union, cast
from urllib.error import HTTPError

import boto3

# Set default region if not provided
REGION = os.environ.get("AWS_REGION", "us-east-1")

KEYWORD_MENTIONS: Dict[str, list] = {}
_raw = os.environ.get("SLACK_KEYWORD_MENTIONS", "")
if _raw:
    try:
        KEYWORD_MENTIONS = json.loads(_raw)
    except json.JSONDecodeError:
        logging.warning("Invalid JSON in SLACK_KEYWORD_MENTIONS, ignoring")

# Create client so its cached/frozen between invocations
KMS_CLIENT = boto3.client("kms", region_name=REGION)

SECURITY_HUB_CLIENT = boto3.client('securityhub', region_name=REGION)

BACKUP_CLIENT = boto3.client("backup", region_name=REGION)


class AwsService(Enum):
    """AWS service supported by function"""

    cloudwatch = "cloudwatch"
    guardduty = "guardduty"
    securityhub = "securityhub"


def decrypt_url(encrypted_url: str) -> str:
    """Decrypt encrypted URL with KMS

    :param encrypted_url: URL to decrypt with KMS
    :returns: plaintext URL
    """
    try:
        decrypted_payload = KMS_CLIENT.decrypt(
            CiphertextBlob=base64.b64decode(encrypted_url)
        )
        return decrypted_payload["Plaintext"].decode()
    except Exception:
        logging.exception("Failed to decrypt URL with KMS")
        return ""


def get_service_url(region: str, service: str) -> str:
    """Get the appropriate service URL for the region

    :param region: name of the AWS region
    :param service: name of the AWS service
    :returns: AWS console url formatted for the region and service provided
    """
    try:
        service_name = AwsService[service].value
        if region.startswith("us-gov-"):
            return f"https://console.amazonaws-us-gov.com/{service_name}/home?region={region}"
        else:
            return f"https://console.aws.amazon.com/{service_name}/home?region={region}"

    except KeyError:
        print(f"Service {service} is currently not supported")
        raise


class CloudWatchAlarmState(Enum):
    """Maps CloudWatch notification state to Slack message format color"""

    OK = "good"
    INSUFFICIENT_DATA = "warning"
    ALARM = "danger"


def format_cloudwatch_alarm(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """Format CloudWatch alarm event into Slack message format

    :params message: SNS message body containing CloudWatch alarm event
    :region: AWS region where the event originated from
    :returns: formatted Slack message payload
    """

    cloudwatch_url = get_service_url(region=region, service="cloudwatch")
    alarm_name = message["AlarmName"]
    alarm_link = f"{cloudwatch_url}#alarm:alarmFilter=ANY;name={urllib.parse.quote(alarm_name)}"
    
    # Build the fields list, conditionally including alarm description
    fields = [
        {"title": "Alarm Name", "value": f"<{alarm_link}|{alarm_name}>", "short": True},
    ]
    
    # Only include alarm description if it has a meaningful value
    alarm_description = message.get('AlarmDescription') or ''
    alarm_description = alarm_description.strip() if alarm_description else ''
    if alarm_description and alarm_description.lower() not in ['none', 'null', '', 'n/a']:
        fields.append({
            "title": "Alarm Description",
            "value": f"`{alarm_description}`",
            "short": False,
        })
    
    # Add the remaining fields
    fields.extend([
        {
            "title": "Alarm reason",
            "value": f"`{message['NewStateReason']}`",
            "short": False,
        },
    ])
    
    # Only show old state if it's not the common OK -> ALARM transition
    old_state = message['OldStateValue']
    new_state = message['NewStateValue']
    if not (old_state == 'OK' and new_state == 'ALARM'):
        fields.append({
            "title": "Old State",
            "value": f"`{old_state}`",
            "short": True,
        })
    
    fields.extend([
        {
            "title": "Current State",
            "value": f"`{new_state}`",
            "short": True,
        },
    ])

    return {
        "color": CloudWatchAlarmState[message["NewStateValue"]].value,
        "fallback": f"Alarm {alarm_name} triggered",
        "fields": fields,
        "text": "AWS CloudWatch notification",
    }


def format_aws_security_hub(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format AWS Security Hub finding event into Slack message format

    :params message: SNS message body containing SecurityHub finding event
    :params region: AWS region where the event originated from
    :returns: formatted Slack message payload
    """
    service_url = get_service_url(region=region, service="securityhub")
    finding = message["detail"]["findings"][0]

    # Switch Status From New To Notified To Prevent Repeated Messages
    try:
        compliance_status = finding["Compliance"].get("Status", "UNKNOWN")
        workflow_status = finding["Workflow"].get("Status", "UNKNOWN")
        if compliance_status == "FAILED" and workflow_status == "NEW":
            notified = SECURITY_HUB_CLIENT.batch_update_findings(
                FindingIdentifiers=[{
                    'Id': finding.get('Id'),
                    'ProductArn': finding.get("ProductArn")
                }],
                Workflow={"Status": "NOTIFIED"}
            )
            logging.warning(f"Successfully updated finding status to NOTIFIED: {json.dumps(notified)}")
    except Exception as e:
        logging.error(f"Failed to update finding status: {str(e)}")
        pass

    if finding.get("ProductName") == "Inspector":
        severity = finding["Severity"].get("Label", "INFORMATIONAL")
        compliance_status = finding["Compliance"].get("Status", "UNKNOWN")

        Id = finding.get("Id", "No ID Provided")
        title = finding.get("Title", "No Title Provided")
        description = finding.get("Description", "No Description Provided")
        control_id = finding['ProductFields'].get('ControlId', 'N/A')
        control_url = service_url + f"#/controls/{control_id}"
        aws_account_id = finding.get('AwsAccountId', 'Unknown Account')
        first_observed = finding.get('FirstObservedAt', 'Unknown Date')
        last_updated = finding.get('UpdatedAt', 'Unknown Date')
        affected_resource = finding['Resources'][0].get('Id', 'Unknown Resource')
        remediation_url = finding.get("Remediation", {}).get("Recommendation", {}).get("Url", "#")

        finding_base_path = "#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A"
        double_encoded_id = urllib.parse.quote(urllib.parse.quote(Id, safe=''), safe='')
        finding_url = f"{service_url}{finding_base_path}{double_encoded_id}"
        generator_id = finding.get("GeneratorId", "Unknown Generator")

        color = SecurityHubSeverity.get(severity.upper(), SecurityHubSeverity.INFORMATIONAL).value
        if compliance_status == "PASSED":
            color = "#4BB543"

        slack_message = {
            "color": color,
            "fallback": f"Inspector Finding: {title}",
            "fields": [
                {"title": "Title", "value": f"`{title}`", "short": False},
                {"title": "Description", "value": f"`{description}`", "short": False},
                {"title": "Compliance Status", "value": f"`{compliance_status}`", "short": True},
                {"title": "Severity", "value": f"`{severity}`", "short": True},
                {"title": "Control ID", "value": f"`{control_id}`", "short": True},
                {"title": "Account ID", "value": f"`{aws_account_id}`", "short": True},
                {"title": "First Observed", "value": f"`{first_observed}`", "short": True},
                {"title": "Last Updated", "value": f"`{last_updated}`", "short": True},
                {"title": "Affected Resource", "value": f"`{affected_resource}`", "short": False},
                {"title": "Generator", "value": f"`{generator_id}`", "short": False},
                {"title": "Control Url", "value": f"`{control_url}`", "short": False},
                {"title": "Finding Url", "value": f"`{finding_url}`", "short": False},
                {"title": "Remediation", "value": f"`{remediation_url}`", "short": False},
            ],
            "text": f"AWS Inspector Finding - {title}",
        }

        return slack_message

    if finding.get("ProductName") == "Security Hub":
        severity = finding["Severity"].get("Label", "INFORMATIONAL")
        compliance_status = finding["Compliance"].get("Status", "UNKNOWN")

        Id = finding.get("Id", "No ID Provided")
        title = finding.get("Title", "No Title Provided")
        description = finding.get("Description", "No Description Provided")
        control_id = finding['ProductFields'].get('ControlId', 'N/A')
        control_url = service_url + f"#/controls/{control_id}"
        aws_account_id = finding.get('AwsAccountId', 'Unknown Account')
        first_observed = finding.get('FirstObservedAt', 'Unknown Date')
        last_updated = finding.get('UpdatedAt', 'Unknown Date')
        affected_resource = finding['Resources'][0].get('Id', 'Unknown Resource')
        remediation_url = finding.get("Remediation", {}).get("Recommendation", {}).get("Url", "#")
        generator_id = finding.get("GeneratorId", "Unknown Generator")

        finding_base_path = "#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A"
        double_encoded_id = urllib.parse.quote(urllib.parse.quote(Id, safe=''), safe='')
        finding_url = f"{service_url}{finding_base_path}{double_encoded_id}"

        color = SecurityHubSeverity.get(severity.upper(), SecurityHubSeverity.INFORMATIONAL).value
        if compliance_status == "PASSED":
            color = "#4BB543"

        slack_message = {
            "color": color,
            "fallback": f"Security Hub Finding: {title}",
            "fields": [
                {"title": "Title", "value": f"`{title}`", "short": False},
                {"title": "Description", "value": f"`{description}`", "short": False},
                {"title": "Compliance Status", "value": f"`{compliance_status}`", "short": True},
                {"title": "Severity", "value": f"`{severity}`", "short": True},
                {"title": "Control ID", "value": f"`{control_id}`", "short": True},
                {"title": "Account ID", "value": f"`{aws_account_id}`", "short": True},
                {"title": "First Observed", "value": f"`{first_observed}`", "short": True},
                {"title": "Last Updated", "value": f"`{last_updated}`", "short": True},
                {"title": "Affected Resource", "value": f"`{affected_resource}`", "short": False},
                {"title": "Generator", "value": f"`{generator_id}`", "short": False},
                {"title": "Control Url", "value": f"`{control_url}`", "short": False},
                {"title": "Finding Url", "value": f"`{finding_url}`", "short": False},
                {"title": "Remediation", "value": f"`{remediation_url}`", "short": False},
            ],
            "text": f"AWS Security Hub Finding - {title}",
        }

        return slack_message

    return format_default(message=message)


class SecurityHubSeverity(Enum):
    """Maps Security Hub finding severity to Slack message format color"""

    CRITICAL = "danger"
    HIGH = "danger"
    MEDIUM = "warning"
    LOW = "#777777"
    INFORMATIONAL = "#439FE0"

    @staticmethod
    def get(name, default):
        try:
            return SecurityHubSeverity[name]
        except KeyError:
            return default


class GuardDutyFindingSeverity(Enum):
    """Maps GuardDuty finding severity to Slack message format color"""

    Low = "#777777"
    Medium = "warning"
    High = "danger"


def format_guardduty_finding(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format GuardDuty finding event into Slack message format

    :params message: SNS message body containing GuardDuty finding event
    :params region: AWS region where the event originated from
    :returns: formatted Slack message payload
    """

    guardduty_url = get_service_url(region=region, service="guardduty")
    detail = message["detail"]
    service = detail.get("service", {})
    severity_score = detail.get("severity")

    if severity_score < 4.0:
        severity = "Low"
    elif severity_score < 7.0:
        severity = "Medium"
    else:
        severity = "High"

    return {
        "color": GuardDutyFindingSeverity[severity].value,
        "fallback": f"GuardDuty Finding: {detail.get('title')}",
        "fields": [
            {
                "title": "Description",
                "value": f"`{detail['description']}`",
                "short": False,
            },
            {
                "title": "Finding Type",
                "value": f"`{detail['type']}`",
                "short": False,
            },
            {
                "title": "First Seen",
                "value": f"`{service['eventFirstSeen']}`",
                "short": True,
            },
            {
                "title": "Last Seen",
                "value": f"`{service['eventLastSeen']}`",
                "short": True,
            },
            {"title": "Severity", "value": f"`{severity}`", "short": True},
            {"title": "Account ID", "value": f"`{detail['accountId']}`", "short": True},
            {
                "title": "Count",
                "value": f"`{service['count']}`",
                "short": True,
            },
            {
                "title": "Link to Finding",
                "value": f"{guardduty_url}#/findings?search=id%3D{detail['id']}",
                "short": False,
            },
        ],
        "text": f"AWS GuardDuty Finding - {detail.get('title')}",
    }


class AwsHealthCategory(Enum):
    """Maps AWS Health eventTypeCategory to Slack message format color

    eventTypeCategory
        The category code of the event. The possible values are issue,
        accountNotification, and scheduledChange.
    """

    accountNotification = "#777777"
    scheduledChange = "warning"
    issue = "danger"


def format_aws_health(message: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    Format AWS Health event into Slack message format

    :params message: SNS message body containing AWS Health event
    :params region: AWS region where the event originated from
    :returns: formatted Slack message payload
    """

    aws_health_url = (
        f"https://phd.aws.amazon.com/phd/home?region={region}#/dashboard/open-issues"
    )
    detail = message["detail"]
    resources = message.get("resources", "<unknown>")
    service = detail.get("service", "<unknown>")

    return {
        "color": AwsHealthCategory[detail["eventTypeCategory"]].value,
        "text": f"New AWS Health Event for {service}",
        "fallback": f"New AWS Health Event for {service}",
        "fields": [
            {"title": "Affected Service", "value": f"`{service}`", "short": True},
            {
                "title": "Affected Region",
                "value": f"`{message.get('region')}`",
                "short": True,
            },
            {
                "title": "Code",
                "value": f"`{detail.get('eventTypeCode')}`",
                "short": False,
            },
            {
                "title": "Event Description",
                "value": f"`{detail['eventDescription'][0]['latestDescription']}`",
                "short": False,
            },
            {
                "title": "Affected Resources",
                "value": f"`{', '.join(resources)}`",
                "short": False,
            },
            {
                "title": "Start Time",
                "value": f"`{detail.get('startTime', '<unknown>')}`",
                "short": True,
            },
            {
                "title": "End Time",
                "value": f"`{detail.get('endTime', '<unknown>')}`",
                "short": True,
            },
            {
                "title": "Link to Event",
                "value": f"{aws_health_url}",
                "short": False,
            },
        ],
    }


class BackupJobState(Enum):
    """Maps AWS Backup job state to Slack message format color"""

    COMPLETED = "good"
    FAILED = "danger"
    EXPIRED = "danger"
    ABORTED = "warning"
    PARTIAL = "warning"
    RUNNING = "#439FE0"


def aws_backup_field_parser(message: str) -> Dict[str, str]:
    """
    Parser for AWS Backup event message. It extracts the fields from the message and returns a dictionary.

    :params message: message containing AWS Backup event
    :returns: dictionary containing the fields extracted from the message
    """
    # Each value is a single whitespace-free token (a UUID or an ARN) that runs up
    # to the sentence-terminating period. Anchoring on the label and capturing
    # `\S+` avoids the greedy `.*` that used to swallow the rest of the message and
    # return its last word (e.g. "failed") instead of the actual field value.
    field_names = {
        "BackupJob ID": r"BackupJob ID\s*:\s*(\S+)",
        "Resource ARN": r"Resource ARN\s*:\s*(\S+)",
        "Recovery point ARN": r"Recovery point ARN\s*:\s*(\S+)",
    }
    fields = {}

    for fname, freg in field_names.items():
        match = re.search(freg, message)
        if match:
            fields[fname] = match.group(1).rstrip(".")

    return fields


def get_backup_job_detail(job_id: str) -> tuple[Dict[str, Any], Optional[str]]:
    """
    Look up the full AWS Backup job record.

    The vault notification body only carries the job ID and resource ARN — the
    fields that actually explain a failure (status message, percent done, bytes
    transferred, resource type) are only available from the API.

    :params job_id: AWS Backup job ID
    :returns: tuple of (describe_backup_job response, error summary). Exactly one
        side is populated; the error is surfaced in Slack rather than swallowed so
        a missing IAM permission can't quietly degrade every notification.
    """
    if not job_id:
        return {}, "no BackupJob ID in the notification, cannot look up job detail"

    try:
        return BACKUP_CLIENT.describe_backup_job(BackupJobId=job_id), None
    except Exception as exc:  # noqa: BLE001 - enrichment must never drop the alert
        logging.exception("Failed to describe backup job %s", job_id)

        # boto3 ClientError carries a structured code; fall back to the class name
        code = getattr(exc, "response", {}).get("Error", {}).get("Code") or type(exc).__name__
        detail = f"`{code}` calling `backup:DescribeBackupJob`"
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            detail += " — grant `backup:DescribeBackupJob` to this Lambda's execution role"
        return {}, detail


def _sns_attribute(attributes: Optional[Dict[str, Any]], name: str) -> Optional[str]:
    """Read a single SNS MessageAttribute value

    :params attributes: SNS record MessageAttributes block
    :params name: attribute name to read
    :returns: attribute value, or None when absent
    """
    entry = (attributes or {}).get(name) or {}
    return entry.get("Value") or entry.get("value")


def _format_bytes(num: Optional[int]) -> str:
    """Render a byte count in human readable units"""
    if not num:
        return "0 B"
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:,.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:,.2f} TB"


def format_aws_backup(
    message: str, attributes: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Format AWS Backup event into Slack message format

    :params message: SNS message body containing AWS Backup event
    :params attributes: SNS record MessageAttributes (State, EventType, Id, StartTime)
    :returns: formatted Slack message payload
    """

    fields: list[Dict[str, Any]] = []

    title = message.split(".")[0]

    if "failed" in title:
        title = f"⚠️ {title}"

    if "completed" in title:
        title = f"✅ {title}"

    backup_fields = aws_backup_field_parser(message)

    # Prefer the structured SNS attribute over the ID scraped from the prose body
    job_id = _sns_attribute(attributes, "Id") or backup_fields.get("BackupJob ID", "")
    state = _sns_attribute(attributes, "State") or ""
    event_type = _sns_attribute(attributes, "EventType")
    start_time = _sns_attribute(attributes, "StartTime")

    detail, enrichment_error = get_backup_job_detail(job_id)

    resource_name = detail.get("ResourceName")
    resource_arn = detail.get("ResourceArn") or backup_fields.get("Resource ARN")
    state = detail.get("State") or state

    if resource_name or resource_arn:
        fields.append(
            {
                "title": "Resource",
                "value": f"`{resource_name or resource_arn}`",
                "short": True,
            }
        )
    if detail.get("ResourceType"):
        fields.append(
            {"title": "Resource type", "value": f"`{detail['ResourceType']}`", "short": True}
        )
    if state:
        fields.append({"title": "State", "value": f"`{state}`", "short": True})
    if event_type:
        fields.append({"title": "Event type", "value": f"`{event_type}`", "short": True})

    # The three fields that actually diagnose a failure
    if detail.get("StatusMessage"):
        fields.append(
            {"title": "Status message", "value": f"`{detail['StatusMessage']}`", "short": False}
        )
    if detail.get("MessageCategory"):
        fields.append(
            {"title": "Message category", "value": f"`{detail['MessageCategory']}`", "short": True}
        )
    if detail.get("PercentDone") is not None:
        fields.append(
            {"title": "Percent done", "value": f"`{detail['PercentDone']}%`", "short": True}
        )
    if detail.get("BytesTransferred") is not None:
        fields.append(
            {
                "title": "Bytes transferred",
                "value": f"`{_format_bytes(detail.get('BytesTransferred'))}`",
                "short": True,
            }
        )
    if detail.get("BackupSizeInBytes") is not None:
        fields.append(
            {
                "title": "Backup size",
                "value": f"`{_format_bytes(detail.get('BackupSizeInBytes'))}`",
                "short": True,
            }
        )

    for label, key in (("Started", "CreationDate"), ("Completed", "CompletionDate")):
        value = detail.get(key)
        if value is not None:
            rendered = value.isoformat() if hasattr(value, "isoformat") else str(value)
            fields.append({"title": label, "value": f"`{rendered}`", "short": True})
    if not detail and start_time:
        fields.append({"title": "Started", "value": f"`{start_time}`", "short": True})

    if detail.get("BackupVaultName"):
        fields.append(
            {"title": "Vault", "value": f"`{detail['BackupVaultName']}`", "short": True}
        )
    if job_id:
        fields.append({"title": "BackupJob ID", "value": f"`{job_id}`", "short": False})
    if resource_arn:
        fields.append({"title": "Resource ARN", "value": f"`{resource_arn}`", "short": False})
    if backup_fields.get("Recovery point ARN"):
        fields.append(
            {
                "title": "Recovery point ARN",
                "value": f"`{backup_fields['Recovery point ARN']}`",
                "short": False,
            }
        )

    # Surface enrichment failure loudly. A missing IAM permission would otherwise
    # silently strip every diagnostic field and leave only the terse SNS body,
    # which looks identical to "AWS didn't tell us anything".
    if enrichment_error:
        fields.append(
            {
                "title": "⚠️ Job detail unavailable",
                "value": enrichment_error,
                "short": False,
            }
        )

    attachments: Dict[str, Any] = {
        "fallback": title,
        "title": title,
        "fields": fields,
        "text": "AWS Backup notification",
        "mrkdwn_in": ["value", "text"],
    }

    try:
        attachments["color"] = BackupJobState[state.upper()].value
    except KeyError:
        pass

    return attachments


def format_default(
    message: Union[str, Dict], subject: Optional[str] = None
) -> Dict[str, Any]:
    """
    Default formatter, converting event into Slack message format

    :params message: SNS message body containing message/event
    :returns: formatted Slack message payload
    """

    attachments = {
        "fallback": "A new message",
        "text": "AWS notification",
        "title": subject if subject else "Message",
        "mrkdwn_in": ["value"],
    }
    fields = []

    if type(message) is dict:
        for k, v in message.items():
            value = f"{json.dumps(v)}" if isinstance(v, (dict, list)) else str(v)
            fields.append({"title": k, "value": f"`{value}`", "short": len(value) < 25})
    else:
        fields.append({"value": message, "short": False})

    if fields:
        attachments["fields"] = fields  # type: ignore

    return attachments


def parse_notification(
    message: Dict[str, Any],
    subject: Optional[str],
    region: str,
    attributes: Optional[Dict[str, Any]] = None,
) -> Optional[Dict]:
    """
    Parse notification message and format into Slack message payload

    :params message: SNS message body notification payload
    :params subject: Optional subject line for Slack notification
    :params region: AWS region where the event originated from
    :params attributes: Optional SNS record MessageAttributes
    :returns: Slack message payload
    """
    if "AlarmName" in message:
        return format_cloudwatch_alarm(message=message, region=region)
    if isinstance(message, Dict) and message.get("detail-type") == "GuardDuty Finding":
        return format_guardduty_finding(message=message, region=message["region"])
    if isinstance(message, Dict) and message.get("detail-type") == "Security Hub Findings - Imported":
        return format_aws_security_hub(message=message, region=message["region"])
    if isinstance(message, Dict) and message.get("detail-type") == "AWS Health Event":
        return format_aws_health(message=message, region=message["region"])
    if subject == "Notification from AWS Backup":
        return format_aws_backup(message=str(message), attributes=attributes)
    return format_default(message=message, subject=subject)


def get_slack_message_payload(
    message: Union[str, Dict],
    region: str,
    subject: Optional[str] = None,
    attributes: Optional[Dict[str, Any]] = None,
) -> Dict:
    """
    Parse notification message and format into Slack message payload

    :params message: SNS message body notification payload
    :params region: AWS region where the event originated from
    :params subject: Optional subject line for Slack notification
    :params attributes: Optional SNS record MessageAttributes
    :returns: Slack message payload
    """

    slack_channel = os.environ["SLACK_CHANNEL"]
    slack_username = os.environ["SLACK_USERNAME"]
    slack_emoji = os.environ["SLACK_EMOJI"]

    payload = {
        "channel": slack_channel,
        "username": slack_username,
        "icon_emoji": slack_emoji,
    }
    attachment = None

    if isinstance(message, str):
        try:
            message = json.loads(message)
        except json.JSONDecodeError:
            logging.info("Not a structured payload, just a string message")

    message = cast(Dict[str, Any], message)

    if "attachments" in message or "text" in message:
        payload = {**payload, **message}
    else:
        attachment = parse_notification(message, subject, region, attributes)

    if attachment:
        payload["attachments"] = [attachment]  # type: ignore

    return payload


def apply_keyword_mentions(payload: Dict[str, Any]) -> None:
    if not KEYWORD_MENTIONS:
        return

    payload_text = json.dumps(payload).lower()
    user_ids: list[str] = []
    for keyword, ids in KEYWORD_MENTIONS.items():
        if keyword.lower() in payload_text:
            for uid in ids:
                if uid not in user_ids:
                    user_ids.append(uid)

    if user_ids:
        mentions = " ".join(f"<@{uid}>" for uid in user_ids)
        cc_text = f"cc {mentions}"
        if "attachments" in payload:
            payload["attachments"].append({"text": cc_text})
        else:
            existing = payload.get("text", "")
            payload["text"] = f"{existing}\n{cc_text}" if existing else cc_text


def send_slack_notification(payload: Dict[str, Any]) -> str:
    """
    Send notification payload to Slack

    :params payload: formatted Slack message payload
    :returns: response details from sending notification
    """

    slack_url = os.environ["SLACK_WEBHOOK_URL"]
    if not slack_url.startswith("http"):
        slack_url = decrypt_url(slack_url)

    data = urllib.parse.urlencode({"payload": json.dumps(payload)}).encode("utf-8")
    req = urllib.request.Request(slack_url)

    try:
        result = urllib.request.urlopen(req, data)
        return json.dumps({"code": result.getcode(), "info": result.info().as_string()})

    except HTTPError as e:
        logging.error(f"{e}: result")
        return json.dumps({"code": e.getcode(), "info": e.info().as_string()})


def lambda_handler(event: Dict[str, Any], context: Dict[str, Any]) -> str:
    """
    Lambda function to parse notification events and forward to Slack

    :param event: lambda expected event object
    :param context: lambda expected context object
    :returns: none
    """

    if os.environ.get("LOG_EVENTS", "False") == "True":
        logging.info("Event logging enabled: %s", json.dumps(event))

    for record in event["Records"]:
        sns = record["Sns"]
        subject = sns["Subject"]
        message = sns["Message"]
        region = sns["TopicArn"].split(":")[3]

        payload = get_slack_message_payload(
            message=message,
            region=region,
            subject=subject,
            attributes=sns.get("MessageAttributes"),
        )
        apply_keyword_mentions(payload)
        response = send_slack_notification(payload=payload)

    if json.loads(response)["code"] != 200:
        response_info = json.loads(response)["info"]
        logging.error(
            f"Error: received status `{response_info}` using event `{event}` and context `{context}`"
        )

    return response
