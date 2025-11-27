# Secuirty Hub findings to teams

import json
import logging
import os
import re
import urllib.parse

import boto3
import requests

AWS_REGION = os.getenv("AWS_REGION", "ca-central-1")
LOG_LEVEL   = os.getenv("LOG_LEVEL", "INFO").upper()

ssm = boto3.client("ssm")
WEBHOOK_PARAMETER = "/lza/securityhubnotifications/webhooks"
webHookUrlValues = ssm.get_parameter(Name=WEBHOOK_PARAMETER, WithDecryption=True)["Parameter"]["Value"]

WEBHOOKS: dict[str, str] = {
    key.strip().upper(): value.strip()
    for key, value in (pair.split("=", 1) for pair in webHookUrlValues.split(","))
}


CORE_ACCOUNT_IDS = [account_id for account_id in os.getenv("core_account_ids", "").split(",") if account_id]
MGMT_ACCOUNT_ID  = os.getenv("management_account_id", "")
if MGMT_ACCOUNT_ID:
    CORE_ACCOUNT_IDS.append(MGMT_ACCOUNT_ID)

def setup_logging(request_id: str) -> logging.Logger:
    logger = logging.getLogger()
    logger.handlers.clear()

    fmt = "[%(levelname)-5s] %(asctime)s %(request_id)s  %(filename)s:%(lineno)d  %(message)s"
    formatter = logging.Formatter(fmt, "%Y-%m-%dT%H:%M:%S.%fZ")

    h = logging.StreamHandler()
    h.setFormatter(formatter)
    logger.addHandler(h)

    logging.LoggerAdapter(logger, extra={"request_id": request_id})
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    return logging.LoggerAdapter(logger, {"request_id": request_id})

def severity_label_colour(score: int) -> tuple[str, str]:
    if   1 <= score <= 39:  return "LOW",       "#879596"
    if  40 <= score <= 69:  return "MEDIUM",    "#ed7211"
    if  70 <= score <= 89:  return "HIGH",      "#ed7211"
    if  90 <= score <= 100: return "CRITICAL",  "#ff0209"
    return "INFORMATIONAL", "#007cbc"


def account_type(account_id: str, description: str) -> str:
    """Classify a finding as *core* or *workload*."""
    if account_id in CORE_ACCOUNT_IDS:
        return "core"
    # See if the description references a core account
    match = re.findall(r"arn:aws:[^:]+:[^:]*:(\d{12})", description)
    return "core" if match and match[-1] in CORE_ACCOUNT_IDS else "workload"


def post(url: str, payload: dict):
    requests.post(url, data=json.dumps(payload), headers={"Content-Type": "application/json"}, timeout=5)


def send_message(acct_type: str, teams_msg: dict):
    key_prefix = acct_type.upper()
    pairs = [("TEAMS", teams_msg)]
    for channel, payload in pairs:
        url = WEBHOOKS.get(f"{channel}_{key_prefix}")
        if url:
            post(url, payload)
        else:
            logging.info("Webhook key %s_%s not configured", channel, key_prefix)

def build_payloads(finding: dict, label: str, colour: str) -> tuple[dict, dict]:
    account = finding["AwsAccountId"]
    region  = finding["Resources"][0].get("Region", AWS_REGION)
    fid     = finding["Id"]

    console_base = f"https://{AWS_REGION}.console.aws.amazon.com/securityhub"
    query = f"search=Id%3D%255Coperator%255C%253AEQUALS%255C%253A{urllib.parse.quote(fid, safe='')}"
    console_link = f"{console_base}/home?region={region}#/findings?{query}"
    teams = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0076D7",
        "summary": console_link,
        "sections": [{
            "activityTitle": finding["Description"],
            "activityImage": "https://logos-world.net/wp-content/uploads/2021/08/Amazon-Web-Services-AWS-Logo.png",
            "activitySubtitle": f"*AWS SecurityHub finding in {region} for Acct: {account}*",
            "facts": [
                {"name": "Resource Type", "value": finding["Resources"][0]["Type"]},
                {"name": "Last Seen",     "value": finding["UpdatedAt"]},
                {"name": "Severity",      "value": label},
                {"name": "Region",        "value": region},
                {"name": "Finding Type",  "value": finding["Types"][0]},
            ],
            "markdown": True,
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "Open in Security Hub",
            "targets": [{"os": "default", "uri": console_link}],
        }],
    }
    return teams

def process_findings(detail: dict, logger: logging.LoggerAdapter):
    findings = detail["findings"]
    logger.info("Received %d Security Hub finding(s)", len(findings))
    for finding in findings:
        label, colour = severity_label_colour(finding["Severity"]["Normalized"])
        acct_type_val = account_type(finding["AwsAccountId"], finding["Description"])
        fid = finding["Id"][:12]
        logger.info(
            "Routing finding %s severity=%s account=%s dest=%s",
            fid, label, finding["AwsAccountId"], acct_type_val.upper()
        )

        teams = build_payloads(finding, label, colour)
        send_message(acct_type_val, teams)

def handler(event, context):
    logger = setup_logging(context.aws_request_id)
    logger.info("Raw event: %s", json.dumps(event)[:1000])

    try:
        if event.get("detail", {}).get("findings"):
            process_findings(event["detail"], logger)
        else:
            logger.info("Non-Security Hub event ignored")
            return {"statusCode": 202, "body": json.dumps({"message": "ignored"})}

        logger.info("Processing complete")
        return {"statusCode": 200, "body": json.dumps({"message": "processed"})}

    except Exception as exc:
        logger.exception("Unhandled exception")
        return {"statusCode": 500, "body": json.dumps({"error": str(exc)})}