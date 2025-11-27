locals {
  //Put all common tags here
  common_tags = {
    Project = "BCGOV_LZA_SecurityHub_Notifications"
  }
  lambda_src_path = "./lambda"
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "security_hub_notifications_role" {
  name               = "BCGOV_LZA_Security_Hub_Notifications_Role"
  path               = "/service-role/"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = local.common_tags
}


resource "aws_iam_role_policy_attachment" "lambda_xray_writeonly" {
  role       = aws_iam_role.security_hub_notifications_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess"
}


resource "aws_iam_role_policy_attachment" "lambda_org_list_accounts" {
  role       = aws_iam_role.security_hub_notifications_role.name
  policy_arn = aws_iam_policy.org_list_policy.arn
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution_role" {
  role       = aws_iam_role.security_hub_notifications_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "random_uuid" "lambda_src_hash" {
  keepers = {
    for filename in setunion(
      fileset(local.lambda_src_path, "*.py"),
      fileset(local.lambda_src_path, "requirements.txt"),
      fileset(local.lambda_src_path, "core/**/*.py")
    ) :
    filename => filemd5("${local.lambda_src_path}/${filename}")
  }
}
resource "null_resource" "install_dependencies" {
  provisioner "local-exec" {
    command = "pip3 install -r ${local.lambda_src_path}/requirements.txt -t ${local.lambda_src_path}/ --upgrade"
  }
  # Only re-run this if the dependencies or their versions
  # have changed since the last deployment with Terraform
  triggers = {
    always_run = timestamp()

  }
}
# Create an archive form the Lambda source code,
# filtering out unneeded files.
data "archive_file" "lambda_source_package" {
  type        = "zip"
  source_dir  = local.lambda_src_path
  output_path = "${path.module}/.tmp/${random_uuid.lambda_src_hash.result}.zip"

  excludes = [
    "__pycache__",
    "core/__pycache__",
    "tests"
  ]

  # This is necessary, since archive_file is now a
  # `data` source and not a `resource` anymore.
  # Use `depends_on` to wait for the "install dependencies"
  # task to be completed.
  depends_on = [null_resource.install_dependencies]
}

# Lambda
resource "aws_lambda_function" "findings_to_teams_rocketchat" {
  filename         = data.archive_file.lambda_source_package.output_path
  function_name    = "BCGOV_LZA-SecurityHubfindings-To-Teams"
  role             = aws_iam_role.security_hub_notifications_role.arn
  handler          = "index.handler"
  description      = "Lambda Function to send security alerts to Teams"
  runtime          = "python3.12"
  timeout          = var.LambdaTimeout
  source_code_hash = data.archive_file.lambda_source_package.output_base64sha256

  environment {
    variables = {
      LOG_LEVEL             = var.LambdaEnvLogLevel,
      core_account_ids      = var.core_account_ids,
      management_account_id = var.management_account_id
    }
  }

  tags = local.common_tags
}


# CloudWatch Events Rules
resource "aws_cloudwatch_event_rule" "security_hub_findings_to_teams_rocketchat" {
  name        = "BCGOV_LZA_SecurityHubFindingsToTeams"
  description = "CloudWatchEvents Rule to enable SecurityHub Findings to Teams"

  event_pattern = <<EOF
{
  "source": [
      "aws.securityhub"
  ],
  "detail-type": [
    "Security Hub Findings - Imported"
  ],
  "detail": {
      "findings": {
          "Region": ["ca-central-1"],
          "Severity": {
              "Label": [
                 "HIGH", "CRITICAL"
              ]
          },
          "ProductFields": {
              "aws/securityhub/ProductName": [
                  "GuardDuty", "Macie", "IAM Access Analyzer", "Inspector", "Firewall Manager", "Systems Manager Patch Manager", "Security Hub"
              ]
          }
      }
  }
}
EOF

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "findings_to_teams_rocketchat" {
  rule      = aws_cloudwatch_event_rule.security_hub_findings_to_teams_rocketchat.name
  target_id = "FindingsToTeams"
  arn       = aws_lambda_function.findings_to_teams_rocketchat.arn
}

# Lambda Permissions
resource "aws_lambda_permission" "security_hub_findings_to_teams_rocketchat_event_rule_lambda_invoke_permissions" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.findings_to_teams_rocketchat.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_hub_findings_to_teams_rocketchat.arn
}

# resource "aws_lambda_permission" "security_hub_findings_to_teams_rocketchat_sns_lambda_invoke_permissions" {
#   statement_id  = "AllowExecutionFromSNS"
#   action        = "lambda:InvokeFunction"
#   function_name = aws_lambda_function.findings_to_teams_rocketchat.function_name
#   principal     = "sns.amazonaws.com"
#   source_arn    = aws_sns_topic.alert_topic.arn
# }

# # SNS Topic
# resource "aws_sns_topic" "alert_topic" {
#   name         = "rocketchat-teams-alerts"
#   display_name = "Rocketchat and Teams Alerts"
#   tags         = local.common_tags
# }

# resource "aws_sns_topic_policy" "default" {
#   arn    = aws_sns_topic.alert_topic.arn
#   policy = data.aws_iam_policy_document.sns_topic_policy.json
# }

# data "aws_iam_policy_document" "sns_topic_policy" {
#   statement {
#     actions = [
#       "SNS:Publish"
#     ]
#     effect = "Allow"
#     principals {
#       type        = "Service"
#       identifiers = ["budgets.amazonaws.com"]
#     }
#     resources = [
#       aws_sns_topic.alert_topic.arn,
#     ]
#   }
# }




resource "aws_iam_policy" "org_list_policy" {
  name        = "list_org_accounts"
  path        = "/"
  description = "list accounts"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "organizations:ListPoliciesForTarget",
          "organizations:DescribeEffectivePolicy",
          "organizations:ListRoots",
          "organizations:ListTargetsForPolicy",
          "organizations:ListTagsForResource",
          "organizations:ListDelegatedServicesForAccount",
          "organizations:DescribeAccount",
          "organizations:ListAWSServiceAccessForOrganization",
          "organizations:DescribePolicy",
          "organizations:ListChildren",
          "organizations:ListPolicies",
          "organizations:ListAccountsForParent",
          "organizations:ListHandshakesForOrganization",
          "organizations:ListDelegatedAdministrators",
          "organizations:ListHandshakesForAccount",
          "organizations:ListAccounts",
          "organizations:ListCreateAccountStatus",
          "organizations:DescribeOrganization",
          "organizations:DescribeOrganizationalUnit",
          "organizations:ListParents",
          "organizations:ListOrganizationalUnitsForParent",
          "organizations:DescribeHandshake",
          "organizations:DescribeCreateAccountStatus"
        ],
        "Resource" : "*"
      },
      {
        Action   = "ssm:GetParameter"
        Effect   = "Allow"
        Resource = "arn:aws:ssm:*:${data.aws_caller_identity.current.account_id}:parameter/lza/securityhubnotifications/webhooks"
        Sid      = "Allowssmgetparameter"
      }
    ]
  })
}
