variable "aws_region" {
  type        = string
  description = "The AWS region things are created in"
  default     = "ca-central-1"
}
variable "LambdaEnvLogLevel" {
  type    = string
  default = "INFO"
}

variable "LambdaTimeout" {
  type    = number
  default = 30
}

variable "core_account_ids" {
  type    = string
  description = "List of core account IDs to monitor for Security Hub findings"
}

variable "management_account_id" {
  type    = string
  description = "The AWS account ID of the management account"
}
