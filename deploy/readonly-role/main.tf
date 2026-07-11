# Crossbearing read-only audit role.
#
# Grants ONLY the actions the `crossbearing report` binary invokes in your
# account — every one read-only, none capable of mutating infrastructure.
# Crossbearing assumes this role cross-account, gated by an external id you
# choose. Deploy with `terraform apply`, hand crossbearing the output role ARN
# and your external id, and revoke any time by deleting the role.
#
# What each permission is for:
#   cloudtrail:LookupEvents  — read the management-event history the join runs against
#   iam:GetRole              — read a role's trust policy to check identity conventions
#   kms:Sign (optional)      — sign the Agent Evidence Package with YOUR key; the
#                              free attribution audit does not sign, so leave it unset

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "crossbearing_principal_arn" {
  description = "The crossbearing IAM principal permitted to assume this role (crossbearing provides this)."
  type        = string
}

variable "external_id" {
  description = "A shared secret presented on every AssumeRole. You choose it; share it with crossbearing out of band. Prevents the confused-deputy problem."
  type        = string
  validation {
    condition     = length(var.external_id) >= 16
    error_message = "Use an external id of at least 16 characters."
  }
}

variable "kms_signing_key_arn" {
  description = "Optional: the KMS key crossbearing signs the Agent Evidence Package with (an engagement step). Empty grants no KMS permission — the free audit never signs."
  type        = string
  default     = ""
}

variable "role_name" {
  description = "Name for the created role."
  type        = string
  default     = "crossbearing-readonly"
}

data "aws_caller_identity" "current" {}

# Trust policy: only the named crossbearing principal, and only when it presents
# the external id. No wildcard principals.
data "aws_iam_policy_document" "trust" {
  statement {
    sid     = "AssumeWithExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.crossbearing_principal_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
  }
}

data "aws_iam_policy_document" "readonly" {
  # cloudtrail:LookupEvents does not support resource-level scoping — AWS
  # requires "*".
  statement {
    sid       = "CrossbearingReadAccountWide"
    effect    = "Allow"
    actions   = ["cloudtrail:LookupEvents"]
    resources = ["*"]
  }

  # iam:GetRole reads role metadata + trust policy (no credentials, no secrets);
  # scoped to roles in this account.
  statement {
    sid       = "CrossbearingReadRoleTrustPolicies"
    effect    = "Allow"
    actions   = ["iam:GetRole"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*"]
  }

  # Engagement only: sign the evidence package with the one named key.
  dynamic "statement" {
    for_each = var.kms_signing_key_arn == "" ? [] : [1]
    content {
      sid       = "CrossbearingSignEvidence"
      effect    = "Allow"
      actions   = ["kms:Sign"]
      resources = [var.kms_signing_key_arn]
    }
  }
}

resource "aws_iam_role" "crossbearing_readonly" {
  name                 = var.role_name
  description          = "Read-only audit access for crossbearing (agent attribution). No mutation; no data leaves the account."
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
  tags = {
    Vendor  = "crossbearing"
    Purpose = "agent-attribution-audit"
    Access  = "read-only"
  }
}

resource "aws_iam_role_policy" "crossbearing_readonly" {
  name   = "${var.role_name}-policy"
  role   = aws_iam_role.crossbearing_readonly.id
  policy = data.aws_iam_policy_document.readonly.json
}

output "role_arn" {
  description = "Hand this ARN (and your external id) to crossbearing."
  value       = aws_iam_role.crossbearing_readonly.arn
}
