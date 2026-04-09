# Target Group Parity Sync Runbook

## Purpose
This runbook documents how to synchronize AWS Application Load Balancer (ALB) target groups from the production environment to the Disaster Recovery (DR) environment and validate parity.

---

## Scope
This automation covers:
- Target group creation
- Protocol and port configuration
- Health check settings
- Target group attributes
- Audit reporting

Not included:
- Target registration
- ALB listeners
- Listener rules
- Certificates

---

## Environment

### Source (Prod)
- Profile: `prod-profile`
- Region: `us-east-1`
- VPC: `vpc-07e9b545595333c38`

### Target (DR)
- Profile: `dr-profile`
- Region: `us-east-2`
- VPC: `vpc-081d7ae01e6d85d22`

---

## Script
```bash
sync_target_groups.py
```

---

## Prerequisites
- Python virtual environment
- boto3 installed
- AWS CLI profiles configured (`prod-profile`, `dr-profile`)

---

## Execution (Recommended - Live Mode)

### Dry Run
```bash
& ./.venv/bin/python3 ./sync_target_groups.py   --source-profile prod-profile   --source-region us-east-1   --source-vpc-id vpc-07e9b545595333c38   --target-profile dr-profile   --target-region us-east-2   --target-vpc-id vpc-081d7ae01e6d85d22   --dry-run
```

### Real Run
```bash
& ./.venv/bin/python3 ./sync_target_groups.py   --source-profile prod-profile   --source-region us-east-1   --source-vpc-id vpc-07e9b545595333c38   --target-profile dr-profile   --target-region us-east-2   --target-vpc-id vpc-081d7ae01e6d85d22
```

---

## Optional JSON Export Mode
```bash
aws elbv2 describe-target-groups   --profile prod-profile   --region us-east-1   --query "{TargetGroups: TargetGroups[?VpcId=='vpc-07e9b545595333c38']}"   --output json > tg-export.json
```

Run script:
```bash
& ./.venv/bin/python3 ./sync_target_groups.py   --json-path ./tg-export.json   --target-profile dr-profile   --target-region us-east-2   --target-vpc-id vpc-081d7ae01e6d85d22
```

---

## Expected Output
```
In sync: 1
Needs review: 0
All audited target groups are in sync.
```

---

## Audit Artifact
- `tg_sync_report.json`

---

## Validation Commands

### List DR Target Groups
```bash
aws elbv2 describe-target-groups   --profile dr-profile   --region us-east-2   --output table
```

### Check DR Target Group Attributes
```bash
aws elbv2 describe-target-group-attributes   --profile dr-profile   --region us-east-2   --target-group-arn <TARGET_GROUP_ARN>
```

### Check Prod Target Group Attributes
```bash
aws elbv2 describe-target-group-attributes   --profile prod-profile   --region us-east-1   --target-group-arn <SOURCE_TARGET_GROUP_ARN>
```

---

## Operational Guidance
- Always run with `--dry-run` first
- Execute real run only after validation
- Confirm audit shows `Needs review: 0`
- Save `tg_sync_report.json` for compliance/evidence

---

## Status
- Target Group parity sync: COMPLETE
- Next phase: ALB Listener and Rule Sync
