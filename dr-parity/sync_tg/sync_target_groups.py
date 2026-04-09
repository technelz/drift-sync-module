#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


# ----------------------------
# logging
# ----------------------------

def log(msg: str) -> None:
    print(msg, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ----------------------------
# aws session helpers
# ----------------------------

def boto3_session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def get_elbv2(profile: str, region: str):
    return boto3_session(profile, region).client("elbv2")


# ----------------------------
# models
# ----------------------------

@dataclass
class Args:
    json_path: Optional[str]
    source_profile: Optional[str]
    source_region: Optional[str]
    source_vpc_id: Optional[str]
    target_profile: str
    target_region: str
    target_vpc_id: str
    dry_run: bool
    report_only: bool


@dataclass
class TgAuditResult:
    target_group_name: str
    source_target_group_arn: Optional[str] = None
    target_target_group_arn: Optional[str] = None
    exists_in_target: bool = False
    immutable_match: bool = True
    settings_match: bool = True
    attributes_match: bool = True
    missing: List[str] = field(default_factory=list)
    drift_fields: List[str] = field(default_factory=list)
    recreate_recommended_fields: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def in_sync(self) -> bool:
        return (
            self.exists_in_target
            and self.immutable_match
            and self.settings_match
            and self.attributes_match
        )


# ----------------------------
# io
# ----------------------------

def load_json_target_groups(json_path: str) -> List[Dict[str, Any]]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "TargetGroups" in data:
        tgs = data["TargetGroups"]
    elif isinstance(data, list):
        tgs = data
    else:
        raise ValueError("Unsupported JSON format. Expected either {'TargetGroups': [...]} or [...]")

    if not isinstance(tgs, list):
        raise ValueError("TargetGroups payload is not a list")

    return tgs


# ----------------------------
# aws reads
# ----------------------------

def describe_target_groups_by_vpc(elbv2, vpc_id: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_target_groups")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate(PageSize=400):
        for tg in page.get("TargetGroups", []):
            if tg.get("VpcId") == vpc_id:
                out.append(tg)
    return out


def describe_target_group_attributes_map(elbv2, tg_arn: str) -> Dict[str, str]:
    resp = elbv2.describe_target_group_attributes(TargetGroupArn=tg_arn)
    attrs = resp.get("Attributes", [])
    return {a["Key"]: a.get("Value", "") for a in attrs}


def fetch_source_target_groups(args: Args) -> List[Dict[str, Any]]:
    if args.json_path:
        log(f"[INFO] Loading source target groups from JSON: {args.json_path}")
        return load_json_target_groups(args.json_path)

    assert args.source_profile and args.source_region and args.source_vpc_id
    log(
        f"[INFO] Pulling source target groups from AWS "
        f"(profile={args.source_profile}, region={args.source_region}, vpc={args.source_vpc_id})"
    )
    elbv2 = get_elbv2(args.source_profile, args.source_region)
    return describe_target_groups_by_vpc(elbv2, args.source_vpc_id)


def get_target_tg_map(elbv2, vpc_id: str) -> Dict[str, Dict[str, Any]]:
    return {tg["TargetGroupName"]: tg for tg in describe_target_groups_by_vpc(elbv2, vpc_id)}


# ----------------------------
# normalization
# ----------------------------

SUPPORTED_ATTR_KEYS = [
    "deregistration_delay.timeout_seconds",
    "stickiness.enabled",
    "stickiness.type",
    "stickiness.lb_cookie.duration_seconds",
    "slow_start.duration_seconds",
    "load_balancing.algorithm.type",
]

IMMUTABLE_KEYS = [
    "TargetGroupName",
    "Protocol",
    "Port",
    "TargetType",
    "IpAddressType",
    "ProtocolVersion",
]

MUTABLE_SETTING_KEYS = [
    "HealthCheckProtocol",
    "HealthCheckPort",
    "HealthCheckEnabled",
    "HealthCheckPath",
    "HealthCheckIntervalSeconds",
    "HealthCheckTimeoutSeconds",
    "HealthyThresholdCount",
    "UnhealthyThresholdCount",
    "Matcher",
]


def normalize_matcher(matcher: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not matcher:
        return {}
    out: Dict[str, Any] = {}
    if "HttpCode" in matcher and matcher["HttpCode"] is not None:
        out["HttpCode"] = matcher["HttpCode"]
    if "GrpcCode" in matcher and matcher["GrpcCode"] is not None:
        out["GrpcCode"] = matcher["GrpcCode"]
    return out


def normalize_target_group(
    tg: Dict[str, Any],
    attrs: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    normalized = {
        "TargetGroupName": tg.get("TargetGroupName"),
        "Protocol": tg.get("Protocol"),
        "Port": tg.get("Port"),
        "TargetType": tg.get("TargetType"),
        "IpAddressType": tg.get("IpAddressType"),
        "ProtocolVersion": tg.get("ProtocolVersion"),
        "HealthCheckProtocol": tg.get("HealthCheckProtocol"),
        "HealthCheckPort": tg.get("HealthCheckPort"),
        "HealthCheckEnabled": tg.get("HealthCheckEnabled"),
        "HealthCheckPath": tg.get("HealthCheckPath"),
        "HealthCheckIntervalSeconds": tg.get("HealthCheckIntervalSeconds"),
        "HealthCheckTimeoutSeconds": tg.get("HealthCheckTimeoutSeconds"),
        "HealthyThresholdCount": tg.get("HealthyThresholdCount"),
        "UnhealthyThresholdCount": tg.get("UnhealthyThresholdCount"),
        "Matcher": normalize_matcher(tg.get("Matcher")),
        "Attributes": {},
    }

    attrs = attrs or {}
    for key in SUPPORTED_ATTR_KEYS:
        if key in attrs:
            normalized["Attributes"][key] = attrs[key]

    return normalized


def diff_dict_fields(
    source: Dict[str, Any],
    target: Dict[str, Any],
    keys: List[str],
) -> List[str]:
    diffs = []
    for key in keys:
        if source.get(key) != target.get(key):
            diffs.append(key)
    return diffs


# ----------------------------
# create / update
# ----------------------------

def create_or_get_target_group(
    elbv2,
    source_tg: Dict[str, Any],
    target_vpc_id: str,
    dry_run: bool,
) -> str:
    name = source_tg["TargetGroupName"]

    existing_in_vpc = []
    try:
        existing = elbv2.describe_target_groups(Names=[name]).get("TargetGroups", [])
        existing_in_vpc = [tg for tg in existing if tg.get("VpcId") == target_vpc_id]
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code != "TargetGroupNotFound":
            raise

    if existing_in_vpc:
        return existing_in_vpc[0]["TargetGroupArn"]

    if dry_run:
        log(f"[DRY-RUN] Would create target group: {name}")
        return f"dryrun:{name}"

    create_args: Dict[str, Any] = {
        "Name": source_tg["TargetGroupName"],
        "Protocol": source_tg["Protocol"],
        "Port": source_tg["Port"],
        "VpcId": target_vpc_id,
        "TargetType": source_tg.get("TargetType", "instance"),
    }

    if source_tg.get("ProtocolVersion"):
        create_args["ProtocolVersion"] = source_tg["ProtocolVersion"]
    if source_tg.get("IpAddressType"):
        create_args["IpAddressType"] = source_tg["IpAddressType"]

    if source_tg.get("HealthCheckProtocol") is not None:
        create_args["HealthCheckProtocol"] = source_tg["HealthCheckProtocol"]
    if source_tg.get("HealthCheckPort") is not None:
        create_args["HealthCheckPort"] = source_tg["HealthCheckPort"]
    if source_tg.get("HealthCheckEnabled") is not None:
        create_args["HealthCheckEnabled"] = source_tg["HealthCheckEnabled"]
    if source_tg.get("HealthCheckPath") is not None:
        create_args["HealthCheckPath"] = source_tg["HealthCheckPath"]
    if source_tg.get("HealthCheckIntervalSeconds") is not None:
        create_args["HealthCheckIntervalSeconds"] = source_tg["HealthCheckIntervalSeconds"]
    if source_tg.get("HealthCheckTimeoutSeconds") is not None:
        create_args["HealthCheckTimeoutSeconds"] = source_tg["HealthCheckTimeoutSeconds"]
    if source_tg.get("HealthyThresholdCount") is not None:
        create_args["HealthyThresholdCount"] = source_tg["HealthyThresholdCount"]
    if source_tg.get("UnhealthyThresholdCount") is not None:
        create_args["UnhealthyThresholdCount"] = source_tg["UnhealthyThresholdCount"]

    matcher = source_tg.get("Matcher") or {}
    if matcher.get("HttpCode") is not None:
        create_args["Matcher"] = {"HttpCode": matcher["HttpCode"]}
    elif matcher.get("GrpcCode") is not None:
        create_args["Matcher"] = {"GrpcCode": matcher["GrpcCode"]}

    resp = elbv2.create_target_group(**create_args)
    tg_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    log(f"[CREATE] Target group {name} -> {tg_arn}")
    return tg_arn

def update_target_group_settings(
    elbv2,
    source_norm: Dict[str, Any],
    target_tg_arn: str,
    dry_run: bool,
) -> None:
    modify_args: Dict[str, Any] = {"TargetGroupArn": target_tg_arn}

    for key in MUTABLE_SETTING_KEYS:
        value = source_norm.get(key)
        if value is None or value == {}:
            continue
        modify_args[key] = value

    if len(modify_args) == 1:
        return

    if dry_run:
        log(f"[DRY-RUN] Would modify target group settings on {target_tg_arn}: {json.dumps(modify_args, default=str)}")
        return

    elbv2.modify_target_group(**modify_args)


def update_target_group_attributes(
    elbv2,
    desired_attrs: Dict[str, str],
    target_tg_arn: str,
    dry_run: bool,
) -> None:
    if not desired_attrs:
        return

    payload = [{"Key": k, "Value": v} for k, v in sorted(desired_attrs.items())]

    if dry_run:
        log(f"[DRY-RUN] Would modify target group attributes on {target_tg_arn}: {json.dumps(payload)}")
        return

    elbv2.modify_target_group_attributes(
        TargetGroupArn=target_tg_arn,
        Attributes=payload,
    )


# ----------------------------
# audit
# ----------------------------

def audit_target_group(
    source_tg: Dict[str, Any],
    source_norm: Dict[str, Any],
    target_tg: Optional[Dict[str, Any]],
    target_norm: Optional[Dict[str, Any]],
) -> TgAuditResult:
    result = TgAuditResult(
        target_group_name=source_tg["TargetGroupName"],
        source_target_group_arn=source_tg.get("TargetGroupArn"),
    )

    if not target_tg or not target_norm:
        result.exists_in_target = False
        result.missing.append("Target group missing in target environment.")
        return result

    result.exists_in_target = True
    result.target_target_group_arn = target_tg.get("TargetGroupArn")

    immutable_diffs = diff_dict_fields(source_norm, target_norm, IMMUTABLE_KEYS)
    if immutable_diffs:
        result.immutable_match = False
        result.recreate_recommended_fields.extend(immutable_diffs)
        result.notes.append(
            f"Immutable/core mismatch on: {', '.join(immutable_diffs)}"
        )

    mutable_diffs = diff_dict_fields(source_norm, target_norm, MUTABLE_SETTING_KEYS)
    if mutable_diffs:
        result.settings_match = False
        result.drift_fields.extend(mutable_diffs)
        result.notes.append(
            f"Mutable settings drift on: {', '.join(mutable_diffs)}"
        )

    source_attrs = source_norm.get("Attributes", {})
    target_attrs = target_norm.get("Attributes", {})
    attr_diffs = sorted(
        key for key in set(source_attrs.keys()) | set(target_attrs.keys())
        if source_attrs.get(key) != target_attrs.get(key)
    )
    if attr_diffs:
        result.attributes_match = False
        result.drift_fields.extend(attr_diffs)
        result.notes.append(
            f"Attribute drift on: {', '.join(attr_diffs)}"
        )

    return result


def print_audit_report(results: List[TgAuditResult]) -> None:
    print("\n" + "=" * 80)
    print("FINAL TARGET GROUP SYNC AUDIT REPORT")
    print("=" * 80)

    in_sync = [r for r in results if r.in_sync]
    out_of_sync = [r for r in results if not r.in_sync]

    print(f"Total TGs audited : {len(results)}")
    print(f"In sync           : {len(in_sync)}")
    print(f"Needs review      : {len(out_of_sync)}")
    print("")

    if not out_of_sync:
        print("All audited target groups are in sync.")
        print("=" * 80)
        return

    for r in out_of_sync:
        print("-" * 80)
        print(f"TG: {r.target_group_name}")
        print(f"Source TG ARN : {r.source_target_group_arn}")
        print(f"Target TG ARN : {r.target_target_group_arn}")
        print(f"Exists        : {r.exists_in_target}")
        print(f"Immutable     : {'OK' if r.immutable_match else 'MISMATCH'}")
        print(f"Settings      : {'OK' if r.settings_match else 'MISMATCH'}")
        print(f"Attributes    : {'OK' if r.attributes_match else 'MISMATCH'}")

        if r.missing:
            print("Missing:")
            for item in r.missing:
                print(f"  - {item}")

        if r.recreate_recommended_fields:
            print("Recreate recommended for fields:")
            for f in r.recreate_recommended_fields:
                print(f"  - {f}")

        if r.drift_fields:
            print("Drift fields:")
            for f in sorted(set(r.drift_fields)):
                print(f"  - {f}")

        if r.notes:
            print("Notes:")
            for n in r.notes:
                print(f"  - {n}")

    print("=" * 80)


def write_audit_report_json(results: List[TgAuditResult], path: str = "tg_sync_report.json") -> None:
    payload = []
    for r in results:
        payload.append({
            "target_group_name": r.target_group_name,
            "source_target_group_arn": r.source_target_group_arn,
            "target_target_group_arn": r.target_target_group_arn,
            "exists_in_target": r.exists_in_target,
            "immutable_match": r.immutable_match,
            "settings_match": r.settings_match,
            "attributes_match": r.attributes_match,
            "missing": r.missing,
            "drift_fields": r.drift_fields,
            "recreate_recommended_fields": r.recreate_recommended_fields,
            "notes": r.notes,
            "in_sync": r.in_sync,
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    log(f"[INFO] Wrote audit report to {path}")


# ----------------------------
# args
# ----------------------------

def parse_args() -> Args:
    p = argparse.ArgumentParser(description="Sync AWS Target Groups from source to target")

    source = p.add_argument_group("source")
    source.add_argument("--json-path", help="Existing JSON export from describe-target-groups")
    source.add_argument("--source-profile", help="Source AWS CLI profile")
    source.add_argument("--source-region", help="Source AWS region")
    source.add_argument("--source-vpc-id", help="Source VPC ID")

    target = p.add_argument_group("target")
    target.add_argument("--target-profile", required=True, help="Target AWS CLI profile")
    target.add_argument("--target-region", required=True, help="Target AWS region")
    target.add_argument("--target-vpc-id", required=True, help="Target VPC ID")

    p.add_argument("--dry-run", action="store_true", help="Show changes without applying them")
    p.add_argument("--report-only", action="store_true", help="Only audit, do not create or modify")

    ns = p.parse_args()

    if not ns.json_path:
        missing = [x for x in ["source_profile", "source_region", "source_vpc_id"] if getattr(ns, x) is None]
        if missing:
            p.error(
                "Either --json-path must be provided, or all of "
                "--source-profile, --source-region, --source-vpc-id must be provided."
            )

    return Args(
        json_path=ns.json_path,
        source_profile=ns.source_profile,
        source_region=ns.source_region,
        source_vpc_id=ns.source_vpc_id,
        target_profile=ns.target_profile,
        target_region=ns.target_region,
        target_vpc_id=ns.target_vpc_id,
        dry_run=ns.dry_run,
        report_only=ns.report_only,
    )


# ----------------------------
# main
# ----------------------------

def main() -> int:
    args = parse_args()

    source_tgs = fetch_source_target_groups(args)
    if not source_tgs:
        log("[INFO] No target groups found in source scope.")
        return 0

    target_elbv2 = get_elbv2(args.target_profile, args.target_region)

    log(f"[INFO] Target profile={args.target_profile} region={args.target_region} vpc={args.target_vpc_id}")
    log(f"[INFO] Source target groups to process: {len(source_tgs)}")

    # Source normalization
    source_norm_by_name: Dict[str, Dict[str, Any]] = {}
    for tg in source_tgs:
        if args.source_profile and args.source_region:
            source_elbv2 = get_elbv2(args.source_profile, args.source_region)
            source_attrs = describe_target_group_attributes_map(source_elbv2, tg["TargetGroupArn"])
        else:
            source_attrs = {}
        source_norm_by_name[tg["TargetGroupName"]] = normalize_target_group(tg, source_attrs)

    # Target inventory
    target_by_name = get_target_tg_map(target_elbv2, args.target_vpc_id)

    # Phase 1: create missing
    if not args.report_only:
        for source_tg in source_tgs:
            name = source_tg["TargetGroupName"]
            if name not in target_by_name:
                try:
                    create_or_get_target_group(
                        target_elbv2,
                        source_tg,
                        args.target_vpc_id,
                        args.dry_run,
                    )
                except ClientError as e:
                    eprint(f"[ERROR] Failed to create/get target group {name}: {e}")
                    return 2

        # refresh after creation
        target_by_name = get_target_tg_map(target_elbv2, args.target_vpc_id)

        # Phase 2: update mutable settings + attrs
        for source_tg in source_tgs:
            name = source_tg["TargetGroupName"]
            source_norm = source_norm_by_name[name]
            target_tg = target_by_name.get(name)
            if not target_tg:
                eprint(f"[ERROR] Target group missing after creation phase: {name}")
                continue

            target_attrs = describe_target_group_attributes_map(target_elbv2, target_tg["TargetGroupArn"])
            target_norm = normalize_target_group(target_tg, target_attrs)

            immutable_diffs = diff_dict_fields(source_norm, target_norm, IMMUTABLE_KEYS)
            if immutable_diffs:
                log(f"[WARN] {name}: immutable/core mismatch on {', '.join(immutable_diffs)}")
                log("[WARN] Recreate recommended instead of in-place update.")

            mutable_diffs = diff_dict_fields(source_norm, target_norm, MUTABLE_SETTING_KEYS)
            attr_diffs = sorted(
                key for key in set(source_norm["Attributes"].keys()) | set(target_norm["Attributes"].keys())
                if source_norm["Attributes"].get(key) != target_norm["Attributes"].get(key)
            )

            if mutable_diffs:
                log(f"[SYNC] Updating target group settings for {name} ({target_tg['TargetGroupArn']})")
                try:
                    update_target_group_settings(
                        target_elbv2,
                        source_norm,
                        target_tg["TargetGroupArn"],
                        args.dry_run,
                    )
                except ClientError as e:
                    eprint(f"[WARN] Failed updating settings for {name}: {e}")

            if attr_diffs:
                log(f"[SYNC] Updating target group attributes for {name} ({target_tg['TargetGroupArn']})")
                try:
                    update_target_group_attributes(
                        target_elbv2,
                        source_norm["Attributes"],
                        target_tg["TargetGroupArn"],
                        args.dry_run,
                    )
                except ClientError as e:
                    eprint(f"[WARN] Failed updating attributes for {name}: {e}")

    # Final audit
    target_by_name = get_target_tg_map(target_elbv2, args.target_vpc_id)
    audit_results: List[TgAuditResult] = []

    for source_tg in source_tgs:
        name = source_tg["TargetGroupName"]
        source_norm = source_norm_by_name[name]
        target_tg = target_by_name.get(name)

        if target_tg:
            target_attrs = describe_target_group_attributes_map(target_elbv2, target_tg["TargetGroupArn"])
            target_norm = normalize_target_group(target_tg, target_attrs)
        else:
            target_norm = None

        audit_results.append(
            audit_target_group(
                source_tg=source_tg,
                source_norm=source_norm,
                target_tg=target_tg,
                target_norm=target_norm,
            )
        )

    print_audit_report(audit_results)
    write_audit_report_json(audit_results)

    log("[DONE] Target group sync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())