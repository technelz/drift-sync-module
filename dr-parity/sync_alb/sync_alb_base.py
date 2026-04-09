#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError


def log(msg: str) -> None:
    print(msg, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def boto3_session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def get_elbv2(profile: str, region: str):
    return boto3_session(profile, region).client("elbv2")


@dataclass
class Args:
    source_profile: str
    source_region: str
    source_alb_name: str
    target_profile: str
    target_region: str
    target_alb_name: str
    target_subnets: List[str]
    target_security_groups: List[str]
    dry_run: bool
    report_only: bool


def get_load_balancer_by_name(elbv2, lb_name: str) -> Optional[Dict[str, Any]]:
    try:
        resp = elbv2.describe_load_balancers(Names=[lb_name])
        lbs = resp.get("LoadBalancers", [])
        return lbs[0] if lbs else None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("LoadBalancerNotFound", "LoadBalancerNotFoundException"):
            return None
        raise


def normalize_lb(lb: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "LoadBalancerName": lb.get("LoadBalancerName"),
        "Scheme": lb.get("Scheme"),
        "Type": lb.get("Type"),
        "IpAddressType": lb.get("IpAddressType"),
        "SecurityGroups": sorted(lb.get("SecurityGroups", [])),
        "Subnets": sorted([az["SubnetId"] for az in lb.get("AvailabilityZones", [])]),
    }


def create_alb(
    elbv2,
    name: str,
    subnets: List[str],
    security_groups: List[str],
    scheme: str,
    lb_type: str,
    ip_address_type: str,
    dry_run: bool,
) -> Optional[str]:
    if dry_run:
        log(f"[DRY-RUN] Would create ALB {name}")
        return None

    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnets,
        SecurityGroups=security_groups,
        Scheme=scheme,
        Type=lb_type,
        IpAddressType=ip_address_type,
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    log(f"[CREATE] ALB {name} -> {lb_arn}")
    return lb_arn


def parse_args() -> Args:
    p = argparse.ArgumentParser(description="Create or validate DR ALB shell from source ALB")

    p.add_argument("--source-profile", required=True)
    p.add_argument("--source-region", required=True)
    p.add_argument("--source-alb-name", required=True)

    p.add_argument("--target-profile", required=True)
    p.add_argument("--target-region", required=True)
    p.add_argument("--target-alb-name", required=True)

    p.add_argument("--target-subnets", nargs="+", required=True)
    p.add_argument("--target-security-groups", nargs="+", required=True)

    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--report-only", action="store_true")

    ns = p.parse_args()

    return Args(
        source_profile=ns.source_profile,
        source_region=ns.source_region,
        source_alb_name=ns.source_alb_name,
        target_profile=ns.target_profile,
        target_region=ns.target_region,
        target_alb_name=ns.target_alb_name,
        target_subnets=ns.target_subnets,
        target_security_groups=ns.target_security_groups,
        dry_run=ns.dry_run,
        report_only=ns.report_only,
    )


def main() -> int:
    args = parse_args()

    src_elbv2 = get_elbv2(args.source_profile, args.source_region)
    tgt_elbv2 = get_elbv2(args.target_profile, args.target_region)

    src_lb = get_load_balancer_by_name(src_elbv2, args.source_alb_name)
    if not src_lb:
        eprint(f"[ERROR] Source ALB not found: {args.source_alb_name}")
        return 2

    tgt_lb = get_load_balancer_by_name(tgt_elbv2, args.target_alb_name)

    src_norm = normalize_lb(src_lb)

    log(f"[INFO] Source ALB: {args.source_alb_name}")
    log(f"[INFO] Source scheme: {src_norm['Scheme']}")
    log(f"[INFO] Source type: {src_norm['Type']}")
    log(f"[INFO] Source IP address type: {src_norm['IpAddressType']}")

    if not tgt_lb and not args.report_only:
        create_alb(
            tgt_elbv2,
            args.target_alb_name,
            args.target_subnets,
            args.target_security_groups,
            src_norm["Scheme"],
            src_norm["Type"],
            src_norm["IpAddressType"],
            args.dry_run,
        )
        tgt_lb = get_load_balancer_by_name(tgt_elbv2, args.target_alb_name)

    print("\n" + "=" * 80)
    print("FINAL ALB BASE SYNC AUDIT REPORT")
    print("=" * 80)

    if not tgt_lb:
        print(f"Target ALB exists : False")
        print("Notes:")
        print("  - Target ALB missing.")
        print("=" * 80)
        return 1

    tgt_norm = normalize_lb(tgt_lb)

    print(f"Target ALB exists : True")
    print(f"Source ALB        : {args.source_alb_name}")
    print(f"Target ALB        : {args.target_alb_name}")

    drift = []

    if src_norm["Scheme"] != tgt_norm["Scheme"]:
        drift.append(f"Scheme mismatch: source={src_norm['Scheme']} target={tgt_norm['Scheme']}")
    if src_norm["Type"] != tgt_norm["Type"]:
        drift.append(f"Type mismatch: source={src_norm['Type']} target={tgt_norm['Type']}")
    if src_norm["IpAddressType"] != tgt_norm["IpAddressType"]:
        drift.append(
            f"IpAddressType mismatch: source={src_norm['IpAddressType']} target={tgt_norm['IpAddressType']}"
        )

    if sorted(args.target_subnets) != tgt_norm["Subnets"]:
        drift.append(f"Target subnet mismatch: expected={sorted(args.target_subnets)} actual={tgt_norm['Subnets']}")
    if sorted(args.target_security_groups) != tgt_norm["SecurityGroups"]:
        drift.append(
            f"Target security group mismatch: expected={sorted(args.target_security_groups)} actual={tgt_norm['SecurityGroups']}"
        )

    if drift:
        print("Needs review      : True")
        print("Notes:")
        for d in drift:
            print(f"  - {d}")
    else:
        print("Needs review      : False")
        print("ALB base is in expected state.")

    print("=" * 80)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())