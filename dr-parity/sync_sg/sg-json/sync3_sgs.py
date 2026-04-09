#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


def log(msg: str) -> None:
    print(msg, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def load_json_security_groups(json_path: str) -> List[Dict[str, Any]]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and "SecurityGroups" in data:
        sgs = data["SecurityGroups"]
    elif isinstance(data, list):
        sgs = data
    else:
        raise ValueError("Unsupported JSON format. Expected either {'SecurityGroups': [...]} or [...]")

    if not isinstance(sgs, list):
        raise ValueError("SecurityGroups payload is not a list")

    return sgs


def boto3_session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def get_ec2(profile: str, region: str):
    return boto3_session(profile, region).client("ec2")


def safe_tags(tags: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    if not tags:
        return []
    out = []
    for t in tags:
        key = t.get("Key")
        value = t.get("Value", "")
        if not key:
            continue
        if key.startswith("aws:"):
            continue
        out.append({"Key": str(key), "Value": str(value)})
    return out


def chunked(seq: List[Any], size: int) -> List[List[Any]]:
    return [seq[i:i + size] for i in range(0, len(seq), size)]


def describe_sgs_by_vpc(ec2, vpc_id: str) -> List[Dict[str, Any]]:
    paginator = ec2.get_paginator("describe_security_groups")
    pages = paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
    out: List[Dict[str, Any]] = []
    for page in pages:
        out.extend(page.get("SecurityGroups", []))
    return out


def is_default_sg(sg: Dict[str, Any]) -> bool:
    return sg.get("GroupName") == "default"


def canonical_tags(tags: Optional[List[Dict[str, str]]]) -> List[Tuple[str, str]]:
    return sorted((t["Key"], t.get("Value", "")) for t in safe_tags(tags))


def sort_dict(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [sort_dict(x) for x in obj]
    return obj


def permission_key(perm: Dict[str, Any]) -> str:
    return json.dumps(sort_dict(perm), sort_keys=True)


def get_account_id(session) -> str:
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


def describe_all_prefix_lists(ec2) -> List[Dict[str, Any]]:
    paginator = ec2.get_paginator("describe_managed_prefix_lists")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate():
        out.extend(page.get("PrefixLists", []))
    return out


def build_prefix_list_maps(ec2) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Returns:
      id_to_name: { 'pl-abc': 'com.amazonaws.us-east-1.s3', ... }
      name_to_id: { 'com.amazonaws.us-east-2.s3': 'pl-xyz', ... }
    """
    pls = describe_all_prefix_lists(ec2)
    id_to_name: Dict[str, str] = {}
    name_to_id: Dict[str, str] = {}
    for pl in pls:
        pl_id = pl.get("PrefixListId")
        pl_name = pl.get("PrefixListName")
        if pl_id and pl_name:
            id_to_name[pl_id] = pl_name
            name_to_id[pl_name] = pl_id
    return id_to_name, name_to_id


def derive_target_prefix_list_name(source_name: str, source_region: Optional[str], target_region: str) -> str:
    if source_region:
        token = f".{source_region}."
        if token in source_name:
            return source_name.replace(token, f".{target_region}.")
    return source_name


def normalize_permission(
    perm: Dict[str, Any],
    source_id_to_name: Dict[str, str],
    target_name_to_id: Dict[str, str],
    target_owner_id: Optional[str],
    source_prefix_id_to_name: Dict[str, str],
    target_prefix_name_to_id: Dict[str, str],
    source_region: Optional[str],
    target_region: str,
) -> Optional[Dict[str, Any]]:
    p: Dict[str, Any] = {
        "IpProtocol": perm.get("IpProtocol"),
    }

    if "FromPort" in perm:
        p["FromPort"] = perm["FromPort"]
    if "ToPort" in perm:
        p["ToPort"] = perm["ToPort"]

    ip_ranges = []
    for r in perm.get("IpRanges", []) or []:
        item = {"CidrIp": r["CidrIp"]}
        if "Description" in r and r["Description"] is not None:
            item["Description"] = r["Description"]
        ip_ranges.append(item)
    if ip_ranges:
        p["IpRanges"] = sorted(ip_ranges, key=lambda x: (x["CidrIp"], x.get("Description", "")))

    ipv6_ranges = []
    for r in perm.get("Ipv6Ranges", []) or []:
        item = {"CidrIpv6": r["CidrIpv6"]}
        if "Description" in r and r["Description"] is not None:
            item["Description"] = r["Description"]
        ipv6_ranges.append(item)
    if ipv6_ranges:
        p["Ipv6Ranges"] = sorted(ipv6_ranges, key=lambda x: (x["CidrIpv6"], x.get("Description", "")))

    prefix_lists = []
    for r in perm.get("PrefixListIds", []) or []:
        src_pl_id = r.get("PrefixListId")
        if not src_pl_id:
            continue

        src_pl_name = source_prefix_id_to_name.get(src_pl_id)
        if not src_pl_name:
            return None

        candidate_target_name = derive_target_prefix_list_name(src_pl_name, source_region, target_region)
        tgt_pl_id = target_prefix_name_to_id.get(candidate_target_name)

        if not tgt_pl_id:
            return None

        item = {"PrefixListId": tgt_pl_id}
        if "Description" in r and r["Description"] is not None:
            item["Description"] = r["Description"]
        prefix_lists.append(item)

    if prefix_lists:
        p["PrefixListIds"] = sorted(prefix_lists, key=lambda x: (x["PrefixListId"], x.get("Description", "")))

    group_pairs = []
    for gp in perm.get("UserIdGroupPairs", []) or []:
        src_group_id = gp.get("GroupId")
        if not src_group_id:
            continue

        src_group_name = source_id_to_name.get(src_group_id)
        if not src_group_name:
            return None

        tgt_group_id = target_name_to_id.get(src_group_name)
        if not tgt_group_id:
            return None

        item = {"GroupId": tgt_group_id}
        if target_owner_id:
            item["UserId"] = target_owner_id
        if "Description" in gp and gp["Description"] is not None:
            item["Description"] = gp["Description"]
        group_pairs.append(item)

    if group_pairs:
        p["UserIdGroupPairs"] = sorted(
            group_pairs, key=lambda x: (x["GroupId"], x.get("Description", ""))
        )

    return sort_dict(p)


def normalize_permissions(
    perms: Optional[List[Dict[str, Any]]],
    source_id_to_name: Dict[str, str],
    target_name_to_id: Dict[str, str],
    target_owner_id: Optional[str],
    source_prefix_id_to_name: Dict[str, str],
    target_prefix_name_to_id: Dict[str, str],
    source_region: Optional[str],
    target_region: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    normalized = []
    skipped = []
    for perm in perms or []:
        n = normalize_permission(
            perm,
            source_id_to_name,
            target_name_to_id,
            target_owner_id,
            source_prefix_id_to_name,
            target_prefix_name_to_id,
            source_region,
            target_region,
        )
        if n is None:
            skipped.append(perm)
        else:
            normalized.append(n)
    normalized = sorted(normalized, key=permission_key)
    return normalized, skipped


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


@dataclass
class SgAuditResult:
    group_name: str
    source_group_id: Optional[str] = None
    target_group_id: Optional[str] = None
    exists_in_target: bool = False
    description_match: bool = True
    tags_match: bool = True
    ingress_match: bool = True
    egress_match: bool = True
    skipped_ingress_count: int = 0
    skipped_egress_count: int = 0
    missing_ingress_rules: List[Dict[str, Any]] = field(default_factory=list)
    extra_ingress_rules: List[Dict[str, Any]] = field(default_factory=list)
    missing_egress_rules: List[Dict[str, Any]] = field(default_factory=list)
    extra_egress_rules: List[Dict[str, Any]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def in_sync(self) -> bool:
        return (
            self.exists_in_target
            and self.description_match
            and self.tags_match
            and self.ingress_match
            and self.egress_match
            and self.skipped_ingress_count == 0
            and self.skipped_egress_count == 0
        )


def fetch_source_security_groups(args: Args) -> List[Dict[str, Any]]:
    if args.json_path:
        log(f"[INFO] Loading source security groups from JSON: {args.json_path}")
        return load_json_security_groups(args.json_path)

    assert args.source_profile and args.source_region and args.source_vpc_id
    log(
        f"[INFO] Pulling source security groups from AWS "
        f"(profile={args.source_profile}, region={args.source_region}, vpc={args.source_vpc_id})"
    )
    ec2 = get_ec2(args.source_profile, args.source_region)
    return describe_sgs_by_vpc(ec2, args.source_vpc_id)


def create_or_get_target_sg(ec2, sg: Dict[str, Any], target_vpc_id: str, dry_run: bool) -> str:
    name = sg["GroupName"]
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [target_vpc_id]},
            {"Name": "group-name", "Values": [name]},
        ]
    )["SecurityGroups"]

    if existing:
        return existing[0]["GroupId"]

    if dry_run:
        log(f"[DRY-RUN] Would create SG: {name}")
        return f"dryrun-{name}"

    resp = ec2.create_security_group(
        GroupName=name,
        Description=sg.get("Description", name)[:255],
        VpcId=target_vpc_id,
    )
    sg_id = resp["GroupId"]
    log(f"[CREATE] SG {name} -> {sg_id}")
    return sg_id


def get_target_sg_map(ec2, vpc_id: str) -> Dict[str, Dict[str, Any]]:
    sgs = describe_sgs_by_vpc(ec2, vpc_id)
    return {sg["GroupName"]: sg for sg in sgs}


def sync_tags(ec2, target_sg: Dict[str, Any], desired_tags: List[Dict[str, str]], dry_run: bool) -> None:
    current = canonical_tags(target_sg.get("Tags"))
    desired = canonical_tags(desired_tags)

    if current == desired:
        return

    log(f"[SYNC] Tags differ for {target_sg['GroupName']}")
    if dry_run:
        log(f"[DRY-RUN] Current tags: {current}")
        log(f"[DRY-RUN] Desired tags: {desired}")
        return

    current_tags = safe_tags(target_sg.get("Tags"))
    current_keys = {t["Key"] for t in current_tags}
    desired_keys = {t["Key"] for t in desired_tags}
    to_delete_keys = sorted(current_keys - desired_keys)
    if to_delete_keys:
        ec2.delete_tags(
            Resources=[target_sg["GroupId"]],
            Tags=[{"Key": k} for k in to_delete_keys],
        )

    if desired_tags:
        ec2.create_tags(Resources=[target_sg["GroupId"]], Tags=desired_tags)


def revoke_permissions(ec2, group_id: str, direction: str, perms: List[Dict[str, Any]], dry_run: bool) -> None:
    if not perms:
        return
    action = "revoke_security_group_ingress" if direction == "ingress" else "revoke_security_group_egress"
    if dry_run:
        log(f"[DRY-RUN] Would {action} on {group_id}: {json.dumps(perms, default=str)}")
        return
    for batch in chunked(perms, 50):
        getattr(ec2, action)(GroupId=group_id, IpPermissions=batch)


def authorize_permissions(ec2, group_id: str, direction: str, perms: List[Dict[str, Any]], dry_run: bool) -> None:
    if not perms:
        return
    action = "authorize_security_group_ingress" if direction == "ingress" else "authorize_security_group_egress"
    if dry_run:
        log(f"[DRY-RUN] Would {action} on {group_id}: {json.dumps(perms, default=str)}")
        return
    for batch in chunked(perms, 50):
        getattr(ec2, action)(GroupId=group_id, IpPermissions=batch)


def sync_rules_for_sg(
    ec2,
    source_sg: Dict[str, Any],
    target_sg: Dict[str, Any],
    source_id_to_name: Dict[str, str],
    target_name_to_id: Dict[str, str],
    target_owner_id: str,
    source_prefix_id_to_name: Dict[str, str],
    target_prefix_name_to_id: Dict[str, str],
    source_region: Optional[str],
    target_region: str,
    dry_run: bool,
) -> None:
    name = source_sg["GroupName"]

    desired_ingress, skipped_ingress = normalize_permissions(
        source_sg.get("IpPermissions"),
        source_id_to_name,
        target_name_to_id,
        target_owner_id,
        source_prefix_id_to_name,
        target_prefix_name_to_id,
        source_region,
        target_region,
    )
    desired_egress, skipped_egress = normalize_permissions(
        source_sg.get("IpPermissionsEgress"),
        source_id_to_name,
        target_name_to_id,
        target_owner_id,
        source_prefix_id_to_name,
        target_prefix_name_to_id,
        source_region,
        target_region,
    )

    current_ingress, _ = normalize_permissions(
        target_sg.get("IpPermissions"),
        {},
        target_name_to_id,
        target_owner_id,
        {},
        target_prefix_name_to_id,
        None,
        target_region,
    )
    current_egress, _ = normalize_permissions(
        target_sg.get("IpPermissionsEgress"),
        {},
        target_name_to_id,
        target_owner_id,
        {},
        target_prefix_name_to_id,
        None,
        target_region,
    )

    desired_ingress_set = {permission_key(p): p for p in desired_ingress}
    desired_egress_set = {permission_key(p): p for p in desired_egress}
    current_ingress_set = {permission_key(p): p for p in current_ingress}
    current_egress_set = {permission_key(p): p for p in current_egress}

    ingress_to_add = [v for k, v in desired_ingress_set.items() if k not in current_ingress_set]
    ingress_to_remove = [v for k, v in current_ingress_set.items() if k not in desired_ingress_set]
    egress_to_add = [v for k, v in desired_egress_set.items() if k not in current_egress_set]
    egress_to_remove = [v for k, v in current_egress_set.items() if k not in desired_egress_set]

    if skipped_ingress:
        log(f"[WARN] {name}: skipped {len(skipped_ingress)} ingress rule(s) due to unresolved SG/prefix-list references")
    if skipped_egress:
        log(f"[WARN] {name}: skipped {len(skipped_egress)} egress rule(s) due to unresolved SG/prefix-list references")

    if not (ingress_to_add or ingress_to_remove or egress_to_add or egress_to_remove):
        log(f"[OK] Rules already match for {name}")
        return

    log(f"[SYNC] Updating rules for {name} ({target_sg['GroupId']})")

    try:
        revoke_permissions(ec2, target_sg["GroupId"], "ingress", ingress_to_remove, dry_run)
    except ClientError as e:
        eprint(f"[WARN] Failed removing ingress for {name}: {e}")

    try:
        revoke_permissions(ec2, target_sg["GroupId"], "egress", egress_to_remove, dry_run)
    except ClientError as e:
        eprint(f"[WARN] Failed removing egress for {name}: {e}")

    try:
        authorize_permissions(ec2, target_sg["GroupId"], "ingress", ingress_to_add, dry_run)
    except ClientError as e:
        eprint(f"[WARN] Failed adding ingress for {name}: {e}")

    try:
        authorize_permissions(ec2, target_sg["GroupId"], "egress", egress_to_add, dry_run)
    except ClientError as e:
        eprint(f"[WARN] Failed adding egress for {name}: {e}")


def audit_sg(
    source_sg: Dict[str, Any],
    target_sg: Optional[Dict[str, Any]],
    source_id_to_name: Dict[str, str],
    target_name_to_id: Dict[str, str],
    target_owner_id: str,
    source_prefix_id_to_name: Dict[str, str],
    target_prefix_name_to_id: Dict[str, str],
    source_region: Optional[str],
    target_region: str,
) -> SgAuditResult:
    result = SgAuditResult(
        group_name=source_sg["GroupName"],
        source_group_id=source_sg.get("GroupId"),
    )

    if not target_sg:
        result.exists_in_target = False
        result.notes.append("Target security group does not exist.")
        return result

    result.exists_in_target = True
    result.target_group_id = target_sg.get("GroupId")

    if source_sg.get("Description", "") != target_sg.get("Description", ""):
        result.description_match = False
        result.notes.append(
            f"Description mismatch: source='{source_sg.get('Description', '')}' "
            f"target='{target_sg.get('Description', '')}'"
        )

    if canonical_tags(source_sg.get("Tags")) != canonical_tags(target_sg.get("Tags")):
        result.tags_match = False
        result.notes.append("Tag mismatch.")

    desired_ingress, skipped_ingress = normalize_permissions(
        source_sg.get("IpPermissions"),
        source_id_to_name,
        target_name_to_id,
        target_owner_id,
        source_prefix_id_to_name,
        target_prefix_name_to_id,
        source_region,
        target_region,
    )
    desired_egress, skipped_egress = normalize_permissions(
        source_sg.get("IpPermissionsEgress"),
        source_id_to_name,
        target_name_to_id,
        target_owner_id,
        source_prefix_id_to_name,
        target_prefix_name_to_id,
        source_region,
        target_region,
    )

    current_ingress, _ = normalize_permissions(
        target_sg.get("IpPermissions"),
        {},
        target_name_to_id,
        target_owner_id,
        {},
        target_prefix_name_to_id,
        None,
        target_region,
    )
    current_egress, _ = normalize_permissions(
        target_sg.get("IpPermissionsEgress"),
        {},
        target_name_to_id,
        target_owner_id,
        {},
        target_prefix_name_to_id,
        None,
        target_region,
    )

    desired_ingress_map = {permission_key(p): p for p in desired_ingress}
    desired_egress_map = {permission_key(p): p for p in desired_egress}
    current_ingress_map = {permission_key(p): p for p in current_ingress}
    current_egress_map = {permission_key(p): p for p in current_egress}

    result.missing_ingress_rules = [
        v for k, v in desired_ingress_map.items() if k not in current_ingress_map
    ]
    result.extra_ingress_rules = [
        v for k, v in current_ingress_map.items() if k not in desired_ingress_map
    ]
    result.missing_egress_rules = [
        v for k, v in desired_egress_map.items() if k not in current_egress_map
    ]
    result.extra_egress_rules = [
        v for k, v in current_egress_map.items() if k not in desired_egress_map
    ]

    result.skipped_ingress_count = len(skipped_ingress)
    result.skipped_egress_count = len(skipped_egress)

    result.ingress_match = not result.missing_ingress_rules and not result.extra_ingress_rules
    result.egress_match = not result.missing_egress_rules and not result.extra_egress_rules

    if skipped_ingress:
        result.notes.append(f"{len(skipped_ingress)} ingress rule(s) could not be normalized/mapped.")
    if skipped_egress:
        result.notes.append(f"{len(skipped_egress)} egress rule(s) could not be normalized/mapped.")
    if result.missing_ingress_rules:
        result.notes.append(f"{len(result.missing_ingress_rules)} missing ingress rule(s) in target.")
    if result.extra_ingress_rules:
        result.notes.append(f"{len(result.extra_ingress_rules)} extra ingress rule(s) in target.")
    if result.missing_egress_rules:
        result.notes.append(f"{len(result.missing_egress_rules)} missing egress rule(s) in target.")
    if result.extra_egress_rules:
        result.notes.append(f"{len(result.extra_egress_rules)} extra egress rule(s) in target.")

    return result


def print_audit_report(results: List[SgAuditResult]) -> None:
    print("\n" + "=" * 80)
    print("FINAL SYNC AUDIT REPORT")
    print("=" * 80)

    in_sync = [r for r in results if r.in_sync]
    out_of_sync = [r for r in results if not r.in_sync]

    print(f"Total SGs audited : {len(results)}")
    print(f"In sync           : {len(in_sync)}")
    print(f"Needs review      : {len(out_of_sync)}")
    print("")

    if not out_of_sync:
        print("All audited security groups are in sync.")
        print("=" * 80)
        return

    for r in out_of_sync:
        print("-" * 80)
        print(f"SG: {r.group_name}")
        print(f"Source SG ID : {r.source_group_id}")
        print(f"Target SG ID : {r.target_group_id}")
        print(f"Exists       : {r.exists_in_target}")
        print(f"Description  : {'OK' if r.description_match else 'MISMATCH'}")
        print(f"Tags         : {'OK' if r.tags_match else 'MISMATCH'}")
        print(f"Ingress      : {'OK' if r.ingress_match else 'MISMATCH'}")
        print(f"Egress       : {'OK' if r.egress_match else 'MISMATCH'}")
        print(f"Skipped in   : {r.skipped_ingress_count}")
        print(f"Skipped out  : {r.skipped_egress_count}")

        if r.notes:
            print("Notes:")
            for n in r.notes:
                print(f"  - {n}")

        if r.missing_ingress_rules:
            print("Missing ingress rules in target:")
            print(json.dumps(r.missing_ingress_rules, indent=2))

        if r.extra_ingress_rules:
            print("Extra ingress rules in target:")
            print(json.dumps(r.extra_ingress_rules, indent=2))

        if r.missing_egress_rules:
            print("Missing egress rules in target:")
            print(json.dumps(r.missing_egress_rules, indent=2))

        if r.extra_egress_rules:
            print("Extra egress rules in target:")
            print(json.dumps(r.extra_egress_rules, indent=2))

    print("=" * 80)


def write_audit_report_json(results: List[SgAuditResult], path: str = "sync_report.json") -> None:
    payload = []
    for r in results:
        payload.append({
            "group_name": r.group_name,
            "source_group_id": r.source_group_id,
            "target_group_id": r.target_group_id,
            "exists_in_target": r.exists_in_target,
            "description_match": r.description_match,
            "tags_match": r.tags_match,
            "ingress_match": r.ingress_match,
            "egress_match": r.egress_match,
            "skipped_ingress_count": r.skipped_ingress_count,
            "skipped_egress_count": r.skipped_egress_count,
            "missing_ingress_rules": r.missing_ingress_rules,
            "extra_ingress_rules": r.extra_ingress_rules,
            "missing_egress_rules": r.missing_egress_rules,
            "extra_egress_rules": r.extra_egress_rules,
            "notes": r.notes,
            "in_sync": r.in_sync,
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    log(f"[INFO] Wrote audit report to {path}")


def parse_args() -> Args:
    p = argparse.ArgumentParser(description="Sync AWS Security Groups from source to target")

    source = p.add_argument_group("source")
    source.add_argument("--json-path", help="Existing JSON export from describe-security-groups")
    source.add_argument("--source-profile", help="Source AWS CLI profile")
    source.add_argument("--source-region", help="Source AWS region")
    source.add_argument("--source-vpc-id", help="Source VPC ID")

    target = p.add_argument_group("target")
    target.add_argument("--target-profile", required=True, help="Target AWS CLI profile")
    target.add_argument("--target-region", required=True, help="Target AWS region")
    target.add_argument("--target-vpc-id", required=True, help="Target VPC ID")

    p.add_argument("--dry-run", action="store_true", help="Show actions without making changes")
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
    )


def main() -> int:
    args = parse_args()

    source_sgs = fetch_source_security_groups(args)
    source_sgs = [sg for sg in source_sgs if not is_default_sg(sg)]
    if not source_sgs:
        log("[INFO] No non-default security groups found to sync.")
        return 0

    target_session = boto3_session(args.target_profile, args.target_region)
    target_ec2 = target_session.client("ec2")
    target_owner_id = get_account_id(target_session)

    log(f"[INFO] Target profile={args.target_profile} region={args.target_region} vpc={args.target_vpc_id}")
    log(f"[INFO] Source security groups to process: {len(source_sgs)}")

    source_id_to_name = {sg["GroupId"]: sg["GroupName"] for sg in source_sgs}

    source_prefix_id_to_name: Dict[str, str] = {}
    target_prefix_name_to_id: Dict[str, str] = {}

    if args.source_profile and args.source_region:
        source_ec2 = get_ec2(args.source_profile, args.source_region)
        source_prefix_id_to_name, _ = build_prefix_list_maps(source_ec2)
    else:
        source_prefix_id_to_name = {}

    _, target_prefix_name_to_id = build_prefix_list_maps(target_ec2)

    created_or_found: Dict[str, str] = {}
    for sg in source_sgs:
        try:
            target_sg_id = create_or_get_target_sg(target_ec2, sg, args.target_vpc_id, args.dry_run)
            created_or_found[sg["GroupName"]] = target_sg_id
        except ClientError as e:
            eprint(f"[ERROR] Failed to create/get SG {sg['GroupName']}: {e}")
            return 2

    target_by_name = get_target_sg_map(target_ec2, args.target_vpc_id)
    if args.dry_run:
        for sg in source_sgs:
            name = sg["GroupName"]
            if name not in target_by_name and name in created_or_found:
                target_by_name[name] = {
                    "GroupName": name,
                    "GroupId": created_or_found[name],
                    "Description": sg.get("Description", ""),
                    "IpPermissions": [],
                    "IpPermissionsEgress": [],
                    "Tags": [],
                }

    target_name_to_id = {name: sg["GroupId"] for name, sg in target_by_name.items()}

    if not source_prefix_id_to_name:
        for sg in source_sgs:
            for perm in (sg.get("IpPermissions") or []) + (sg.get("IpPermissionsEgress") or []):
                for p in perm.get("PrefixListIds", []) or []:
                    plid = p.get("PrefixListId")
                    if plid and plid not in source_prefix_id_to_name:
                        source_prefix_id_to_name[plid] = plid

    for source_sg in source_sgs:
        name = source_sg["GroupName"]
        target_sg = target_by_name.get(name)
        if not target_sg:
            eprint(f"[ERROR] Target SG missing after creation phase: {name}")
            continue

        src_desc = source_sg.get("Description", "")
        tgt_desc = target_sg.get("Description", "")
        if src_desc != tgt_desc:
            log(f"[WARN] Description mismatch for {name}: target='{tgt_desc}' source='{src_desc}'")
            log("[WARN] AWS does not allow in-place SG description updates after creation.")

        try:
            sync_tags(target_ec2, target_sg, safe_tags(source_sg.get("Tags")), args.dry_run)
        except ClientError as e:
            eprint(f"[WARN] Failed syncing tags for {name}: {e}")

        try:
            sync_rules_for_sg(
                target_ec2,
                source_sg,
                target_sg,
                source_id_to_name,
                target_name_to_id,
                target_owner_id,
                source_prefix_id_to_name,
                target_prefix_name_to_id,
                args.source_region,
                args.target_region,
                args.dry_run,
            )
        except ClientError as e:
            eprint(f"[WARN] Failed syncing rules for {name}: {e}")

    target_by_name = get_target_sg_map(target_ec2, args.target_vpc_id)
    target_name_to_id = {name: sg["GroupId"] for name, sg in target_by_name.items()}

    audit_results: List[SgAuditResult] = []
    for source_sg in source_sgs:
        target_sg = target_by_name.get(source_sg["GroupName"])
        audit_results.append(
            audit_sg(
                source_sg=source_sg,
                target_sg=target_sg,
                source_id_to_name=source_id_to_name,
                target_name_to_id=target_name_to_id,
                target_owner_id=target_owner_id,
                source_prefix_id_to_name=source_prefix_id_to_name,
                target_prefix_name_to_id=target_prefix_name_to_id,
                source_region=args.source_region,
                target_region=args.target_region,
            )
        )

    print_audit_report(audit_results)
    write_audit_report_json(audit_results)

    log("[DONE] Security group sync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())