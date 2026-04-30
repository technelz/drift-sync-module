#!/usr/bin/env python3
"""
sg_sync_v9_discovery.py

AWS Security Group DR parity sync tool.

Purpose:
- Read source/Prod security groups from an exported JSON file.
- Read target/DR security groups live from AWS.
- Build a safe matching plan using enterprise-safe strategies:
  1. Manual name-map override
  2. Exact GroupName match
  3. Case-insensitive GroupName match
  4. Exact Name-tag match
  5. Case-insensitive Name-tag match
  6. CloudFormation stack-name + logical-id match
  7. CloudFormation logical-id-only match
  8. Normalized GroupName / Name-tag cross-match
  9. Rule fingerprint match using protocol/port/CIDR/prefix-list/SG-reference shape
- Preserve original source names, actual target names, normalized match keys, and match confidence in the report.
- Block unsafe --yes remediation by default when matching is ambiguous or low confidence.
- Create missing target SGs.
- Sync tags.
- Add missing ingress/egress rules.
- Optionally remove extra ingress/egress rules.

Important:
- Default SG is skipped.
- AWS-managed CloudFormation tags are used for matching clues but are not copied to target resources.
- Security group descriptions cannot be updated in-place by AWS. Exact description parity for existing SGs requires recreation.
- Use --dry-run or --name-preview first.

Enterprise note:
- In many enterprise AWS accounts, the value humans see in the console may be the Name tag, not the actual GroupName.
  This version treats both GroupName and the Name tag as first-class matching identifiers.
- If names/tags still differ, this version can fall back to a rule-structure fingerprint. The fingerprint
  intentionally neutralizes account IDs and SG IDs, because those normally differ between Prod and DR.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError


PRINT_LOCK = threading.Lock()


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def eprint(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, file=sys.stderr, flush=True)


DEFAULT_REPORTS_DIR = "sg_reports"

SYSTEM_TAG_KEYS_TO_IGNORE = {
    "aws:cloudformation:logical-id",
    "aws:cloudformation:stack-id",
    "aws:cloudformation:stack-name",
}

CFN_LOGICAL_ID_KEY = "aws:cloudformation:logical-id"
CFN_STACK_NAME_KEY = "aws:cloudformation:stack-name"
NAME_TAG_KEY = "Name"

GENERIC_LOW_CONFIDENCE_KEYS = {
    "securitygroup",
    "rsecuritygroup",
    "sg",
    "security-group",
    "websg",
    "appsg",
    "dbsg",
    "web-security-group",
    "app-security-group",
    "db-security-group",
}


@dataclass
class Args:
    json_path: str
    target_profile: str
    target_region: str
    target_vpc_id: str
    target_json_path: Optional[str] = None
    source_account_id: Optional[str] = None
    target_account_id: Optional[str] = None
    dry_run: bool = False
    report_only: bool = False
    yes: bool = False
    name_preview: bool = False
    debug_names: bool = False
    workers: int = 6
    no_rollback: bool = False
    report_path: Optional[str] = None
    revoke_extra_rules: bool = True
    name_map_path: Optional[str] = None
    allow_low_confidence: bool = False
    allow_ambiguous: bool = False
    create_missing: bool = True
    sync_tags: bool = True


def auto_report_path(json_path: str, target_profile: str, target_region: str) -> str:
    Path(DEFAULT_REPORTS_DIR).mkdir(exist_ok=True)
    base = Path(json_path).stem
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    return str(Path(DEFAULT_REPORTS_DIR) / f"{base}_{target_profile}_{target_region}_{timestamp}_sg_sync_report.json")


def parse_args() -> Args:
    p = argparse.ArgumentParser(description="Sync AWS Security Groups from a source JSON export into a target DR VPC.")
    p.add_argument("--json-path", required=True)
    p.add_argument(
        "--source-account-id",
        default=None,
        help="Optional source/Prod AWS account ID used for embedded account-ID name normalization.",
    )
    p.add_argument(
        "--target-account-id",
        default=None,
        help="Optional target/DR AWS account ID. If omitted, STS caller identity is used.",
    )
    p.add_argument("--target-profile", required=True)
    p.add_argument("--target-region", required=True)
    p.add_argument("--target-vpc-id", required=True)
    p.add_argument("--target-json-path", default=None, help="Optional target/DR describe-security-groups JSON export. Use this to bypass live AWS discovery and validate matching against an exported target file.")
    p.add_argument("--dry-run", action="store_true", help="Audit only. Do not modify DR.")
    p.add_argument("--report-only", action="store_true", help="Audit only. Do not modify DR.")
    p.add_argument("--yes", action="store_true", help="Apply remediation to DR.")
    p.add_argument("--name-preview", action="store_true", help="Show matching details and exit.")
    p.add_argument("--debug-names", action="store_true", help="Print source/target GroupName, Name tag, normalized keys, and CFN keys.")
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--no-rollback", action="store_true")
    p.add_argument("--report-path", default=None)
    p.add_argument("--name-map", dest="name_map_path", default=None, help='Optional JSON mapping file: {"source prod sg name": "target dr sg name"}')
    p.add_argument("--no-revoke-extra-rules", action="store_true", help="Only add missing rules. Do not remove extra DR rules.")
    p.add_argument("--allow-low-confidence", action="store_true", help="Allow --yes to remediate low-confidence normalized matches.")
    p.add_argument("--allow-ambiguous", action="store_true", help="Allow --yes to continue even when ambiguous normalized/tag matches exist.")
    p.add_argument("--no-create-missing", action="store_true", help="Do not create missing security groups during --yes.")
    p.add_argument("--no-sync-tags", action="store_true", help="Do not sync tags during --yes.")
    ns = p.parse_args()

    selected_modes = sum([bool(ns.dry_run), bool(ns.report_only), bool(ns.yes), bool(ns.name_preview)])
    if selected_modes > 1:
        raise ValueError("Choose only one mode: --dry-run, --report-only, --yes, or --name-preview")
    if selected_modes == 0:
        raise ValueError("Choose a mode: --dry-run, --report-only, --yes, or --name-preview")

    return Args(
        json_path=ns.json_path,
        source_account_id=ns.source_account_id,
        target_account_id=ns.target_account_id,
        target_profile=ns.target_profile,
        target_region=ns.target_region,
        target_vpc_id=ns.target_vpc_id,
        target_json_path=ns.target_json_path,
        dry_run=ns.dry_run,
        report_only=ns.report_only,
        yes=ns.yes,
        name_preview=ns.name_preview,
        debug_names=ns.debug_names,
        workers=ns.workers,
        no_rollback=ns.no_rollback,
        report_path=ns.report_path or auto_report_path(ns.json_path, ns.target_profile, ns.target_region),
        revoke_extra_rules=not ns.no_revoke_extra_rules,
        name_map_path=ns.name_map_path,
        allow_low_confidence=ns.allow_low_confidence,
        allow_ambiguous=ns.allow_ambiguous,
        create_missing=not ns.no_create_missing,
        sync_tags=not ns.no_sync_tags,
    )


@dataclass
class MatchInfo:
    source_group_name: str
    source_group_id: Optional[str]
    normalized_match_key: str
    source_name_tag: Optional[str] = None
    target_group_name: Optional[str] = None
    target_group_id: Optional[str] = None
    target_name_tag: Optional[str] = None
    match_method: str = "unmatched"
    match_confidence: str = "unmatched"
    ambiguous: bool = False
    ambiguity_reason: Optional[str] = None
    matched_key_type: Optional[str] = None
    matched_key_value: Optional[str] = None


@dataclass
class SgAuditResult:
    source_group_name: str
    normalized_match_key: str
    source_group_id: Optional[str] = None
    source_name_tag: Optional[str] = None
    target_group_name: Optional[str] = None
    target_group_id: Optional[str] = None
    target_name_tag: Optional[str] = None
    exists_in_target: bool = False
    match_method: str = "unmatched"
    match_confidence: str = "unmatched"
    matched_key_type: Optional[str] = None
    matched_key_value: Optional[str] = None
    ambiguous: bool = False
    ambiguity_reason: Optional[str] = None
    missing: List[str] = field(default_factory=list)
    drift_fields: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    missing_ingress_rules: List[Dict[str, Any]] = field(default_factory=list)
    extra_ingress_rules: List[Dict[str, Any]] = field(default_factory=list)
    missing_egress_rules: List[Dict[str, Any]] = field(default_factory=list)
    extra_egress_rules: List[Dict[str, Any]] = field(default_factory=list)
    tag_drift: bool = False
    description_drift: bool = False

    @property
    def in_sync(self) -> bool:
        return (
            self.exists_in_target
            and not self.ambiguous
            and not self.missing
            and not self.drift_fields
            and not self.missing_ingress_rules
            and not self.extra_ingress_rules
            and not self.missing_egress_rules
            and not self.extra_egress_rules
            and not self.tag_drift
            and not self.description_drift
        )


@dataclass
class Plan:
    changes: List[SgAuditResult]
    unsafe_reasons: List[str] = field(default_factory=list)


def boto3_session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def get_ec2(profile: str, region: str):
    return boto3_session(profile, region).client("ec2")


def get_sts(profile: str, region: str):
    return boto3_session(profile, region).client("sts")


def get_account_id(profile: str, region: str) -> str:
    return get_sts(profile, region).get_caller_identity()["Account"]


def load_json_security_groups(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "SecurityGroups" in data:
        groups = data["SecurityGroups"]
    elif isinstance(data, list):
        groups = data
    else:
        raise ValueError("Invalid SG JSON format. Expected AWS describe-security-groups JSON.")
    if not isinstance(groups, list):
        raise ValueError("Invalid SG JSON format. SecurityGroups must be a list.")
    return groups


def load_name_map(path: Optional[str]) -> Dict[str, str]:
    if not path:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("--name-map must be a JSON object mapping source SG names to target SG names.")
    return {str(k): str(v) for k, v in data.items()}


def is_default_sg(sg: Dict[str, Any]) -> bool:
    return sg.get("GroupName") == "default"


def tag_value(sg: Dict[str, Any], key: str) -> Optional[str]:
    for t in sg.get("Tags", []) or []:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def name_tag(sg: Dict[str, Any]) -> Optional[str]:
    return tag_value(sg, NAME_TAG_KEY)


def canonical_tags(tags: Optional[List[Dict[str, str]]]) -> List[Tuple[str, str]]:
    out = []
    for t in tags or []:
        k = t.get("Key")
        v = t.get("Value", "")
        if k and k not in SYSTEM_TAG_KEYS_TO_IGNORE:
            out.append((k, v))
    return sorted(out)


def aws_tags(tags: Optional[List[Dict[str, str]]]) -> List[Dict[str, str]]:
    out = []
    for t in tags or []:
        k = t.get("Key")
        v = t.get("Value", "")
        if k and k not in SYSTEM_TAG_KEYS_TO_IGNORE:
            out.append({"Key": k, "Value": v})
    return out


def cfn_match_key(sg: Dict[str, Any]) -> Optional[str]:
    logical_id = tag_value(sg, CFN_LOGICAL_ID_KEY)
    stack_name = tag_value(sg, CFN_STACK_NAME_KEY)
    if logical_id and stack_name:
        return f"{stack_name.lower()}::{logical_id.lower()}"
    if logical_id:
        return f"logical::{logical_id.lower()}"
    return None


def cfn_logical_key(sg: Dict[str, Any]) -> Optional[str]:
    logical_id = tag_value(sg, CFN_LOGICAL_ID_KEY)
    if logical_id:
        return logical_id.lower().strip()
    return None


def _drop_account_ids(value: str, src_acct: str = "", tgt_acct: str = "") -> str:
    out = value
    for acct in {str(src_acct or ""), str(tgt_acct or "")}:
        if acct:
            out = out.replace(acct, "")
    return out


def normalize_sg_name(name: Optional[str], src_acct: str = "", tgt_acct: str = "") -> str:
    """
    Enterprise SG-name normalization.

    Goals:
    - Match names where Prod and DR use different env/account prefixes.
    - Match CloudFormation-generated name suffix variants.
    - Keep meaningful application terms intact.
    - Avoid collapsing names so aggressively that unrelated SGs match.
    """
    if not name:
        return ""

    normalized = str(name).strip().lower()
    normalized = _drop_account_ids(normalized, src_acct, tgt_acct)
    normalized = normalized.replace("_", "-")

    # Remove common AWS/CFN generated security-group ID tokens if embedded.
    normalized = re.sub(r"sg-[a-f0-9]{8,17}", "", normalized)

    # CloudFormation pattern: stack-name-logicalid-randomhash -> logicalid or meaningful suffix.
    cfn_match = re.match(
        r"^stack-[a-z0-9][a-z0-9-]*-([a-z0-9-]*(?:securitygroup|security-group|sg)[a-z0-9-]*)-(?:[a-f0-9]{8,}|(?=[a-z0-9]*\d)[a-z0-9]{8,})$",
        normalized,
        flags=re.IGNORECASE,
    )
    if cfn_match:
        normalized = cfn_match.group(1)
    else:
        maybe = re.sub(r"^stack-[a-z0-9][a-z0-9-]*-", "", normalized, flags=re.IGNORECASE)
        if maybe != normalized and re.search(r"(securitygroup|security-group|sg)", maybe, flags=re.IGNORECASE):
            normalized = maybe

    # Remove environment prefixes.
    normalized = re.sub(
        r"^(prod|production|prd|dr|dev|development|qa|uat|stage|stg|test|acc|acct|env)[-_]+",
        "",
        normalized,
        flags=re.IGNORECASE,
    )

    # Remove env + random/generated prefix: dr-a1b2c3d4-sg-name -> sg-name.
    normalized = re.sub(
        r"^(d|dr|dev|prod|prd|qa|uat|stage|stg|test|acc|acct|env)-[a-z0-9]{4,}[-_]",
        "",
        normalized,
        flags=re.IGNORECASE,
    )

    # Remove leading account-number prefix.
    normalized = re.sub(r"^[0-9]{6,12}[-_]", "", normalized, flags=re.IGNORECASE)

    # Remove trailing generated suffix only when it looks hash/random-like.
    normalized = re.sub(
        r"-(?:[a-f0-9]{8,}|(?=[a-z0-9]*\d)[a-z0-9]{8,})$",
        "",
        normalized,
        flags=re.IGNORECASE,
    )

    # Normalize common SG wording variants.
    normalized = normalized.replace("security-group", "securitygroup")
    normalized = normalized.replace("securitygroups", "securitygroup")

    normalized = re.sub(r"-{2,}", "-", normalized)
    normalized = normalized.strip("-_ ")
    return normalized


def compact_name_key(name: Optional[str], src_acct: str = "", tgt_acct: str = "") -> str:
    """More permissive key used only as a fallback index. Removes separators."""
    n = normalize_sg_name(name, src_acct, tgt_acct)
    return re.sub(r"[^a-z0-9]", "", n)


def is_low_confidence_key(key: str) -> bool:
    k = (key or "").lower().strip()
    compact = re.sub(r"[^a-z0-9]", "", k)
    if not compact or k in GENERIC_LOW_CONFIDENCE_KEYS or compact in GENERIC_LOW_CONFIDENCE_KEYS or len(compact) < 5:
        return True
    if re.fullmatch(r"r?securitygroup[0-9a-z-]*", k):
        return True
    if re.fullmatch(r"r?securitygroup[0-9a-z]*", compact):
        return True
    return False




def _clean_rule_description(value: Optional[str]) -> str:
    """Normalize rule descriptions for fingerprinting without making them mandatory."""
    if not value:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().lower())


def _normalize_cidr_text(value: Optional[str]) -> str:
    if not value:
        return ""
    return str(value).strip().lower()


def _rule_range_item(item: Dict[str, Any], id_key: str, include_descriptions: bool) -> Dict[str, Any]:
    out: Dict[str, Any] = {id_key: _normalize_cidr_text(item.get(id_key))}
    if include_descriptions and item.get("Description"):
        out["Description"] = _clean_rule_description(item.get("Description"))
    return out


def _neutral_user_group_pair(pair: Dict[str, Any], include_descriptions: bool, mode: str = "shape") -> Dict[str, Any]:
    """
    Neutralize SG references for cross-account comparison.

    AWS SG-to-SG rules contain fields that naturally differ between Prod and DR:
    - GroupId
    - UserId/account ID
    - VpcId
    - VpcPeeringConnectionId

    For structural matching, do not compare those volatile values. If AWS includes GroupName,
    the optional named mode can keep a normalized clue, but the default structural mode uses only
    the existence/shape of an SG reference and optionally its rule description.
    """
    out: Dict[str, Any] = {"GroupRef": "sg-ref"}

    group_name = pair.get("GroupName")
    if mode == "named" and group_name:
        out["GroupNameKey"] = normalize_sg_name(group_name)

    if include_descriptions and pair.get("Description"):
        out["Description"] = _clean_rule_description(pair.get("Description"))

    return out


def _fingerprint_permission(permission: Dict[str, Any], include_descriptions: bool = True, sg_ref_mode: str = "shape") -> Dict[str, Any]:
    fp: Dict[str, Any] = {"IpProtocol": str(permission.get("IpProtocol", ""))}

    if permission.get("FromPort") is not None:
        fp["FromPort"] = permission.get("FromPort")
    if permission.get("ToPort") is not None:
        fp["ToPort"] = permission.get("ToPort")

    ip_ranges = [
        _rule_range_item(r, "CidrIp", include_descriptions)
        for r in permission.get("IpRanges", []) or []
        if r.get("CidrIp")
    ]
    ipv6_ranges = [
        _rule_range_item(r, "CidrIpv6", include_descriptions)
        for r in permission.get("Ipv6Ranges", []) or []
        if r.get("CidrIpv6")
    ]
    prefix_lists = [
        _rule_range_item(r, "PrefixListId", include_descriptions)
        for r in permission.get("PrefixListIds", []) or []
        if r.get("PrefixListId")
    ]
    sg_refs = [
        _neutral_user_group_pair(r, include_descriptions, mode=sg_ref_mode)
        for r in permission.get("UserIdGroupPairs", []) or []
    ]

    if ip_ranges:
        fp["IpRanges"] = sorted(ip_ranges, key=lambda x: json.dumps(x, sort_keys=True))
    if ipv6_ranges:
        fp["Ipv6Ranges"] = sorted(ipv6_ranges, key=lambda x: json.dumps(x, sort_keys=True))
    if prefix_lists:
        fp["PrefixListIds"] = sorted(prefix_lists, key=lambda x: json.dumps(x, sort_keys=True))
    if sg_refs:
        fp["UserIdGroupPairs"] = sorted(sg_refs, key=lambda x: json.dumps(x, sort_keys=True))

    return fp


def _fingerprint_permissions(permissions: List[Dict[str, Any]], include_descriptions: bool = True, sg_ref_mode: str = "shape") -> List[Dict[str, Any]]:
    out = []
    for p in permissions or []:
        fp = _fingerprint_permission(p, include_descriptions=include_descriptions, sg_ref_mode=sg_ref_mode)
        has_target = any(k in fp for k in ["IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"])
        if fp.get("IpProtocol") == "-1" or has_target:
            out.append(fp)
    return sorted(out, key=lambda x: json.dumps(x, sort_keys=True))


def rule_fingerprint(sg: Dict[str, Any], include_descriptions: bool = True, sg_ref_mode: str = "shape") -> str:
    """
    Build a deterministic structural fingerprint for an SG's ingress/egress rules.

    This is designed for Prod-vs-DR matching where SG IDs/account IDs differ. It compares rule shape:
    protocol, ports, CIDRs, IPv6 CIDRs, prefix lists, and neutralized SG-reference shape.
    """
    payload = {
        "ingress": _fingerprint_permissions(sg.get("IpPermissions", []) or [], include_descriptions, sg_ref_mode),
        "egress": _fingerprint_permissions(sg.get("IpPermissionsEgress", []) or [], include_descriptions, sg_ref_mode),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def rule_fingerprint_summary(fingerprint: str) -> str:
    """Return a short stable display key for reports without requiring extra dependencies."""
    checksum = 0
    for ch in fingerprint:
        checksum = (checksum * 131 + ord(ch)) % 1000000007
    return f"rulefp:{checksum:x}:len{len(fingerprint)}"


def is_weak_rule_fingerprint(fingerprint: str) -> bool:
    """
    Do not trust fingerprints that are too generic, especially SGs with only default egress.
    These can appear many times in enterprise VPCs.
    """
    try:
        payload = json.loads(fingerprint)
    except Exception:
        return True

    ingress = payload.get("ingress", []) or []
    egress = payload.get("egress", []) or []

    if not ingress and not egress:
        return True

    # Default AWS egress-only SG shape. Many SGs have this exact fingerprint.
    if not ingress and len(egress) == 1:
        rule = egress[0]
        if rule.get("IpProtocol") == "-1" and rule.get("IpRanges") == [{"CidrIp": "0.0.0.0/0"}]:
            return True

    # Very weak for matching if no ingress exists.
    if not ingress:
        return True

    return False

def identity_values_for_sg(sg: Dict[str, Any], src_acct: str, tgt_acct: str) -> Dict[str, List[str]]:
    """
    Return all useful identity values for matching.
    This is intentionally explicit so name-preview/debug output can explain what matched.
    """
    values: Dict[str, List[str]] = defaultdict(list)
    group_name = sg.get("GroupName", "") or ""
    nt = name_tag(sg) or ""

    if group_name:
        values["group_name_exact"].append(group_name)
        values["group_name_lower"].append(group_name.lower())
        values["group_name_normalized"].append(normalize_sg_name(group_name, src_acct, tgt_acct))
        values["group_name_compact"].append(compact_name_key(group_name, src_acct, tgt_acct))

    if nt:
        values["name_tag_exact"].append(nt)
        values["name_tag_lower"].append(nt.lower())
        values["name_tag_normalized"].append(normalize_sg_name(nt, src_acct, tgt_acct))
        values["name_tag_compact"].append(compact_name_key(nt, src_acct, tgt_acct))

    ck = cfn_match_key(sg)
    if ck:
        values["cfn_stack_logical"].append(ck)

    lk = cfn_logical_key(sg)
    if lk:
        values["cfn_logical_only"].append(lk)

    # Deduplicate and remove empty strings.
    return {k: sorted(set(v for v in vals if v)) for k, vals in values.items()}


def get_target_sgs(ec2, vpc_id: str) -> List[Dict[str, Any]]:
    """Return all target SGs in the DR VPC using a paginator."""
    paginator = ec2.get_paginator("describe_security_groups")
    out: List[Dict[str, Any]] = []

    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
        out.extend(page.get("SecurityGroups", []))

    return out




def load_target_security_groups(path: str, target_vpc_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load target/DR SGs from an exported describe-security-groups JSON file."""
    groups = load_json_security_groups(path)
    if target_vpc_id:
        groups = [sg for sg in groups if sg.get("VpcId") == target_vpc_id]
    return groups


def print_discovery_diagnostics(source_groups, target_sgs, target_vpc_id, src_acct, tgt_acct):
    """Print hard proof of what the script is actually comparing."""
    source_names = {sg.get("GroupName", "") for sg in source_groups if sg.get("GroupName")}
    target_names = {sg.get("GroupName", "") for sg in target_sgs if sg.get("GroupName")}
    source_name_tags = {name_tag(sg) for sg in source_groups if name_tag(sg)}
    target_name_tags = {name_tag(sg) for sg in target_sgs if name_tag(sg)}

    exact_group_overlap = sorted(source_names & target_names)
    exact_name_tag_overlap = sorted(source_name_tags & target_name_tags)
    group_to_target_tag_overlap = sorted(source_names & target_name_tags)
    tag_to_target_group_overlap = sorted(source_name_tags & target_names)

    vpc_counts = defaultdict(int)
    owner_counts = defaultdict(int)
    for sg in target_sgs:
        vpc_counts[sg.get("VpcId", "UNKNOWN")] += 1
        owner_counts[sg.get("OwnerId", "UNKNOWN")] += 1

    log("\n========== DISCOVERY DIAGNOSTICS ==========")
    log(f"Target SGs loaded/discovered      : {len(target_sgs)}")
    log(f"Requested target VPC              : {target_vpc_id}")
    log(f"Target SG VPC distribution        : {dict(sorted(vpc_counts.items()))}")
    log(f"Target SG OwnerId distribution    : {dict(sorted(owner_counts.items()))}")
    log(f"Exact GroupName overlap count     : {len(exact_group_overlap)}")
    log(f"Exact Name-tag overlap count      : {len(exact_name_tag_overlap)}")
    log(f"Source GroupName -> Target NameTag: {len(group_to_target_tag_overlap)}")
    log(f"Source NameTag -> Target GroupName: {len(tag_to_target_group_overlap)}")
    if exact_group_overlap[:10]:
        log("Sample exact GroupName overlaps:")
        for x in exact_group_overlap[:10]:
            log(f" - {x}")
    if len(target_sgs) == 0:
        log("[DIAGNOSIS] ZERO target SGs are being compared. This is discovery/profile/region/VPC/export filtering, not name matching.")
    elif not exact_group_overlap and not exact_name_tag_overlap and not group_to_target_tag_overlap and not tag_to_target_group_overlap:
        log("[DIAGNOSIS] Target SGs are loaded, but there is no direct name/tag overlap. Use --debug-names or a name-map to inspect exact differences.")
    else:
        log("[DIAGNOSIS] Direct name/tag overlap exists. If report still says missing, matching code path is the issue.")
    log("===========================================\n")

def index_target_sgs(target_sgs: List[Dict[str, Any]], src_acct: str, tgt_acct: str) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    index_names = [
        "group_name_exact",
        "group_name_lower",
        "name_tag_exact",
        "name_tag_lower",
        "cfn_stack_logical",
        "cfn_logical_only",
        "group_name_normalized",
        "name_tag_normalized",
        "group_name_compact",
        "name_tag_compact",
        "rule_fingerprint_strict",
        "rule_fingerprint_no_desc",
    ]
    indexes: Dict[str, Dict[str, List[Dict[str, Any]]]] = {name: defaultdict(list) for name in index_names}

    # Cross indexes let source GroupName match target Name tag and source Name tag match target GroupName.
    indexes["any_normalized"] = defaultdict(list)
    indexes["any_compact"] = defaultdict(list)

    for sg in target_sgs:
        vals = identity_values_for_sg(sg, src_acct, tgt_acct)
        for idx_name, idx_values in vals.items():
            if idx_name in indexes:
                for value in idx_values:
                    indexes[idx_name][value].append(sg)

        for value in vals.get("group_name_normalized", []) + vals.get("name_tag_normalized", []):
            indexes["any_normalized"][value].append(sg)

        for value in vals.get("group_name_compact", []) + vals.get("name_tag_compact", []):
            indexes["any_compact"][value].append(sg)

        strict_fp = rule_fingerprint(sg, include_descriptions=True, sg_ref_mode="shape")
        loose_fp = rule_fingerprint(sg, include_descriptions=False, sg_ref_mode="shape")
        if not is_weak_rule_fingerprint(strict_fp):
            indexes["rule_fingerprint_strict"][strict_fp].append(sg)
        if not is_weak_rule_fingerprint(loose_fp):
            indexes["rule_fingerprint_no_desc"][loose_fp].append(sg)

    return indexes

def get_single_match(candidates: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]:
    if not candidates:
        return None, False, None
    unique = {sg.get("GroupId"): sg for sg in candidates if sg.get("GroupId")}
    if len(unique) == 1:
        return next(iter(unique.values())), False, None
    names = [f"{sg.get('GroupName')} / NameTag={name_tag(sg) or ''} ({sg.get('GroupId')})" for sg in unique.values()]
    return None, True, "Multiple target SGs matched: " + ", ".join(sorted(names))


def _make_match(
    source_sg: Dict[str, Any],
    target: Optional[Dict[str, Any]],
    normalized_key: str,
    method: str,
    confidence: str,
    key_type: Optional[str] = None,
    key_value: Optional[str] = None,
    ambiguous: bool = False,
    reason: Optional[str] = None,
) -> MatchInfo:
    return MatchInfo(
        source_group_name=source_sg.get("GroupName", ""),
        source_group_id=source_sg.get("GroupId"),
        normalized_match_key=normalized_key,
        source_name_tag=name_tag(source_sg),
        target_group_name=target.get("GroupName") if target else None,
        target_group_id=target.get("GroupId") if target else None,
        target_name_tag=name_tag(target) if target else None,
        match_method=method,
        match_confidence=confidence,
        ambiguous=ambiguous,
        ambiguity_reason=reason,
        matched_key_type=key_type,
        matched_key_value=key_value,
    )


def match_source_to_target(
    source_sg: Dict[str, Any],
    indexes: Dict[str, Dict[str, List[Dict[str, Any]]]],
    name_map: Dict[str, str],
    src_acct: str,
    tgt_acct: str,
) -> MatchInfo:
    source_name = source_sg.get("GroupName", "")
    source_name_tag = name_tag(source_sg) or ""
    normalized_key = normalize_sg_name(source_name, src_acct, tgt_acct)
    source_vals = identity_values_for_sg(source_sg, src_acct, tgt_acct)

    # 1. Manual override. Match target GroupName or Name tag exactly/case-insensitively.
    if source_name in name_map:
        target_name = name_map[source_name]
        manual_candidates = []
        manual_candidates.extend(indexes["group_name_exact"].get(target_name, []))
        manual_candidates.extend(indexes["name_tag_exact"].get(target_name, []))
        manual_candidates.extend(indexes["group_name_lower"].get(target_name.lower(), []))
        manual_candidates.extend(indexes["name_tag_lower"].get(target_name.lower(), []))
        target, ambiguous, reason = get_single_match(manual_candidates)
        if target:
            return _make_match(source_sg, target, normalized_key, "manual-name-map", "manual", "manual", target_name)
        return _make_match(
            source_sg,
            None,
            normalized_key,
            "manual-name-map",
            "unmatched",
            "manual",
            target_name,
            ambiguous=ambiguous,
            reason=reason or f"Manual name-map target not found: {target_name}",
        )

    # Strict high-confidence strategies first.
    strict_strategy_order = [
        ("group_name_exact", "exact-group-name", "exact"),
        ("group_name_lower", "case-insensitive-group-name", "exact-ci"),
        ("name_tag_exact", "exact-name-tag", "name-tag"),
        ("name_tag_lower", "case-insensitive-name-tag", "name-tag-ci"),
        ("cfn_stack_logical", "cloudformation-stack-logical", "tag-based"),
        ("cfn_logical_only", "cloudformation-logical-id", "tag-based"),
    ]

    for key_type, method, confidence in strict_strategy_order:
        for value in source_vals.get(key_type, []):
            target, ambiguous, reason = get_single_match(indexes[key_type].get(value, []))
            if target:
                return _make_match(source_sg, target, normalized_key, method, confidence, key_type, value)
            if ambiguous:
                return _make_match(source_sg, None, normalized_key, method, "ambiguous", key_type, value, True, reason)

    # Cross-match GroupName <-> Name tag using normalized keys.
    normalized_candidates_to_try = []
    normalized_candidates_to_try.extend(source_vals.get("group_name_normalized", []))
    normalized_candidates_to_try.extend(source_vals.get("name_tag_normalized", []))
    normalized_candidates_to_try = sorted(set(v for v in normalized_candidates_to_try if v))

    for value in normalized_candidates_to_try:
        target, ambiguous, reason = get_single_match(indexes["any_normalized"].get(value, []))
        if target:
            confidence = "low" if is_low_confidence_key(value) else "normalized"
            return _make_match(source_sg, target, normalized_key, "normalized-any-name", confidence, "any_normalized", value)
        if ambiguous:
            return _make_match(source_sg, None, normalized_key, "normalized-any-name", "ambiguous", "any_normalized", value, True, reason)

    # Last fallback: compact key cross-match. This is intentionally lower confidence.
    compact_candidates_to_try = []
    compact_candidates_to_try.extend(source_vals.get("group_name_compact", []))
    compact_candidates_to_try.extend(source_vals.get("name_tag_compact", []))
    compact_candidates_to_try = sorted(set(v for v in compact_candidates_to_try if v))

    for value in compact_candidates_to_try:
        target, ambiguous, reason = get_single_match(indexes["any_compact"].get(value, []))
        if target:
            confidence = "low" if is_low_confidence_key(value) else "compact-normalized"
            return _make_match(source_sg, target, normalized_key, "compact-any-name", confidence, "any_compact", value)
        if ambiguous:
            return _make_match(source_sg, None, normalized_key, "compact-any-name", "ambiguous", "any_compact", value, True, reason)

    # Structural fallback: match by actual rule shape, neutralizing SG IDs/account IDs.
    # This is intentionally after all name/tag strategies because multiple SGs can legitimately share rules.
    strict_fp = rule_fingerprint(source_sg, include_descriptions=True, sg_ref_mode="shape")
    if not is_weak_rule_fingerprint(strict_fp):
        target, ambiguous, reason = get_single_match(indexes["rule_fingerprint_strict"].get(strict_fp, []))
        if target:
            return _make_match(
                source_sg,
                target,
                normalized_key,
                "rule-fingerprint-strict",
                "structural",
                "rule_fingerprint_strict",
                rule_fingerprint_summary(strict_fp),
            )
        if ambiguous:
            return _make_match(
                source_sg,
                None,
                normalized_key,
                "rule-fingerprint-strict",
                "ambiguous",
                "rule_fingerprint_strict",
                rule_fingerprint_summary(strict_fp),
                True,
                reason,
            )

    loose_fp = rule_fingerprint(source_sg, include_descriptions=False, sg_ref_mode="shape")
    if not is_weak_rule_fingerprint(loose_fp):
        target, ambiguous, reason = get_single_match(indexes["rule_fingerprint_no_desc"].get(loose_fp, []))
        if target:
            return _make_match(
                source_sg,
                target,
                normalized_key,
                "rule-fingerprint-no-description",
                "low",
                "rule_fingerprint_no_desc",
                rule_fingerprint_summary(loose_fp),
            )
        if ambiguous:
            return _make_match(
                source_sg,
                None,
                normalized_key,
                "rule-fingerprint-no-description",
                "ambiguous",
                "rule_fingerprint_no_desc",
                rule_fingerprint_summary(loose_fp),
                True,
                reason,
            )

    # Useful diagnostic: if source GroupName and NameTag differ, normalized key should show the stronger human label.
    if source_name_tag and normalize_sg_name(source_name_tag, src_acct, tgt_acct):
        normalized_key = f"group={normalize_sg_name(source_name, src_acct, tgt_acct)} | name-tag={normalize_sg_name(source_name_tag, src_acct, tgt_acct)}"

    return _make_match(source_sg, None, normalized_key, "unmatched", "unmatched")


def build_match_map(source_groups, target_sgs, name_map, src_acct, tgt_acct):
    indexes = index_target_sgs(target_sgs, src_acct, tgt_acct)
    match_by_source_name = {}
    unsafe_reasons = []
    target_by_group_id = {sg.get("GroupId"): sg for sg in target_sgs if sg.get("GroupId")}
    for sg in source_groups:
        if is_default_sg(sg):
            continue
        match = match_source_to_target(sg, indexes, name_map, src_acct, tgt_acct)
        match_by_source_name[sg.get("GroupName", "")] = match
        if match.ambiguous:
            unsafe_reasons.append(f"Ambiguous match for source SG '{match.source_group_name}': {match.ambiguity_reason}")
        if match.match_confidence == "low":
            unsafe_reasons.append(
                f"Low-confidence normalized match for source SG '{match.source_group_name}' using key '{match.matched_key_value or match.normalized_match_key}' -> target '{match.target_group_name}'"
            )
    return match_by_source_name, unsafe_reasons, target_by_group_id


def build_source_id_maps(source_groups, match_by_source_name):
    by_source_id, by_source_name = {}, {}
    for sg in source_groups:
        name = sg.get("GroupName", "")
        match = match_by_source_name.get(name)
        if not match:
            continue
        by_source_name[name] = match
        if sg.get("GroupId"):
            by_source_id[sg["GroupId"]] = match
    return by_source_id, by_source_name


def _sorted_clean(items, id_key):
    cleaned = []
    for r in items or []:
        item = {}
        if id_key in r:
            item[id_key] = r[id_key]
        if "Description" in r:
            item["Description"] = r["Description"]
        if item:
            cleaned.append(item)
    return sorted(cleaned, key=lambda x: json.dumps(x, sort_keys=True))


def clean_user_group_pairs(pairs, source_id_to_match, source_name_to_match, notes=None):
    cleaned = []
    for pair in pairs or []:
        src_gid = pair.get("GroupId")
        src_gname = pair.get("GroupName")
        match = source_id_to_match.get(src_gid) if src_gid else None
        if not match and src_gname:
            match = source_name_to_match.get(src_gname)
        if match and match.target_group_id:
            item = {"GroupId": match.target_group_id}
            if "Description" in pair:
                item["Description"] = pair["Description"]
            cleaned.append(item)
        elif notes is not None:
            notes.append(f"Could not remap SG reference GroupId={src_gid}, GroupName={src_gname}")
    return sorted(cleaned, key=lambda x: json.dumps(x, sort_keys=True))


def canonicalize_permission(p, source_id_to_match, source_name_to_match, notes=None):
    norm = {"IpProtocol": p.get("IpProtocol")}
    if p.get("FromPort") is not None:
        norm["FromPort"] = p.get("FromPort")
    if p.get("ToPort") is not None:
        norm["ToPort"] = p.get("ToPort")
    ip_ranges = _sorted_clean(p.get("IpRanges", []), "CidrIp")
    ipv6_ranges = _sorted_clean(p.get("Ipv6Ranges", []), "CidrIpv6")
    prefix_lists = _sorted_clean(p.get("PrefixListIds", []), "PrefixListId")
    user_groups = clean_user_group_pairs(p.get("UserIdGroupPairs", []), source_id_to_match, source_name_to_match, notes)
    if ip_ranges:
        norm["IpRanges"] = ip_ranges
    if ipv6_ranges:
        norm["Ipv6Ranges"] = ipv6_ranges
    if prefix_lists:
        norm["PrefixListIds"] = prefix_lists
    if user_groups:
        norm["UserIdGroupPairs"] = user_groups
    return norm


def canonicalize_permissions(perms, source_id_to_match, source_name_to_match, notes=None):
    out = []
    for p in perms or []:
        cp = canonicalize_permission(p, source_id_to_match, source_name_to_match, notes)
        has_target = any(k in cp for k in ["IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs"])
        if cp.get("IpProtocol") == "-1" or has_target:
            out.append(cp)
    return sorted(out, key=lambda x: json.dumps(x, sort_keys=True))


def permission_key(p):
    return json.dumps(p, sort_keys=True, separators=(",", ":"))


def diff_permissions(source_perms, target_perms):
    source_by_key = {permission_key(p): p for p in source_perms}
    target_by_key = {permission_key(p): p for p in target_perms}
    return (
        [source_by_key[k] for k in sorted(source_by_key.keys() - target_by_key.keys())],
        [target_by_key[k] for k in sorted(target_by_key.keys() - source_by_key.keys())],
    )


def find_many_to_one_source_target_mappings(results):
    reasons = []
    target_to_sources = defaultdict(list)
    for r in results:
        if r.target_group_id:
            target_to_sources[r.target_group_id].append(r.source_group_name)
    for target_group_id, sources in target_to_sources.items():
        if len(set(sources)) > 1:
            reasons.append(f"Multiple source SGs map to one target SG {target_group_id}: {', '.join(sorted(set(sources)))}")
    return reasons


def build_plan(source_groups, target_sgs, name_map, src_acct, tgt_acct) -> Plan:
    match_by_source_name, unsafe_reasons, target_by_group_id = build_match_map(source_groups, target_sgs, name_map, src_acct, tgt_acct)
    source_id_to_match, source_name_to_match = build_source_id_maps(source_groups, match_by_source_name)
    results = []
    for sg in source_groups:
        if is_default_sg(sg):
            continue
        source_name = sg.get("GroupName", "")
        match = match_by_source_name[source_name]
        target_sg = target_by_group_id.get(match.target_group_id) if match.target_group_id else None
        result = SgAuditResult(
            source_group_name=match.source_group_name,
            normalized_match_key=match.normalized_match_key,
            source_group_id=match.source_group_id,
            source_name_tag=match.source_name_tag,
            target_group_name=match.target_group_name,
            target_group_id=match.target_group_id,
            target_name_tag=match.target_name_tag,
            exists_in_target=bool(target_sg),
            match_method=match.match_method,
            match_confidence=match.match_confidence,
            matched_key_type=match.matched_key_type,
            matched_key_value=match.matched_key_value,
            ambiguous=match.ambiguous,
            ambiguity_reason=match.ambiguity_reason,
        )
        if match.ambiguous:
            result.notes.append(match.ambiguity_reason or "Ambiguous match.")
            result.drift_fields.append("AmbiguousMatch")
            results.append(result)
            continue
        if not target_sg:
            result.missing.append("SG missing in target")
            results.append(result)
            continue

        notes = []
        src_ing = canonicalize_permissions(sg.get("IpPermissions", []), source_id_to_match, source_name_to_match, notes)
        src_eg = canonicalize_permissions(sg.get("IpPermissionsEgress", []), source_id_to_match, source_name_to_match, notes)
        tgt_ing = canonicalize_permissions(target_sg.get("IpPermissions", []), source_id_to_match, source_name_to_match, notes)
        tgt_eg = canonicalize_permissions(target_sg.get("IpPermissionsEgress", []), source_id_to_match, source_name_to_match, notes)
        missing_ing, extra_ing = diff_permissions(src_ing, tgt_ing)
        missing_eg, extra_eg = diff_permissions(src_eg, tgt_eg)
        result.missing_ingress_rules = missing_ing
        result.extra_ingress_rules = extra_ing
        result.missing_egress_rules = missing_eg
        result.extra_egress_rules = extra_eg
        if missing_ing or extra_ing:
            result.drift_fields.append("Ingress")
        if missing_eg or extra_eg:
            result.drift_fields.append("Egress")
        if canonical_tags(sg.get("Tags", [])) != canonical_tags(target_sg.get("Tags", [])):
            result.tag_drift = True
            result.drift_fields.append("Tags")
        if (sg.get("Description") or "") != (target_sg.get("Description") or ""):
            result.description_drift = True
            result.drift_fields.append("Description")
            result.notes.append("AWS does not support direct SG description update. Recreate required for exact description parity.")
        result.notes.extend(sorted(set(notes)))
        result.drift_fields = sorted(set(result.drift_fields))
        results.append(result)
    unsafe_reasons.extend(find_many_to_one_source_target_mappings(results))
    return Plan(changes=results, unsafe_reasons=sorted(set(unsafe_reasons)))


def compute_summary(results):
    total = len(results)
    missing = [r for r in results if not r.exists_in_target and not r.ambiguous]
    ambiguous = [r for r in results if r.ambiguous]
    low_conf = [r for r in results if r.match_confidence == "low"]
    drift = [r for r in results if r.exists_in_target and not r.in_sync]
    in_sync = total - len(missing) - len(drift) - len(ambiguous)
    return {
        "total": total,
        "in_sync": max(in_sync, 0),
        "drift": len(drift),
        "missing": len(missing),
        "ambiguous": len(ambiguous),
        "low_confidence_matches": len(low_conf),
        "missing_list": [
            {
                "source_group_name": r.source_group_name,
                "source_name_tag": r.source_name_tag,
                "normalized_match_key": r.normalized_match_key,
                "match_method": r.match_method,
            }
            for r in missing
        ],
        "ambiguous_list": [
            {
                "source_group_name": r.source_group_name,
                "source_name_tag": r.source_name_tag,
                "normalized_match_key": r.normalized_match_key,
                "matched_key_type": r.matched_key_type,
                "matched_key_value": r.matched_key_value,
                "reason": r.ambiguity_reason,
            }
            for r in ambiguous
        ],
        "low_confidence_list": [
            {
                "source_group_name": r.source_group_name,
                "source_name_tag": r.source_name_tag,
                "target_group_name": r.target_group_name,
                "target_name_tag": r.target_name_tag,
                "normalized_match_key": r.normalized_match_key,
                "matched_key_type": r.matched_key_type,
                "matched_key_value": r.matched_key_value,
                "match_method": r.match_method,
            }
            for r in low_conf
        ],
        "drift_list": [
            {
                "source_group_name": r.source_group_name,
                "source_name_tag": r.source_name_tag,
                "target_group_name": r.target_group_name,
                "target_name_tag": r.target_name_tag,
                "target_group_id": r.target_group_id,
                "normalized_match_key": r.normalized_match_key,
                "matched_key_type": r.matched_key_type,
                "matched_key_value": r.matched_key_value,
                "match_method": r.match_method,
                "match_confidence": r.match_confidence,
                "fields": r.drift_fields,
                "missing_ingress_rules": len(r.missing_ingress_rules),
                "extra_ingress_rules": len(r.extra_ingress_rules),
                "missing_egress_rules": len(r.missing_egress_rules),
                "extra_egress_rules": len(r.extra_egress_rules),
                "tag_drift": r.tag_drift,
                "description_drift": r.description_drift,
            }
            for r in drift
        ],
    }


def write_report(report_path: str, plan: Plan, mode: str) -> None:
    payload = {
        "mode": mode,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": compute_summary(plan.changes),
        "unsafe_reasons": plan.unsafe_reasons,
        "results": [asdict(r) for r in plan.changes],
    }
    Path(report_path).parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    log(f"[REPORT] saved -> {report_path}")


def print_summary(plan: Plan) -> None:
    summary = compute_summary(plan.changes)
    log("\n========== SUMMARY ==========")
    log(f"Total                 : {summary['total']}")
    log(f"In Sync               : {summary['in_sync']}")
    log(f"Drift                 : {summary['drift']}")
    log(f"Missing               : {summary['missing']}")
    log(f"Ambiguous             : {summary['ambiguous']}")
    log(f"Low Confidence Matches: {summary['low_confidence_matches']}")
    log("=============================\n")
    if summary["missing_list"]:
        log("Missing SGs:")
        for item in summary["missing_list"]:
            log(f" - {item['source_group_name']} | NameTag={item.get('source_name_tag') or ''} | key={item['normalized_match_key']}")
    if summary["ambiguous_list"]:
        log("\nAmbiguous Matches:")
        for item in summary["ambiguous_list"]:
            log(
                f" - {item['source_group_name']} | NameTag={item.get('source_name_tag') or ''} "
                f"| key={item['normalized_match_key']} | matched={item.get('matched_key_type')}:{item.get('matched_key_value')} "
                f"({item['reason']})"
            )
    if summary["low_confidence_list"]:
        log("\nLow Confidence Matches:")
        for item in summary["low_confidence_list"]:
            log(
                f" - {item['source_group_name']} -> {item['target_group_name']} "
                f"| source NameTag={item.get('source_name_tag') or ''} "
                f"| target NameTag={item.get('target_name_tag') or ''} "
                f"| matched={item.get('matched_key_type')}:{item.get('matched_key_value')} "
                f"| method={item['match_method']}"
            )
    if summary["drift_list"]:
        log("\nDrifted SGs:")
        for d in summary["drift_list"]:
            log(
                f" - {d['source_group_name']} -> {d['target_group_name']} "
                f"[source NameTag={d.get('source_name_tag') or ''}, target NameTag={d.get('target_name_tag') or ''}, "
                f"matched={d.get('matched_key_type')}:{d.get('matched_key_value')}, confidence={d['match_confidence']}] "
                f"({', '.join(d['fields'])}) [+ing:{d['missing_ingress_rules']} -ing:{d['extra_ingress_rules']} "
                f"+eg:{d['missing_egress_rules']} -eg:{d['extra_egress_rules']}]"
            )
    if plan.unsafe_reasons:
        log("\nUnsafe Conditions:")
        for reason in plan.unsafe_reasons:
            log(f" - {reason}")


def compute_exit_code(plan: Plan) -> int:
    summary = compute_summary(plan.changes)
    return 1 if summary["drift"] > 0 or summary["missing"] > 0 or summary["ambiguous"] > 0 or plan.unsafe_reasons else 0


def enforce_apply_safety(plan: Plan, args: Args) -> None:
    blocking_reasons = []
    for reason in plan.unsafe_reasons:
        if "Low-confidence" in reason and args.allow_low_confidence:
            continue
        if ("Ambiguous" in reason or "Multiple source SGs map" in reason) and args.allow_ambiguous:
            continue
        blocking_reasons.append(reason)
    for r in plan.changes:
        if r.ambiguous and not args.allow_ambiguous:
            blocking_reasons.append(f"Blocked ambiguous source SG '{r.source_group_name}': {r.ambiguity_reason}")
        if r.match_confidence == "low" and not args.allow_low_confidence:
            blocking_reasons.append(
                f"Blocked low-confidence match '{r.source_group_name}' -> '{r.target_group_name}' using key '{r.matched_key_value or r.normalized_match_key}'"
            )
        if any(n.startswith("Could not remap SG reference") for n in r.notes):
            blocking_reasons.append(f"Blocked '{r.source_group_name}' because one or more SG references could not be remapped.")
    blocking_reasons = sorted(set(blocking_reasons))
    if blocking_reasons:
        eprint("\n[SAFETY BLOCK] --yes remediation was blocked.")
        for reason in blocking_reasons:
            eprint(f" - {reason}")
        eprint("\nUse --dry-run and review the report. For intentional cases, use --name-map, --allow-low-confidence, or --allow-ambiguous.")
        raise RuntimeError("Unsafe matching conditions detected. Remediation not applied.")


def create_missing_security_groups(ec2, source_groups, target_vpc_id, match_by_source_name):
    created = 0
    for sg in source_groups:
        if is_default_sg(sg):
            continue
        source_name = sg.get("GroupName", "")
        match = match_by_source_name.get(source_name)
        if match and match.target_group_id:
            continue
        if match and match.ambiguous:
            log(f"[SKIP-CREATE] Ambiguous match for {source_name}; not creating.")
            continue
        description = sg.get("Description") or f"Synced from source SG {sg.get('GroupId', '')}"
        tags = aws_tags(sg.get("Tags", []))
        log(f"[CREATE] SG missing in DR: {source_name}")
        kwargs = {"GroupName": source_name, "Description": description[:255], "VpcId": target_vpc_id}
        if tags:
            kwargs["TagSpecifications"] = [{"ResourceType": "security-group", "Tags": tags}]
        try:
            response = ec2.create_security_group(**kwargs)
            created += 1
            log(f"[CREATE] Created {source_name} -> {response['GroupId']}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            if code == "InvalidGroup.Duplicate":
                log(f"[SKIP] SG already exists by exact name: {source_name}")
            else:
                eprint(f"[ERROR] Failed to create SG {source_name}: {code} {msg}")
                raise
    if created:
        log("[INFO] Waiting briefly for newly created SGs to become visible...")
        time.sleep(5)


def authorize_rules(ec2, group_id, rules, direction):
    for rule in rules or []:
        try:
            if direction == "ingress":
                ec2.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[rule])
            else:
                ec2.authorize_security_group_egress(GroupId=group_id, IpPermissions=[rule])
            log(f"[ADD-{direction.upper()}] {group_id}: {json.dumps(rule, sort_keys=True)}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            if code == "InvalidPermission.Duplicate":
                log(f"[SKIP-{direction.upper()}] Duplicate rule already exists on {group_id}")
            else:
                eprint(f"[ERROR] Failed to add {direction} rule on {group_id}: {code} {msg}")
                raise


def revoke_rules(ec2, group_id, rules, direction):
    for rule in rules or []:
        try:
            if direction == "ingress":
                ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[rule])
            else:
                ec2.revoke_security_group_egress(GroupId=group_id, IpPermissions=[rule])
            log(f"[REMOVE-{direction.upper()}] {group_id}: {json.dumps(rule, sort_keys=True)}")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            msg = e.response.get("Error", {}).get("Message", "")
            if code == "InvalidPermission.NotFound":
                log(f"[SKIP-{direction.upper()}] Rule already absent on {group_id}")
            else:
                eprint(f"[ERROR] Failed to remove {direction} rule on {group_id}: {code} {msg}")
                raise


def sync_tags_to_target(ec2, target_group_id, source_tags):
    tags = aws_tags(source_tags)
    if tags:
        ec2.create_tags(Resources=[target_group_id], Tags=tags)
        log(f"[TAGS] Synced tags on {target_group_id}")


def apply_plan(ec2, source_groups, target_vpc_id, name_map, src_acct, tgt_acct, args):
    log("\n========== APPLY MODE ==========")
    log("[INFO] --yes was provided. Remediation will be applied to the target DR VPC.")
    log("================================\n")
    target_sgs = get_target_sgs(ec2, target_vpc_id)
    initial_plan = build_plan(source_groups, target_sgs, name_map, src_acct, tgt_acct)
    enforce_apply_safety(initial_plan, args)
    if args.create_missing:
        match_by_source_name, _, _ = build_match_map(source_groups, target_sgs, name_map, src_acct, tgt_acct)
        create_missing_security_groups(ec2, source_groups, target_vpc_id, match_by_source_name)
    else:
        log("[SKIP-CREATE] --no-create-missing was provided.")
    target_sgs = get_target_sgs(ec2, target_vpc_id)
    plan = build_plan(source_groups, target_sgs, name_map, src_acct, tgt_acct)
    enforce_apply_safety(plan, args)
    source_by_name = {sg.get("GroupName", ""): sg for sg in source_groups if not is_default_sg(sg)}
    for result in plan.changes:
        if result.ambiguous or not result.exists_in_target or not result.target_group_id:
            log(f"[SKIP] Cannot safely apply {result.source_group_name}")
            continue
        if result.match_confidence == "low" and not args.allow_low_confidence:
            log(f"[SKIP] Low-confidence match for {result.source_group_name}")
            continue
        source_sg = source_by_name.get(result.source_group_name)
        if not source_sg:
            log(f"[SKIP] Source SG not found in source map: {result.source_group_name}")
            continue
        if args.sync_tags and result.tag_drift:
            sync_tags_to_target(ec2, result.target_group_id, source_sg.get("Tags", []))
        authorize_rules(ec2, result.target_group_id, result.missing_ingress_rules, "ingress")
        authorize_rules(ec2, result.target_group_id, result.missing_egress_rules, "egress")
        if args.revoke_extra_rules:
            revoke_rules(ec2, result.target_group_id, result.extra_ingress_rules, "ingress")
            revoke_rules(ec2, result.target_group_id, result.extra_egress_rules, "egress")
        elif result.extra_ingress_rules or result.extra_egress_rules:
            log(f"[SKIP-REVOKE] Extra rules left untouched for {result.source_group_name}")
    log("\n[APPLY] Remediation pass completed.")


def debug_name_matching_dump(source_groups, target_sgs, src_acct, tgt_acct, limit=100):
    log("\n========== NAME MATCH DEBUG DUMP ==========")

    log("\n--- SOURCE SECURITY GROUPS ---")
    shown = 0
    for sg in source_groups:
        if is_default_sg(sg):
            continue
        if shown >= limit:
            log(f"... source debug truncated at {limit} entries")
            break
        group_name = sg.get("GroupName", "")
        name_tag_value = name_tag(sg) or ""
        log(
            f"SOURCE | GroupName='{group_name}' "
            f"| GroupId='{sg.get('GroupId')}' "
            f"| NameTag='{name_tag_value}' "
            f"| NormGroup='{normalize_sg_name(group_name, src_acct, tgt_acct)}' "
            f"| NormNameTag='{normalize_sg_name(name_tag_value, src_acct, tgt_acct)}' "
            f"| CompactGroup='{compact_name_key(group_name, src_acct, tgt_acct)}' "
            f"| CompactNameTag='{compact_name_key(name_tag_value, src_acct, tgt_acct)}' "
            f"| CFNStackLogical='{cfn_match_key(sg)}' "
            f"| CFNLogical='{cfn_logical_key(sg)}'"
        )
        shown += 1

    log("\n--- TARGET SECURITY GROUPS ---")
    shown = 0
    for sg in target_sgs:
        if is_default_sg(sg):
            continue
        if shown >= limit:
            log(f"... target debug truncated at {limit} entries")
            break
        group_name = sg.get("GroupName", "")
        name_tag_value = name_tag(sg) or ""
        log(
            f"TARGET | GroupName='{group_name}' "
            f"| GroupId='{sg.get('GroupId')}' "
            f"| NameTag='{name_tag_value}' "
            f"| NormGroup='{normalize_sg_name(group_name, src_acct, tgt_acct)}' "
            f"| NormNameTag='{normalize_sg_name(name_tag_value, src_acct, tgt_acct)}' "
            f"| CompactGroup='{compact_name_key(group_name, src_acct, tgt_acct)}' "
            f"| CompactNameTag='{compact_name_key(name_tag_value, src_acct, tgt_acct)}' "
            f"| CFNStackLogical='{cfn_match_key(sg)}' "
            f"| CFNLogical='{cfn_logical_key(sg)}'"
        )
        shown += 1

    log("===========================================\n")


def print_name_preview(source_groups, target_sgs, name_map, src_acct, tgt_acct):
    match_by_source_name, unsafe_reasons, _ = build_match_map(source_groups, target_sgs, name_map, src_acct, tgt_acct)

    log("\n========== NAME PREVIEW ==========")

    for sg in source_groups:
        if is_default_sg(sg):
            continue

        match = match_by_source_name[sg.get("GroupName", "")]

        log(
            f"Source: {match.source_group_name} "
            f"| Source NameTag: {match.source_name_tag or ''} "
            f"| Target: {match.target_group_name or 'NOT FOUND'} "
            f"| Target NameTag: {match.target_name_tag or ''} "
            f"| Target ID: {match.target_group_id or 'N/A'} "
            f"| Key: {match.normalized_match_key} "
            f"| Matched: {(match.matched_key_type or 'N/A')}={(match.matched_key_value or 'N/A')} "
            f"| Method: {match.match_method} "
            f"| Confidence: {match.match_confidence}"
        )

        if match.ambiguous:
            log(f"  Ambiguous: {match.ambiguity_reason}")

        if not match.target_group_id:
            possible_same_key = []
            source_values = identity_values_for_sg(sg, src_acct, tgt_acct)
            source_norms = set(source_values.get("group_name_normalized", []) + source_values.get("name_tag_normalized", []))
            source_compacts = set(source_values.get("group_name_compact", []) + source_values.get("name_tag_compact", []))

            for candidate_sg in target_sgs:
                candidate_values = identity_values_for_sg(candidate_sg, src_acct, tgt_acct)
                candidate_norms = set(candidate_values.get("group_name_normalized", []) + candidate_values.get("name_tag_normalized", []))
                candidate_compacts = set(candidate_values.get("group_name_compact", []) + candidate_values.get("name_tag_compact", []))
                if source_norms.intersection(candidate_norms) or source_compacts.intersection(candidate_compacts):
                    possible_same_key.append(candidate_sg)

            if possible_same_key:
                log("  Possible target candidates with same normalized/compact key:")
                for candidate in possible_same_key:
                    log(f"   - GroupName={candidate.get('GroupName')} | NameTag={name_tag(candidate) or ''} | GroupId={candidate.get('GroupId')}")

    if unsafe_reasons:
        log("\nUnsafe Conditions:")
        for reason in unsafe_reasons:
            log(f" - {reason}")

    log("==================================\n")


def main() -> int:
    args = parse_args()

    source_groups = [s for s in load_json_security_groups(args.json_path) if not is_default_sg(s)]

    if not source_groups:
        log("No non-default security groups found.")
        return 0

    name_map = load_name_map(args.name_map_path)

    ec2 = get_ec2(args.target_profile, args.target_region)
    tgt_acct = args.target_account_id or get_account_id(args.target_profile, args.target_region)

    src_acct = args.source_account_id or next((s.get("OwnerId") for s in source_groups if s.get("OwnerId")), "")

    if not src_acct:
        log("[WARN] No source account ID provided and none found in JSON. Account-ID normalization will be skipped.")

    log(f"[INFO] Source SGs: {len(source_groups)}")
    log(f"[INFO] Source account from export/CLI: {src_acct or 'UNKNOWN'}")
    log(f"[INFO] Target account: {tgt_acct}")
    log(f"[INFO] Target region: {args.target_region}")
    log(f"[INFO] Target VPC: {args.target_vpc_id}")

    if name_map:
        log(f"[INFO] Loaded manual name-map entries: {len(name_map)}")

    if args.target_json_path:
        target_sgs = load_target_security_groups(args.target_json_path, args.target_vpc_id)
        log(f"[INFO] Target SGs loaded from JSON for VPC {args.target_vpc_id}: {len(target_sgs)}")
    else:
        target_sgs = get_target_sgs(ec2, args.target_vpc_id)
        log(f"[INFO] Target SGs discovered live in VPC: {len(target_sgs)}")

    print_discovery_diagnostics(source_groups, target_sgs, args.target_vpc_id, src_acct, tgt_acct)

    if args.debug_names:
        debug_name_matching_dump(source_groups, target_sgs, src_acct, tgt_acct)

    if args.name_preview:
        print_name_preview(source_groups, target_sgs, name_map, src_acct, tgt_acct)
        return 0

    initial_plan = build_plan(source_groups, target_sgs, name_map, src_acct, tgt_acct)

    log("\n[INITIAL AUDIT]")
    print_summary(initial_plan)

    if args.dry_run or args.report_only:
        write_report(args.report_path, initial_plan, mode="dry-run" if args.dry_run else "report-only")
        return compute_exit_code(initial_plan)

    if args.yes:
        apply_plan(ec2, source_groups, args.target_vpc_id, name_map, src_acct, tgt_acct, args)

        final_plan = build_plan(source_groups, get_target_sgs(ec2, args.target_vpc_id), name_map, src_acct, tgt_acct)

        log("\n[FINAL AUDIT AFTER REMEDIATION]")
        print_summary(final_plan)

        write_report(args.report_path, final_plan, mode="yes-applied")

        return compute_exit_code(final_plan)

    raise ValueError("No valid mode selected.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        eprint("[ABORTED] Interrupted by user.")
        sys.exit(130)
    except Exception as e:
        eprint(f"[FATAL] {e}")
        sys.exit(1)
