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


def boto3_session(profile: str, region: str):
    return boto3.Session(profile_name=profile, region_name=region)


def get_elbv2(profile: str, region: str):
    return boto3_session(profile, region).client("elbv2")


def get_acm(profile: str, region: str):
    return boto3_session(profile, region).client("acm")


@dataclass
class Args:
    source_profile: str
    source_region: str
    source_alb_name: str
    target_profile: str
    target_region: str
    target_alb_name: str
    dry_run: bool
    report_only: bool


@dataclass
class ListenerAuditResult:
    listener_key: str
    exists_in_target: bool = False
    listener_match: bool = True
    rules_match: bool = True
    notes: List[str] = field(default_factory=list)
    missing_rules: List[Dict[str, Any]] = field(default_factory=list)
    extra_rules: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def in_sync(self) -> bool:
        return self.exists_in_target and self.listener_match and self.rules_match


def get_load_balancer_by_name(elbv2, alb_name: str) -> Dict[str, Any]:
    resp = elbv2.describe_load_balancers(Names=[alb_name])
    lbs = resp.get("LoadBalancers", [])
    if not lbs:
        raise RuntimeError(f"Load balancer not found: {alb_name}")
    return lbs[0]


def describe_listeners(elbv2, lb_arn: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_listeners")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate(LoadBalancerArn=lb_arn):
        out.extend(page.get("Listeners", []))
    return out


def describe_rules(elbv2, listener_arn: str) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_rules")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate(ListenerArn=listener_arn):
        out.extend(page.get("Rules", []))
    return out


def describe_all_target_groups(elbv2) -> List[Dict[str, Any]]:
    paginator = elbv2.get_paginator("describe_target_groups")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate(PageSize=400):
        out.extend(page.get("TargetGroups", []))
    return out


def tg_maps_by_name(elbv2) -> Tuple[Dict[str, str], Dict[str, str]]:
    tgs = describe_all_target_groups(elbv2)
    name_to_arn = {tg["TargetGroupName"]: tg["TargetGroupArn"] for tg in tgs}
    arn_to_name = {tg["TargetGroupArn"]: tg["TargetGroupName"] for tg in tgs}
    return name_to_arn, arn_to_name


def list_certificates(acm) -> List[Dict[str, Any]]:
    paginator = acm.get_paginator("list_certificates")
    out: List[Dict[str, Any]] = []
    for page in paginator.paginate(CertificateStatuses=["ISSUED"]):
        out.extend(page.get("CertificateSummaryList", []))
    return out


def cert_domain_map(acm) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for cert in list_certificates(acm):
        domain = cert.get("DomainName")
        arn = cert.get("CertificateArn")
        if domain and arn and domain not in result:
            result[domain] = arn
    return result


def source_cert_arn_to_domain(acm, cert_arns: List[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for arn in cert_arns:
        try:
            resp = acm.describe_certificate(CertificateArn=arn)
            domain = resp.get("Certificate", {}).get("DomainName")
            if domain:
                result[arn] = domain
        except ClientError:
            continue
    return result


def listener_key(listener: Dict[str, Any]) -> str:
    return f"{listener.get('Protocol')}:{listener.get('Port')}"


def sort_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: sort_obj(obj[k]) for k in sorted(obj)}
    if isinstance(obj, list):
        return [sort_obj(x) for x in obj]
    return obj


def json_key(obj: Any) -> str:
    return json.dumps(sort_obj(obj), sort_keys=True)


def normalize_certificate_arns(
    certs: List[Dict[str, Any]],
    source_cert_to_domain: Dict[str, str],
    target_domain_to_cert: Dict[str, str],
) -> Tuple[List[Dict[str, str]], List[str]]:
    normalized: List[Dict[str, str]] = []
    unresolved: List[str] = []

    for c in certs or []:
        src_arn = c.get("CertificateArn")
        if not src_arn:
            continue

        domain = source_cert_to_domain.get(src_arn)
        if not domain:
            unresolved.append(src_arn)
            continue

        tgt_arn = target_domain_to_cert.get(domain)
        if not tgt_arn:
            unresolved.append(f"{src_arn} (domain={domain})")
            continue

        normalized.append({"CertificateArn": tgt_arn})

    normalized = sorted(normalized, key=lambda x: x["CertificateArn"])
    return normalized, unresolved


def _map_tg_arn(
    src_tg_arn: Optional[str],
    source_tg_arn_to_name: Dict[str, str],
    target_tg_name_to_arn: Dict[str, str],
) -> Tuple[Optional[str], Optional[str]]:
    if not src_tg_arn:
        return None, "Missing source target group ARN"

    if source_tg_arn_to_name:
        tg_name = source_tg_arn_to_name.get(src_tg_arn)
        if not tg_name:
            return None, f"Missing source TG name for ARN {src_tg_arn}"
        tgt_tg_arn = target_tg_name_to_arn.get(tg_name)
        if not tgt_tg_arn:
            return None, f"Missing target TG for source TG name {tg_name}"
        return tgt_tg_arn, None

    return src_tg_arn, None


def normalize_actions(
    actions: List[Dict[str, Any]],
    source_tg_arn_to_name: Dict[str, str],
    target_tg_name_to_arn: Dict[str, str],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    normalized: List[Dict[str, Any]] = []
    unresolved: List[str] = []

    for action in actions or []:
        action_type = action["Type"]
        a: Dict[str, Any] = {"Type": action_type}

        if action_type == "forward":
            forward_targets: List[Dict[str, Any]] = []
            stickiness_cfg = None

            if "ForwardConfig" in action and action["ForwardConfig"].get("TargetGroups"):
                fc = action["ForwardConfig"]
                for tg in fc.get("TargetGroups", []):
                    mapped_tg_arn, err = _map_tg_arn(
                        tg.get("TargetGroupArn"),
                        source_tg_arn_to_name,
                        target_tg_name_to_arn,
                    )
                    if err:
                        unresolved.append(err)
                        continue

                    item = {"TargetGroupArn": mapped_tg_arn}
                    if "Weight" in tg:
                        item["Weight"] = tg["Weight"]
                    forward_targets.append(item)

                if "TargetGroupStickinessConfig" in fc:
                    stickiness_cfg = fc["TargetGroupStickinessConfig"]

            elif "TargetGroupArn" in action:
                mapped_tg_arn, err = _map_tg_arn(
                    action.get("TargetGroupArn"),
                    source_tg_arn_to_name,
                    target_tg_name_to_arn,
                )
                if err:
                    unresolved.append(err)
                    continue

                forward_targets.append({"TargetGroupArn": mapped_tg_arn})

            else:
                unresolved.append("Forward action missing both TargetGroupArn and ForwardConfig")
                continue

            a["ForwardConfig"] = {
                "TargetGroups": sorted(
                    forward_targets,
                    key=lambda x: (x["TargetGroupArn"], x.get("Weight", 0))
                )
            }

            if stickiness_cfg is not None:
                a["ForwardConfig"]["TargetGroupStickinessConfig"] = stickiness_cfg

        elif action_type == "redirect":
            a["RedirectConfig"] = action.get("RedirectConfig", {})

        elif action_type == "fixed-response":
            a["FixedResponseConfig"] = action.get("FixedResponseConfig", {})

        elif action_type == "authenticate-oidc":
            a["AuthenticateOidcConfig"] = action.get("AuthenticateOidcConfig", {})

        elif action_type == "authenticate-cognito":
            a["AuthenticateCognitoConfig"] = action.get("AuthenticateCognitoConfig", {})

        else:
            unresolved.append(f"Unsupported action type {action_type}")
            continue

        normalized.append(sort_obj(a))

    normalized = sorted(normalized, key=json_key)
    return normalized, unresolved


def normalize_conditions(conditions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for cond in conditions or []:
        c: Dict[str, Any] = {"Field": cond["Field"]}

        if "HostHeaderConfig" in cond:
            c["HostHeaderConfig"] = {
                "Values": sorted(cond["HostHeaderConfig"].get("Values", []))
            }
        elif "PathPatternConfig" in cond:
            c["PathPatternConfig"] = {
                "Values": sorted(cond["PathPatternConfig"].get("Values", []))
            }
        elif "HttpHeaderConfig" in cond:
            c["HttpHeaderConfig"] = {
                "HttpHeaderName": cond["HttpHeaderConfig"].get("HttpHeaderName"),
                "Values": sorted(cond["HttpHeaderConfig"].get("Values", [])),
            }
        elif "QueryStringConfig" in cond:
            items = cond["QueryStringConfig"].get("Values", [])
            c["QueryStringConfig"] = {
                "Values": sorted(
                    [{"Key": x.get("Key"), "Value": x.get("Value")} for x in items],
                    key=lambda x: (x.get("Key") or "", x.get("Value") or ""),
                )
            }
        elif "SourceIpConfig" in cond:
            c["SourceIpConfig"] = {
                "Values": sorted(cond["SourceIpConfig"].get("Values", []))
            }
        elif "HttpRequestMethodConfig" in cond:
            c["HttpRequestMethodConfig"] = {
                "Values": sorted(cond["HttpRequestMethodConfig"].get("Values", []))
            }

        out.append(sort_obj(c))

    return sorted(out, key=json_key)


def normalize_listener(
    listener: Dict[str, Any],
    source_tg_arn_to_name: Dict[str, str],
    target_tg_name_to_arn: Dict[str, str],
    source_cert_to_domain: Dict[str, str],
    target_domain_to_cert: Dict[str, str],
) -> Tuple[Dict[str, Any], List[str]]:
    unresolved: List[str] = []
    norm: Dict[str, Any] = {
        "Protocol": listener.get("Protocol"),
        "Port": listener.get("Port"),
    }

    if listener.get("SslPolicy"):
        norm["SslPolicy"] = listener["SslPolicy"]

    certs, unresolved_certs = normalize_certificate_arns(
        listener.get("Certificates", []),
        source_cert_to_domain,
        target_domain_to_cert,
    )
    if certs:
        norm["Certificates"] = certs
    unresolved.extend(unresolved_certs)

    actions, unresolved_actions = normalize_actions(
        listener.get("DefaultActions", []),
        source_tg_arn_to_name,
        target_tg_name_to_arn,
    )
    norm["DefaultActions"] = actions
    unresolved.extend(unresolved_actions)

    return sort_obj(norm), unresolved


def normalize_rule(
    rule: Dict[str, Any],
    source_tg_arn_to_name: Dict[str, str],
    target_tg_name_to_arn: Dict[str, str],
) -> Tuple[Dict[str, Any], List[str]]:
    unresolved: List[str] = []

    actions, unresolved_actions = normalize_actions(
        rule.get("Actions", []),
        source_tg_arn_to_name,
        target_tg_name_to_arn,
    )
    unresolved.extend(unresolved_actions)

    norm = {
        "Priority": rule.get("Priority"),
        "Conditions": normalize_conditions(rule.get("Conditions", [])),
        "Actions": actions,
    }

    return sort_obj(norm), unresolved


def find_target_listener_by_port_protocol(target_listeners: List[Dict[str, Any]], protocol: str, port: int) -> Optional[Dict[str, Any]]:
    for l in target_listeners:
        if l.get("Protocol") == protocol and l.get("Port") == port:
            return l
    return None


def create_listener(
    elbv2,
    target_lb_arn: str,
    normalized_listener: Dict[str, Any],
    dry_run: bool,
) -> Optional[str]:
    args: Dict[str, Any] = {
        "LoadBalancerArn": target_lb_arn,
        "Protocol": normalized_listener["Protocol"],
        "Port": normalized_listener["Port"],
        "DefaultActions": normalized_listener["DefaultActions"],
    }

    if "SslPolicy" in normalized_listener:
        args["SslPolicy"] = normalized_listener["SslPolicy"]
    if "Certificates" in normalized_listener:
        args["Certificates"] = normalized_listener["Certificates"]

    if dry_run:
        log(f"[DRY-RUN] Would create listener {normalized_listener['Protocol']}:{normalized_listener['Port']}")
        return None

    resp = elbv2.create_listener(**args)
    listener_arn = resp["Listeners"][0]["ListenerArn"]
    log(f"[CREATE] Listener {normalized_listener['Protocol']}:{normalized_listener['Port']} -> {listener_arn}")
    return listener_arn


def modify_listener(
    elbv2,
    listener_arn: str,
    normalized_listener: Dict[str, Any],
    dry_run: bool,
) -> None:
    args: Dict[str, Any] = {
        "ListenerArn": listener_arn,
        "DefaultActions": normalized_listener["DefaultActions"],
    }

    if "SslPolicy" in normalized_listener:
        args["SslPolicy"] = normalized_listener["SslPolicy"]
    if "Certificates" in normalized_listener:
        args["Certificates"] = normalized_listener["Certificates"]

    if dry_run:
        log(f"[DRY-RUN] Would modify listener {listener_arn}")
        return

    elbv2.modify_listener(**args)
    log(f"[SYNC] Modified listener {listener_arn}")


def delete_rule(elbv2, rule_arn: str, dry_run: bool) -> None:
    if dry_run:
        log(f"[DRY-RUN] Would delete rule {rule_arn}")
        return
    elbv2.delete_rule(RuleArn=rule_arn)


def create_rule(
    elbv2,
    listener_arn: str,
    normalized_rule: Dict[str, Any],
    dry_run: bool,
) -> None:
    args = {
        "ListenerArn": listener_arn,
        "Priority": int(normalized_rule["Priority"]),
        "Conditions": normalized_rule["Conditions"],
        "Actions": normalized_rule["Actions"],
    }

    if dry_run:
        log(f"[DRY-RUN] Would create rule priority {normalized_rule['Priority']} on {listener_arn}")
        return

    elbv2.create_rule(**args)
    log(f"[CREATE] Rule priority {normalized_rule['Priority']} on {listener_arn}")


def modify_rule(
    elbv2,
    rule_arn: str,
    normalized_rule: Dict[str, Any],
    dry_run: bool,
) -> None:
    args = {
        "RuleArn": rule_arn,
        "Conditions": normalized_rule["Conditions"],
        "Actions": normalized_rule["Actions"],
    }

    if dry_run:
        log(f"[DRY-RUN] Would modify rule {rule_arn}")
        return

    elbv2.modify_rule(**args)
    log(f"[SYNC] Modified rule {rule_arn}")


def non_default_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in rules if not r.get("IsDefault")]


def print_audit_report(results: List[ListenerAuditResult]) -> None:
    print("\n" + "=" * 80)
    print("FINAL ALB LISTENER / RULE SYNC AUDIT REPORT")
    print("=" * 80)

    in_sync = [r for r in results if r.in_sync]
    out_of_sync = [r for r in results if not r.in_sync]

    print(f"Total listeners audited : {len(results)}")
    print(f"In sync                 : {len(in_sync)}")
    print(f"Needs review            : {len(out_of_sync)}")
    print("")

    if not out_of_sync:
        print("All audited listeners and rules are in sync.")
        print("=" * 80)
        return

    for r in out_of_sync:
        print("-" * 80)
        print(f"Listener: {r.listener_key}")
        print(f"Exists   : {r.exists_in_target}")
        print(f"Listener : {'OK' if r.listener_match else 'MISMATCH'}")
        print(f"Rules    : {'OK' if r.rules_match else 'MISMATCH'}")
        if r.notes:
            print("Notes:")
            for n in r.notes:
                print(f"  - {n}")
        if r.missing_rules:
            print("Missing rules in target:")
            print(json.dumps(r.missing_rules, indent=2))
        if r.extra_rules:
            print("Extra rules in target:")
            print(json.dumps(r.extra_rules, indent=2))

    print("=" * 80)


def write_audit_report_json(results: List[ListenerAuditResult], path: str = "alb_listener_sync_report.json") -> None:
    payload = []
    for r in results:
        payload.append({
            "listener_key": r.listener_key,
            "exists_in_target": r.exists_in_target,
            "listener_match": r.listener_match,
            "rules_match": r.rules_match,
            "notes": r.notes,
            "missing_rules": r.missing_rules,
            "extra_rules": r.extra_rules,
            "in_sync": r.in_sync,
        })

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    log(f"[INFO] Wrote audit report to {path}")


def parse_args() -> Args:
    p = argparse.ArgumentParser(description="Sync ALB listeners and listener rules from source to target")

    p.add_argument("--source-profile", required=True)
    p.add_argument("--source-region", required=True)
    p.add_argument("--source-alb-name", required=True)

    p.add_argument("--target-profile", required=True)
    p.add_argument("--target-region", required=True)
    p.add_argument("--target-alb-name", required=True)

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
        dry_run=ns.dry_run,
        report_only=ns.report_only,
    )


def main() -> int:
    args = parse_args()

    src_elbv2 = get_elbv2(args.source_profile, args.source_region)
    tgt_elbv2 = get_elbv2(args.target_profile, args.target_region)

    src_acm = get_acm(args.source_profile, args.source_region)
    tgt_acm = get_acm(args.target_profile, args.target_region)

    src_lb = get_load_balancer_by_name(src_elbv2, args.source_alb_name)
    tgt_lb = get_load_balancer_by_name(tgt_elbv2, args.target_alb_name)

    log(f"[INFO] Source ALB: {args.source_alb_name} ({src_lb['LoadBalancerArn']})")
    log(f"[INFO] Target ALB: {args.target_alb_name} ({tgt_lb['LoadBalancerArn']})")

    src_listeners = describe_listeners(src_elbv2, src_lb["LoadBalancerArn"])
    tgt_listeners = describe_listeners(tgt_elbv2, tgt_lb["LoadBalancerArn"])

    log(f"[INFO] Source listeners to process: {len(src_listeners)}")

    src_tg_name_to_arn, src_tg_arn_to_name = tg_maps_by_name(src_elbv2)
    tgt_tg_name_to_arn, _ = tg_maps_by_name(tgt_elbv2)

    all_source_cert_arns: List[str] = []
    for l in src_listeners:
        for c in l.get("Certificates", []):
            arn = c.get("CertificateArn")
            if arn:
                all_source_cert_arns.append(arn)

    source_cert_to_domain = source_cert_arn_to_domain(src_acm, list(set(all_source_cert_arns)))
    target_domain_to_cert = cert_domain_map(tgt_acm)

    src_listener_norm: Dict[str, Dict[str, Any]] = {}
    src_listener_unresolved: Dict[str, List[str]] = {}
    src_rules_norm: Dict[str, List[Dict[str, Any]]] = {}
    src_rules_unresolved: Dict[str, List[str]] = {}

    for src_listener in src_listeners:
        key = listener_key(src_listener)

        norm_listener, unresolved_listener = normalize_listener(
            src_listener,
            src_tg_arn_to_name,
            tgt_tg_name_to_arn,
            source_cert_to_domain,
            target_domain_to_cert,
        )
        src_listener_norm[key] = norm_listener
        src_listener_unresolved[key] = unresolved_listener

        src_rules = non_default_rules(describe_rules(src_elbv2, src_listener["ListenerArn"]))
        norm_rules: List[Dict[str, Any]] = []
        unresolved_rules: List[str] = []

        for r in src_rules:
            norm_rule, unr = normalize_rule(r, src_tg_arn_to_name, tgt_tg_name_to_arn)
            norm_rules.append(norm_rule)
            unresolved_rules.extend(unr)

        src_rules_norm[key] = sorted(norm_rules, key=json_key)
        src_rules_unresolved[key] = unresolved_rules

    if not args.report_only:
        for src_listener in src_listeners:
            key = listener_key(src_listener)
            unresolved = src_listener_unresolved[key] + src_rules_unresolved[key]

            if unresolved:
                log(f"[WARN] {key}: unresolved dependencies found; listener/rule sync may be partial.")
                for item in unresolved:
                    log(f"[WARN]   - {item}")

            target_listener = find_target_listener_by_port_protocol(
                tgt_listeners,
                src_listener.get("Protocol"),
                src_listener.get("Port"),
            )

            if not target_listener:
                if not src_listener_unresolved[key]:
                    create_listener(
                        tgt_elbv2,
                        tgt_lb["LoadBalancerArn"],
                        src_listener_norm[key],
                        args.dry_run,
                    )
                else:
                    log(f"[WARN] Skipping create of listener {key} due to unresolved cert/action mapping.")

        tgt_listeners = describe_listeners(tgt_elbv2, tgt_lb["LoadBalancerArn"])

        for src_listener in src_listeners:
            key = listener_key(src_listener)
            target_listener = find_target_listener_by_port_protocol(
                tgt_listeners,
                src_listener.get("Protocol"),
                src_listener.get("Port"),
            )

            if not target_listener:
                continue

            if not src_listener_unresolved[key]:
                tgt_norm_listener, _ = normalize_listener(
                    target_listener,
                    {},
                    tgt_tg_name_to_arn,
                    {},
                    target_domain_to_cert,
                )
                if json_key(tgt_norm_listener) != json_key(src_listener_norm[key]):
                    modify_listener(
                        tgt_elbv2,
                        target_listener["ListenerArn"],
                        src_listener_norm[key],
                        args.dry_run,
                    )

            source_rules = src_rules_norm[key]
            target_rules_raw = non_default_rules(describe_rules(tgt_elbv2, target_listener["ListenerArn"]))

            target_rules_norm_by_priority: Dict[str, Tuple[Dict[str, Any], str]] = {}
            for tr in target_rules_raw:
                nr, _ = normalize_rule(tr, {}, tgt_tg_name_to_arn)
                target_rules_norm_by_priority[str(tr["Priority"])] = (nr, tr["RuleArn"])

            source_rules_by_priority = {str(r["Priority"]): r for r in source_rules}

            for prio, src_rule_norm in source_rules_by_priority.items():
                if src_rules_unresolved[key]:
                    break

                if prio not in target_rules_norm_by_priority:
                    create_rule(
                        tgt_elbv2,
                        target_listener["ListenerArn"],
                        src_rule_norm,
                        args.dry_run,
                    )
                else:
                    tgt_rule_norm, tgt_rule_arn = target_rules_norm_by_priority[prio]
                    if json_key(tgt_rule_norm) != json_key(src_rule_norm):
                        modify_rule(
                            tgt_elbv2,
                            tgt_rule_arn,
                            src_rule_norm,
                            args.dry_run,
                        )

            for prio, (_, tgt_rule_arn) in target_rules_norm_by_priority.items():
                if prio not in source_rules_by_priority:
                    delete_rule(tgt_elbv2, tgt_rule_arn, args.dry_run)

    tgt_listeners = describe_listeners(tgt_elbv2, tgt_lb["LoadBalancerArn"])
    audit_results: List[ListenerAuditResult] = []

    for src_listener in src_listeners:
        key = listener_key(src_listener)
        audit = ListenerAuditResult(listener_key=key)

        target_listener = find_target_listener_by_port_protocol(
            tgt_listeners,
            src_listener.get("Protocol"),
            src_listener.get("Port"),
        )

        if not target_listener:
            audit.exists_in_target = False
            audit.listener_match = False
            audit.rules_match = False
            audit.notes.append("Target listener missing.")
            audit_results.append(audit)
            continue

        audit.exists_in_target = True

        tgt_norm_listener, _ = normalize_listener(
            target_listener,
            {},
            tgt_tg_name_to_arn,
            {},
            target_domain_to_cert,
        )

        if json_key(tgt_norm_listener) != json_key(src_listener_norm[key]):
            audit.listener_match = False
            audit.notes.append("Listener drift detected.")

        src_rules = src_rules_norm[key]
        tgt_rules_raw = non_default_rules(describe_rules(tgt_elbv2, target_listener["ListenerArn"]))
        tgt_rules = []
        for tr in tgt_rules_raw:
            nr, _ = normalize_rule(tr, {}, tgt_tg_name_to_arn)
            tgt_rules.append(nr)

        src_rule_map = {json_key(r): r for r in src_rules}
        tgt_rule_map = {json_key(r): r for r in tgt_rules}

        missing = [v for k, v in src_rule_map.items() if k not in tgt_rule_map]
        extra = [v for k, v in tgt_rule_map.items() if k not in src_rule_map]

        if missing or extra:
            audit.rules_match = False
            audit.missing_rules = missing
            audit.extra_rules = extra
            audit.notes.append("Listener rule drift detected.")

        if src_listener_unresolved[key]:
            audit.listener_match = False
            audit.notes.append("Unresolved listener dependency mapping:")
            audit.notes.extend(src_listener_unresolved[key])

        if src_rules_unresolved[key]:
            audit.rules_match = False
            audit.notes.append("Unresolved rule dependency mapping:")
            audit.notes.extend(src_rules_unresolved[key])

        audit_results.append(audit)

    print_audit_report(audit_results)
    write_audit_report_json(audit_results)

    log("[DONE] ALB listener / rule sync complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())