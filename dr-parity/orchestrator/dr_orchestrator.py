#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------
# logging
# ---------------------------------------------------------

def log(msg: str) -> None:
    print(msg, flush=True)


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------
# dataclasses
# ---------------------------------------------------------

@dataclass
class PhaseResult:
    phase: str
    enabled: bool
    attempted: bool
    status: str
    command: List[str]
    exit_code: Optional[int]
    stdout: str
    stderr: str
    started_at: Optional[str]
    finished_at: Optional[str]
    notes: List[str]


@dataclass
class OrchestratorReport:
    overall_status: str
    started_at: str
    finished_at: str
    mode: str
    selected_phase: Optional[str]
    config_file: str
    phase_results: List[PhaseResult]


# ---------------------------------------------------------
# config loading
# ---------------------------------------------------------

def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------
# subprocess runner
# ---------------------------------------------------------

def run_command(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# ---------------------------------------------------------
# command builders
# ---------------------------------------------------------

def build_sg_command(
    python_exe: str,
    script_path: str,
    cfg: Dict[str, Any],
    mode: str,
) -> List[str]:
    global_cfg = cfg["global"]
    network_cfg = cfg["network"]

    cmd = [
        python_exe,
        script_path,
        "--source-profile", global_cfg["source_profile"],
        "--source-region", global_cfg["source_region"],
        "--source-vpc-id", network_cfg["source_vpc_id"],
        "--target-profile", global_cfg["target_profile"],
        "--target-region", global_cfg["target_region"],
        "--target-vpc-id", network_cfg["target_vpc_id"],
    ]

    if mode == "dry-run":
        cmd.append("--dry-run")
    elif mode == "report-only":
        cmd.append("--report-only")

    return cmd


def build_tg_command(
    python_exe: str,
    script_path: str,
    cfg: Dict[str, Any],
    mode: str,
) -> List[str]:
    global_cfg = cfg["global"]
    network_cfg = cfg["network"]

    cmd = [
        python_exe,
        script_path,
        "--source-profile", global_cfg["source_profile"],
        "--source-region", global_cfg["source_region"],
        "--source-vpc-id", network_cfg["source_vpc_id"],
        "--target-profile", global_cfg["target_profile"],
        "--target-region", global_cfg["target_region"],
        "--target-vpc-id", network_cfg["target_vpc_id"],
    ]

    if mode == "dry-run":
        cmd.append("--dry-run")
    elif mode == "report-only":
        cmd.append("--report-only")

    return cmd


def build_alb_command(
    python_exe: str,
    script_path: str,
    cfg: Dict[str, Any],
    mode: str,
) -> List[str]:
    global_cfg = cfg["global"]
    alb_cfg = cfg["phases"]["albs"]

    cmd = [
        python_exe,
        script_path,
        "--source-profile", global_cfg["source_profile"],
        "--source-region", global_cfg["source_region"],
        "--target-profile", global_cfg["target_profile"],
        "--target-region", global_cfg["target_region"],
        "--alb-map-file", alb_cfg["alb_map_file"],
    ]

    if mode == "dry-run":
        cmd.append("--dry-run")
    elif mode == "report-only":
        cmd.append("--report-only")

    if "wait_timeout_seconds" in global_cfg:
        cmd.extend(["--wait-timeout-seconds", str(global_cfg["wait_timeout_seconds"])])
    if "wait_interval_seconds" in global_cfg:
        cmd.extend(["--wait-interval-seconds", str(global_cfg["wait_interval_seconds"])])

    return cmd


# ---------------------------------------------------------
# phase orchestration
# ---------------------------------------------------------

def run_phase(
    phase_name: str,
    enabled: bool,
    command: List[str],
) -> PhaseResult:
    if not enabled:
        return PhaseResult(
            phase=phase_name,
            enabled=False,
            attempted=False,
            status="skipped",
            command=command,
            exit_code=None,
            stdout="",
            stderr="",
            started_at=None,
            finished_at=None,
            notes=["Phase disabled in config."]
        )

    started = iso_now()
    log(f"[INFO] Starting phase: {phase_name}")
    log(f"[INFO] Command: {' '.join(command)}")

    proc = run_command(command)

    finished = iso_now()
    status = "success" if proc.returncode == 0 else "failed"

    return PhaseResult(
        phase=phase_name,
        enabled=True,
        attempted=True,
        status=status,
        command=command,
        exit_code=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
        started_at=started,
        finished_at=finished,
        notes=[]
    )


def select_phases(cfg: Dict[str, Any], selected_phase: Optional[str]) -> List[str]:
    ordered = ["sgs", "target_groups", "albs"]
    if selected_phase:
        if selected_phase not in ordered:
            raise ValueError(f"Unsupported phase: {selected_phase}")
        return [selected_phase]
    return ordered


# ---------------------------------------------------------
# report writing
# ---------------------------------------------------------

def write_report(report: OrchestratorReport, path: str) -> None:
    payload = asdict(report)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


# ---------------------------------------------------------
# args
# ---------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Enterprise DR parity orchestrator")

    p.add_argument("--config", required=True, help="Path to dr_config.json")

    mode_group = p.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--dry-run", action="store_true")
    mode_group.add_argument("--apply", action="store_true")
    mode_group.add_argument("--report-only", action="store_true")

    p.add_argument(
        "--phase",
        choices=["sgs", "target_groups", "albs"],
        help="Run only one phase"
    )

    p.add_argument(
        "--python-exe",
        default=sys.executable,
        help="Python interpreter to use for child scripts"
    )

    return p.parse_args()


# ---------------------------------------------------------
# main
# ---------------------------------------------------------

def main() -> int:
    args = parse_args()
    cfg = load_json(args.config)

    if args.dry_run:
        mode = "dry-run"
    elif args.apply:
        mode = "apply"
    else:
        mode = "report-only"

    reports_cfg = cfg["reports"]
    output_dir = reports_cfg["output_dir"]
    ensure_dir(output_dir)
    orchestrator_report_path = os.path.join(output_dir, reports_cfg["orchestrator_report_file"])

    fail_fast = cfg["global"].get("fail_fast", True)

    started = iso_now()
    phase_results: List[PhaseResult] = []

    phases_to_run = select_phases(cfg, args.phase)

    phase_builders = {
        "sgs": lambda: build_sg_command(
            args.python_exe,
            cfg["phases"]["sgs"]["script_path"],
            cfg,
            mode,
        ),
        "target_groups": lambda: build_tg_command(
            args.python_exe,
            cfg["phases"]["target_groups"]["script_path"],
            cfg,
            mode,
        ),
        "albs": lambda: build_alb_command(
            args.python_exe,
            cfg["phases"]["albs"]["script_path"],
            cfg,
            mode,
        ),
    }

    for phase_name in phases_to_run:
        phase_cfg = cfg["phases"][phase_name]
        enabled = phase_cfg.get("enabled", False)

        command = phase_builders[phase_name]()
        result = run_phase(phase_name, enabled, command)
        phase_results.append(result)

        if result.stdout:
            log(f"[{phase_name}] STDOUT:\n{result.stdout}")
        if result.stderr:
            eprint(f"[{phase_name}] STDERR:\n{result.stderr}")

        if result.status == "failed" and fail_fast:
            eprint(f"[ERROR] Phase failed and fail_fast is enabled: {phase_name}")
            break

    # determine overall status
    attempted = [r for r in phase_results if r.attempted]
    failed = [r for r in attempted if r.status == "failed"]

    if failed:
        overall_status = "failed"
    elif attempted:
        overall_status = "success"
    else:
        overall_status = "skipped"

    finished = iso_now()

    report = OrchestratorReport(
        overall_status=overall_status,
        started_at=started,
        finished_at=finished,
        mode=mode,
        selected_phase=args.phase,
        config_file=args.config,
        phase_results=phase_results,
    )

    write_report(report, orchestrator_report_path)

    log("\n" + "=" * 80)
    log("FINAL DR ORCHESTRATOR REPORT")
    log("=" * 80)
    log(f"Overall status : {overall_status}")
    log(f"Mode           : {mode}")
    log(f"Config         : {args.config}")
    log(f"Report         : {orchestrator_report_path}")

    for r in phase_results:
        log(f"- {r.phase}: {r.status}")

    log("=" * 80)

    return 0 if overall_status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())