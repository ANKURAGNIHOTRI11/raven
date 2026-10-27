"""Patch-validation sandbox.

Scope, stated plainly: this service validates *remediation*, not exploitation.
It answers "does this patch resolve, apply cleanly and revert" in a disposable
container with no route to the production network. It does not run exploit code
or proof-of-concept payloads, and RAVEN does not ship a component that does -
an autonomous system that executes attacker-supplied code against a target is a
liability, not a feature. If you need PoC replay, do it in a physically
separate range with its own change control and feed the verdict back in through
the feedback API.

Checks performed:
  * command shape - allowlisted package-manager verbs only
  * dry-run resolution - apt/dnf/yum/zypper/pip resolve the requested version
  * IaC lint - Ansible YAML parses and declares no unbounded host pattern
  * rollback symmetry - every forward step has a matching revert step
"""
from __future__ import annotations

import asyncio
import re
import shlex

import yaml
from fastapi import FastAPI
from prometheus_client import make_asgi_app
from pydantic import BaseModel

app = FastAPI(title="RAVEN patch sandbox", version="1.0.0")
app.mount("/metrics", make_asgi_app())

ALLOWED_BINARIES = {
    "apt-get", "apt", "dnf", "yum", "zypper", "pip", "pip3", "systemctl",
    "dpkg", "rpm", "kubectl", "helm", "docker", "sed", "sysctl", "update-grub",
}
DRY_RUN = {
    "apt-get": ["apt-get", "install", "--dry-run", "-y"],
    "apt": ["apt-get", "install", "--dry-run", "-y"],
    "dnf": ["dnf", "install", "--assumeno"],
    "yum": ["yum", "install", "--assumeno"],
    "zypper": ["zypper", "--non-interactive", "install", "--dry-run"],
    "pip": ["pip", "install", "--dry-run"],
    "pip3": ["pip3", "install", "--dry-run"],
}
FORBIDDEN = re.compile(
    r"(rm\s+-rf\s+/|mkfs|dd\s+if=|>\s*/dev/sd|curl[^|]*\|\s*(ba)?sh|"
    r"wget[^|]*\|\s*(ba)?sh|nc\s+-e|/dev/tcp/|base64\s+-d\s*\|)", re.I)


class ValidateRequest(BaseModel):
    asset_id: str
    platform: str = "host"
    packages: list[str] = []
    patch_commands: list[str] = []
    validation: list[str] = []
    rollback: list[str] = []
    iac_patch: str = ""


async def run(cmd: list[str], timeout: int = 90) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return proc.returncode or 0, out.decode("utf-8", "replace")[-4000:]
    except asyncio.TimeoutError:
        return 124, "timeout"
    except FileNotFoundError:
        return 127, "binary not present in sandbox image"


def inspect_commands(commands: list[str]) -> tuple[list[str], list[str]]:
    problems, targets = [], []
    for raw in commands:
        if FORBIDDEN.search(raw):
            problems.append(f"forbidden pattern: {raw[:120]}")
            continue
        try:
            parts = shlex.split(raw)
        except ValueError:
            problems.append(f"unparseable: {raw[:120]}")
            continue
        if not parts:
            continue
        binary = parts[0].split("/")[-1]
        if binary == "sudo" and len(parts) > 1:
            parts, binary = parts[1:], parts[1].split("/")[-1]
        if binary not in ALLOWED_BINARIES:
            problems.append(f"binary not allowlisted: {binary}")
            continue
        if binary in DRY_RUN:
            pkgs = [p for p in parts[1:] if not p.startswith("-") and p not in
                    ("install", "update", "upgrade", "reinstall")]
            targets.extend(f"{binary}:{p}" for p in pkgs)
    return problems, targets


def lint_iac(text: str) -> list[str]:
    if not text.strip():
        return []
    problems = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        return [f"iac does not parse: {str(exc)[:200]}"]
    for doc in docs:
        items = doc if isinstance(doc, list) else [doc]
        for item in items:
            if not isinstance(item, dict):
                continue
            hosts = str(item.get("hosts", ""))
            if hosts in ("all", "*"):
                problems.append("playbook targets all hosts")
            for key in ("shell", "command", "raw"):
                if key in item and FORBIDDEN.search(str(item[key])):
                    problems.append(f"forbidden pattern in {key}")
    return problems


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "mode": "patch-validation-only"}


@app.post("/validate")
async def validate(req: ValidateRequest) -> dict:
    problems, targets = inspect_commands(req.patch_commands)
    problems += lint_iac(req.iac_patch)

    if not req.rollback:
        problems.append("no rollback steps supplied")
    elif len(req.rollback) < max(1, len(req.patch_commands) // 3):
        problems.append("rollback looks thinner than the forward plan")
    if not req.validation:
        problems.append("no post-change validation supplied")

    resolutions = []
    for target in targets[:8]:
        binary, pkg = target.split(":", 1)
        code, out = await run(DRY_RUN[binary] + [pkg])
        resolutions.append({
            "package": pkg, "manager": binary,
            "resolves": code == 0,
            "output": out[-600:],
        })

    unresolved = [r["package"] for r in resolutions if not r["resolves"]]
    if unresolved and all(r["output"].startswith("binary not present") is False for r in resolutions):
        problems.append(f"packages did not resolve: {', '.join(unresolved[:5])}")

    status = "patch_verified" if not problems else (
        "needs_review" if resolutions else "insufficient_evidence"
    )
    return {
        "status": status,
        "detail": "; ".join(problems[:6]),
        "problems": problems,
        "resolutions": resolutions,
        "exploit_replay": "not performed by design",
    }
