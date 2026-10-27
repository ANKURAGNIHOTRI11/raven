#!/usr/bin/env python3
"""Upload a safe snapshot of a local folder to a NEW private GitHub repository.

Usage: python3 upload_raven_to_github.py /path/to/project

Uses GitHub CLI browser/device authentication. It never asks for or stores your
GitHub account password or token. The source folder is not modified.
"""
from __future__ import annotations
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", ".cache", ".next", ".turbo", "site-packages", ".idea",
}
SKIP_CREDENTIAL_DIRS = {".ssh", ".aws", ".azure", ".kube"}
SKIP_EXACT_FILES = {
    "project_bundle.txt",
    ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_ed25519", "id_ecdsa",
    "id_dsa", "known_hosts", "credentials", "credentials.json",
    "credentials.yml", "credentials.yaml", "secrets.json", "secrets.yml",
    "secrets.yaml", "secret.json", "secret.yml", "secret.yaml",
    "service-account.json", "service_account.json", ".ds_store",
}
SKIP_SUFFIXES = {
    ".pyc", ".pyo", ".log", ".pem", ".key", ".p12", ".pfx", ".p7b",
    ".p7c", ".jks", ".keystore", ".tfstate", ".sqlite", ".sqlite3",
    ".db", ".dump",
}
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_SCAN_BYTES = 5 * 1024 * 1024
SECRET_PATTERNS = [
    ("private-key block", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b")),
    ("AWS access key ID", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("Google API key", re.compile(rb"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI-style API key", re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}\b")),
    ("credential-bearing database URL", re.compile(rb"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^/\s:@]+:[^@\s]+@")),
]
GITIGNORE_BLOCK = """

# Safe local-only exclusions added by upload_raven_to_github.py
.env
.env.*
!.env.example
!.env.template
**/.netrc
**/.npmrc
**/.pypirc
**/.ssh/**
**/.aws/**
**/.azure/**
**/.kube/**
**/id_rsa
**/id_ed25519
**/id_ecdsa
**/id_dsa
**/*.pem
**/*.key
**/*.p12
**/*.pfx
**/*.jks
**/*.keystore
**/*.tfstate
**/*.sqlite
**/*.sqlite3
**/*.db
**/*.dump
**/*.log
**/__pycache__/**
**/.pytest_cache/**
**/.venv/**
**/venv/**
**/node_modules/**
**/raven_redhat_*_before.json
**/raven_redhat_*_publish.jsonl
""".lstrip()
MARKER = "# Safe local-only exclusions added by upload_raven_to_github.py"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True,
        capture: bool = False) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, text=True, check=False,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
        )
    except FileNotFoundError:
        fail(f"Required command not found: {cmd[0]}")
    if check and result.returncode != 0:
        if capture:
            if result.stdout:
                print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
        fail(f"Command failed (exit {result.returncode}): {' '.join(cmd[:4])}")
    return result


def excluded_reason(name: str) -> str | None:
    low = name.lower()
    if low in SKIP_EXACT_FILES:
        return "credential/local account file"
    if low == ".env" or (low.startswith(".env.") and low not in {".env.example", ".env.template"}):
        return "environment file"
    if low.endswith(tuple(SKIP_SUFFIXES)):
        return "private-key/runtime/database artifact extension"
    if low.startswith("raven_redhat_") and low.endswith("_before.json"):
        return "local database snapshot"
    if low.startswith("raven_redhat_") and low.endswith("_publish.jsonl"):
        return "local operations log"
    if low.startswith("service-account") and low.endswith(".json"):
        return "service-account credentials"
    if low.startswith(("credentials.", "secret.", "secrets.")) and not low.endswith((".example", ".template", ".sample")):
        return "likely credentials/secrets file"
    return None


def copy_safe_tree(source: Path, destination: Path) -> tuple[list[str], list[str]]:
    copied: list[str] = []
    excluded: list[str] = []
    for root, dirs, files in os.walk(source, topdown=True, followlinks=False):
        current = Path(root)
        rel_dir = current.relative_to(source)
        kept = []
        for name in dirs:
            path = current / name
            rel = (rel_dir / name).as_posix()
            if path.is_symlink():
                excluded.append(f"{rel} (symbolic link)")
            elif name in SKIP_DIRS:
                excluded.append(f"{rel} (environment/cache/IDE state)")
            elif name in SKIP_CREDENTIAL_DIRS:
                excluded.append(f"{rel} (credential directory)")
            else:
                kept.append(name)
        dirs[:] = kept
        target_dir = destination / rel_dir
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            src = current / name
            rel = (rel_dir / name).as_posix()
            if src.is_symlink():
                excluded.append(f"{rel} (symbolic link)")
                continue
            reason = excluded_reason(name)
            if reason:
                excluded.append(f"{rel} ({reason})")
                continue
            size = src.stat().st_size
            if size > MAX_FILE_BYTES:
                fail(f"File exceeds GitHub's 100 MiB limit: {rel} ({size} bytes). Use Git LFS or exclude it, then retry.")
            dest = target_dir / name
            shutil.copy2(src, dest)
            copied.append(rel)
    return copied, excluded


def scan_for_secrets(stage: Path, files: list[str]) -> list[tuple[str, str]]:
    findings = []
    for rel in files:
        path = stage / rel
        try:
            if path.stat().st_size > MAX_SCAN_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in data[:8192]:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(data):
                findings.append((rel, label))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="Upload a safe project snapshot to a new private GitHub repository.")
    parser.add_argument("project_dir", nargs="?", default=".", help="Folder to upload; defaults to current directory")
    args = parser.parse_args()
    source = Path(args.project_dir).expanduser().resolve()
    if not source.is_dir():
        fail(f"Project folder is not a directory: {source}")
    if shutil.which("git") is None or shutil.which("gh") is None:
        fail("Both git and GitHub CLI ('gh') must be installed first. This script won't install packages automatically.")

    print("Folder to upload:", source)
    print("Authentication: GitHub CLI browser/device flow; this script will never ask for your password.")
    status = run(["gh", "auth", "status", "--hostname", "github.com"], check=False)
    if status.returncode != 0:
        print("Starting GitHub sign-in. Follow the browser/device-code prompts.")
        run(["gh", "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web"])
        run(["gh", "auth", "status", "--hostname", "github.com"])
    run(["gh", "auth", "setup-git", "--hostname", "github.com"])
    login = run(["gh", "api", "user", "--jq", ".login"], capture=True).stdout.strip()
    if not login:
        fail("Could not determine the authenticated GitHub username.")

    owner = input(f"GitHub username/owner [{login}]: ").strip() or login
    if owner.casefold() != login.casefold():
        fail(f"You are authenticated as '{login}', not '{owner}'. Authenticate as the account that should own this repository and retry.")
    default_name = re.sub(r"[^A-Za-z0-9._-]+", "-", source.name).strip(".-") or "project-upload"
    repo_name = input(f"New repository name [{default_name}]: ").strip() or default_name
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", repo_name) or repo_name in {".", ".."}:
        fail("Invalid repository name.")
    repo = f"{owner}/{repo_name}"
    exists = run(["gh", "repo", "view", repo, "--json", "url"], check=False, capture=True)
    if exists.returncode == 0:
        fail(f"Repository {repo} already exists or is accessible. This script will not overwrite it.")

    visibility = input("Repository visibility [private/public, default private]: ").strip().lower() or "private"
    if visibility not in {"private", "public"}:
        fail("Visibility must be 'private' or 'public'.")
    if visibility == "public" and input("This makes the code public. Type MAKE PUBLIC to confirm: ").strip() != "MAKE PUBLIC":
        print("Cancelled. No repository created.")
        return

    with tempfile.TemporaryDirectory(prefix="github-upload-stage-") as temp:
        stage = Path(temp) / "repo"
        stage.mkdir()
        copied, excluded = copy_safe_tree(source, stage)
        ignore = stage / ".gitignore"
        existing_ignore = ignore.read_text(encoding="utf-8", errors="replace") if ignore.exists() else ""
        if MARKER not in existing_ignore:
            with ignore.open("a", encoding="utf-8") as f:
                if existing_ignore and not existing_ignore.endswith("\n"):
                    f.write("\n")
                f.write("\n" + GITIGNORE_BLOCK)
            if ".gitignore" not in copied:
                copied.append(".gitignore")

        if not copied:
            fail("No files eligible for upload were found.")
        findings = scan_for_secrets(stage, copied)
        if findings:
            print("Potential secrets detected; nothing uploaded. Files and pattern types only:")
            for rel, label in findings:
                print(f"  {rel}: {label}")
            fail("Remove or replace the potential secret(s), then rerun. Secret values were not displayed.")

        print("\n========== UPLOAD PREVIEW ==========")
        print("Repository:", f"https://github.com/{repo}")
        print("Visibility:", visibility)
        print("Files to upload:", len(copied))
        print("Files/folders excluded:", len(excluded))
        if excluded:
            print("Excluded items (first 60):")
            for item in excluded[:60]:
                print("  -", item)
            if len(excluded) > 60:
                print(f"  ... plus {len(excluded) - 60} more")
        print("\nA clean snapshot will be uploaded; the source directory and its Git history remain untouched.")
        print("Credentials, environment files, private keys, cache/virtual environments, database artifacts, Raven before-state snapshots, and publication logs are excluded.")
        if input(f"Type UPLOAD to create the {visibility} repository and push files: ").strip() != "UPLOAD":
            print("Cancelled. Nothing uploaded and no remote repository created.")
            return

        run(["git", "init", "-b", "main"], cwd=stage)
        run(["git", "add", "-A"], cwd=stage)
        staged = run(["git", "diff", "--cached", "--name-only"], cwd=stage, capture=True).stdout.splitlines()
        if not staged:
            fail("No staged files were found.")
        if len(staged) > 10000:
            fail("More than 10,000 files staged; split the upload into smaller repositories or remove generated files.")
        email = run(["gh", "api", "user", "--jq", ".email // empty"], capture=True, check=False).stdout.strip()
        if not email:
            email = run(["git", "config", "--global", "user.email"], capture=True, check=False).stdout.strip()
        if not email:
            email = input("Commit author email (used in Git commit metadata): ").strip()
        if not email or "\n" in email:
            fail("A commit email is required.")
        run(["git", "config", "user.name", login], cwd=stage)
        run(["git", "config", "user.email", email], cwd=stage)
        run(["git", "commit", "-m", f"Initial upload of {source.name}"], cwd=stage)

        flags = ["--private"] if visibility == "private" else ["--public"]
        run(["gh", "repo", "create", repo, *flags, "--description", f"Uploaded project snapshot: {source.name}", "--source", str(stage), "--remote", "origin", "--push"])
        print("\nUPLOAD SUCCESSFUL")
        print("Repository:", f"https://github.com/{repo}")
        print("Files uploaded:", len(staged))
        print("Source folder was not modified.")

if __name__ == "__main__":
    main()

