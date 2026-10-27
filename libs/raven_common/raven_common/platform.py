"""Classify a vulnerability by OS family, Linux distro and CPU architecture.

Signals in decreasing reliability: CPE fields, package ecosystem prefixes,
description text. Anything unsupported stays 'unknown' / 'any': most CVEs are
not architecture-specific and the data does not say, so we never guess.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# (vendor, product-substring) -> family
_CPE_FAMILY = [
    (("microsoft",), ("windows",), "windows"),
    (("apple",), ("macos", "mac_os", "iphone_os", "ipados", "tvos", "watchos", "ios"), "apple"),
    (("linux",), ("linux_kernel",), "linux"),
    (("google",), ("android",), "android"),
    (("freebsd", "openbsd", "netbsd"), ("",), "bsd"),
    (("debian", "canonical", "redhat", "suse", "opensuse", "alpinelinux",
      "fedoraproject", "centos", "almalinux", "rockylinux", "oracle", "amazon",
      "archlinux", "gentoo"), ("",), "linux"),
]
_DISTRO_VENDOR = {
    "debian": "debian", "canonical": "ubuntu", "redhat": "rhel", "suse": "suse",
    "opensuse": "suse", "alpinelinux": "alpine", "fedoraproject": "fedora",
    "centos": "centos", "almalinux": "alma", "rockylinux": "rocky",
    "amazon": "amazon", "archlinux": "arch", "gentoo": "gentoo", "oracle": "oracle",
}
_ECO_DISTRO = [
    ("debian", "debian"), ("ubuntu", "ubuntu"), ("alpine", "alpine"),
    ("red hat", "rhel"), ("rhel", "rhel"), ("suse", "suse"), ("rocky", "rocky"),
    ("almalinux", "alma"), ("amazon", "amazon"), ("fedora", "fedora"),
]
_HW = {
    "x64": "x86_64", "x86_64": "x86_64", "amd64": "x86_64", "x86": "x86",
    "arm64": "arm64", "aarch64": "arm64", "arm": "arm", "armv7": "arm",
    "ppc64": "ppc64", "ppc64le": "ppc64", "s390x": "s390x", "riscv64": "riscv64",
}
_TEXT_OS = [
    (re.compile(r"\bwindows\b", re.I), "windows"),
    (re.compile(r"\b(macos|mac os x|ios|ipados|iphone os|tvos|watchos|safari)\b", re.I), "apple"),
    (re.compile(r"\blinux kernel\b|\bin the linux\b|\bglibc\b", re.I), "linux"),
    (re.compile(r"\bandroid\b", re.I), "android"),
    (re.compile(r"\b(ubuntu|debian|red hat|rhel|alpine linux|suse)\b", re.I), "linux"),
]
_TEXT_HW = [
    (re.compile(r"\b(aarch64|arm64|armv8)\b", re.I), "arm64"),
    (re.compile(r"\b(x86[-_]64|amd64|x64)\b", re.I), "x86_64"),
    (re.compile(r"\b(spectre|meltdown|retbleed|inception|zenbleed|downfall|"
                r"speculative execution|intel me|amd sev|intel sgx|microcode)\b", re.I), "x86_64"),
]


@dataclass
class Platform:
    os_families: list[str] = field(default_factory=list)
    linux_distros: list[str] = field(default_factory=list)
    architectures: list[str] = field(default_factory=list)
    basis: str = "none"          # cpe | ecosystem | text | none
    confidence: float = 0.0


def _add(lst: list[str], v: str) -> None:
    if v and v not in lst:
        lst.append(v)


def classify(cpe_uris: list[str] | None, packages: list[str] | None,
             description: str | None) -> Platform:
    p = Platform()
    bases: set[str] = set()

    # 1. CPE 2.3: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:target_sw:target_hw
    for uri in cpe_uris or []:
        f = uri.split(":")
        if len(f) < 6:
            continue
        vendor, product = f[3].lower(), f[4].lower()
        for vendors, prods, fam in _CPE_FAMILY:
            if vendor in vendors and any(x in product for x in prods):
                _add(p.os_families, fam); bases.add("cpe")
                if fam == "linux" and vendor in _DISTRO_VENDOR:
                    _add(p.linux_distros, _DISTRO_VENDOR[vendor])
                break
        if len(f) > 10:
            tsw = f[10].lower()
            if tsw in ("linux", "windows", "android"):
                _add(p.os_families, tsw); bases.add("cpe")
            elif tsw in ("macos", "mac_os_x", "iphone_os"):
                _add(p.os_families, "apple"); bases.add("cpe")
        if len(f) > 11 and f[11] not in ("*", "-", ""):
            hw = _HW.get(f[11].lower())
            if hw:
                _add(p.architectures, hw); bases.add("cpe")

    # 2. package ecosystem prefixes (OSV/GHSA style "Ubuntu:22.04:LTS:openssl")
    for pkg in packages or []:
        head = pkg.lower().split(":", 1)[0]
        for key, distro in _ECO_DISTRO:
            if head.startswith(key):
                _add(p.os_families, "linux"); _add(p.linux_distros, distro)
                bases.add("ecosystem")

    # 3. description text: lowest confidence, only fills gaps
    text = description or ""
    if not p.os_families:
        for rx, fam in _TEXT_OS:
            if rx.search(text):
                _add(p.os_families, fam); bases.add("text")
    if not p.architectures:
        for rx, hw in _TEXT_HW:
            if rx.search(text):
                _add(p.architectures, hw); bases.add("text")

    for b in ("cpe", "ecosystem", "text"):
        if b in bases:
            p.basis = b
            p.confidence = {"cpe": 0.9, "ecosystem": 0.8, "text": 0.5}[b]
            break
    return p
