"""Transformer-backed enrichment: a BERT classifier for exploit-maturity
language and a lightweight NER pass for vendor/product extraction.

Both run on the H200 when CUDA is visible and fall back to CPU heuristics when
the models are absent, so the pipeline never hard-depends on a download.
"""
from __future__ import annotations

import re

import structlog

log = structlog.get_logger()

WEAPONIZED = re.compile(r"\b(actively exploited|exploited in the wild|ransomware|mass exploitation)\b", re.I)
FUNCTIONAL = re.compile(r"\b(working exploit|metasploit|exploit is available|weaponi[sz]ed)\b", re.I)
POC = re.compile(r"\b(proof[- ]of[- ]concept|poc (code|available)|exploit code published)\b", re.I)

CPE_RE = re.compile(r"cpe:2\.3:[aho]:([^:]+):([^:]+):([^:]*)", re.I)
PRODUCT_HINT = re.compile(
    r"\b(apache|nginx|openssl|linux kernel|kubernetes|docker|postgresql|mysql|"
    r"mariadb|slurm|openstack|nvidia|cuda|lustre|infiniband|mellanox|redis|"
    r"grafana|prometheus|jenkins|log4j|spring|struts|windows|vmware|citrix|"
    r"fortios|fortinet|cisco ios|ganglia|nagios|singularity|apptainer)\b", re.I)


class Enricher:
    def __init__(self, model_name: str, device_preference: str = "auto") -> None:
        self.pipe = None
        self.ner = None
        self.model_name = model_name
        try:
            import torch
            from transformers import pipeline

            device = 0 if (device_preference != "cpu" and torch.cuda.is_available()) else -1
            self.pipe = pipeline(
                "zero-shot-classification",
                model="MoritzLaurer/deberta-v3-base-zeroshot-v2.0",
                device=device,
            )
            self.ner = pipeline(
                "token-classification",
                model="dslim/bert-base-NER",
                aggregation_strategy="simple",
                device=device,
            )
            log.info("enricher_ready", device="cuda" if device == 0 else "cpu")
        except Exception as exc:
            log.warning("enricher_degraded", error=str(exc)[:200])

    def exploit_maturity(self, text: str) -> tuple[str, float]:
        if WEAPONIZED.search(text):
            return "weaponized", 0.95
        if FUNCTIONAL.search(text):
            return "functional", 0.85
        if POC.search(text):
            return "poc", 0.75
        if self.pipe is None or not text.strip():
            return "none", 0.5
        try:
            labels = [
                "exploit is actively used in attacks",
                "proof of concept exploit exists",
                "no known exploit",
            ]
            res = self.pipe(text[:1500], candidate_labels=labels, multi_label=False)
            top, score = res["labels"][0], float(res["scores"][0])
            mapping = {
                labels[0]: "weaponized",
                labels[1]: "poc",
                labels[2]: "none",
            }
            return mapping[top], score
        except Exception:
            return "none", 0.5

    def products(self, text: str, cpe_uris: list[str]) -> list[str]:
        found = {m.group(1).lower().replace("_", " ") for m in CPE_RE.finditer(" ".join(cpe_uris))}
        found |= {m.group(0).lower() for m in PRODUCT_HINT.finditer(text or "")}
        if self.ner is not None and text:
            try:
                for ent in self.ner(text[:1200]):
                    if ent.get("entity_group") == "ORG" and len(ent.get("word", "")) > 2:
                        found.add(ent["word"].lower())
            except Exception:
                pass
        return sorted(found)[:40]
