import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in [
    ROOT / "libs" / "raven_common",
    ROOT / "services" / "crawler",
    ROOT / "services" / "risk_engine",
    ROOT / "services" / "agents",
    ROOT / "services" / "gnn_engine",
]:
    sys.path.insert(0, str(p))
