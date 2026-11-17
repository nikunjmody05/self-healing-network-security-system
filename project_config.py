"""
Central path configuration for the Self-Healing Network Security System.

All paths are resolved relative to this file's folder (the project root),
so the project runs from any clone location.

Every pipeline run writes ONLY inside ``runs/<RUN_ID>/``. Historical
top-level CSVs, databases, charts, the model and the Q-table are never
written by code that uses this module.
"""

from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# ------------------------------------------------------------------
# Inputs (read-only)
# ------------------------------------------------------------------

DATA_PATH = BASE_DIR / "data" / "cic-collection.parquet"
UNSW_DIR = BASE_DIR / "data" / "unsw"
MODEL_FILE = BASE_DIR / "models" / "rf_model.pkl"
Q_TABLE_FILE = BASE_DIR / "models" / "q_table.pkl"

DASHBOARD_TEMPLATE = BASE_DIR / "dashboard" / "soc_dashboard_template.html"

# Chart.js v4.4.1 (MIT), bundled for offline use.
# sha256 74401d738dd3e03ee5dfb3b6841210fe2c4ead8a960c4011ca4ba0b78a9fd8f3
CHART_JS = BASE_DIR / "dashboard" / "vendor" / "chart.umd.js"

# Google Fonts used by the original dashboard (SIL OFL), latin subset.
FONTS_DIR = BASE_DIR / "dashboard" / "vendor" / "fonts"

# ------------------------------------------------------------------
# Outputs (per run)
# ------------------------------------------------------------------

RUNS_DIR = BASE_DIR / "runs"


def new_run_id():
    return datetime.now().strftime("%Y%m%d-%H%M%S-%f")


def create_run_dir(run_id):
    """Create a fresh, empty folder for one run. Refuses to reuse one."""

    run_dir = RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def check_inputs():
    """Return a list of missing required input files (empty = OK)."""

    required = [DATA_PATH, MODEL_FILE, Q_TABLE_FILE]
    return [str(path) for path in required if not path.exists()]


def assert_inside(path, root):
    """Raise if ``path`` resolves outside ``root`` (write-safety guard)."""

    resolved = Path(path).resolve()
    root = Path(root).resolve()
    if resolved != root and root not in resolved.parents:
        raise PermissionError(
            f"Refusing to write outside {root}: {resolved}"
        )
    return resolved


if __name__ == "__main__":
    missing = check_inputs()
    print("Project root :", BASE_DIR)
    print("Dataset      :", DATA_PATH, DATA_PATH.exists())
    print("RF model     :", MODEL_FILE, MODEL_FILE.exists())
    print("Q-table      :", Q_TABLE_FILE, Q_TABLE_FILE.exists())
    print("Runs folder  :", RUNS_DIR)
    print("INPUTS OK" if not missing else f"MISSING: {missing}")
