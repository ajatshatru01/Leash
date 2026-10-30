import subprocess
import sys
from pathlib import Path


def test_dashboard_response_types_match_fastapi_openapi() -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate_api_types.py"
    result = subprocess.run(
        [sys.executable, str(script), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
