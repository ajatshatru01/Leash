from pathlib import Path

from leash.secret_audit import audit_exact_secret


def test_secret_audit_detects_leak_but_ignores_env_storage(tmp_path: Path) -> None:
    secret = "fixture-secret-that-must-not-escape"
    (tmp_path / ".env").write_text(f"MODEL_API_KEY={secret}\n", encoding="utf-8")
    safe_file = tmp_path / "safe.txt"
    safe_file.write_text("no credentials here", encoding="utf-8")

    safe_result = audit_exact_secret(tmp_path, secret)
    assert safe_result.leak_paths == ()

    leaked_file = tmp_path / "debug.log"
    leaked_file.write_text(f"accidental={secret}\n", encoding="utf-8")
    leaked_result = audit_exact_secret(tmp_path, secret)

    assert leaked_result.leak_paths == (Path("debug.log"),)
