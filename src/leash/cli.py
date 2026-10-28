from __future__ import annotations

import asyncio
from pathlib import Path

import typer
import uvicorn

from leash.provider_check import check_meta_models
from leash.secret_audit import audit_exact_secret
from leash.settings import get_settings

app = typer.Typer(help="Leash safety gateway")


@app.command()
def serve() -> None:
    """Run the local Leash API."""
    settings = get_settings()
    uvicorn.run(
        "leash.api:app",
        host=settings.leash_host,
        port=settings.leash_port,
        reload=settings.leash_env == "development",
        log_level=settings.leash_log_level.lower(),
    )


@app.command("config-status")
def config_status() -> None:
    """Print configuration presence without exposing secrets."""
    settings = get_settings()
    typer.echo(f"environment={settings.leash_env}")
    typer.echo(f"judge_mode={settings.leash_judge_mode}")
    typer.echo(f"model_api_key_configured={settings.model_api_key_configured}")
    typer.echo(f"spark_model={settings.spark_model}")
    typer.echo(f"judge_model={settings.judge_model}")


@app.command("check-models")
def check_models() -> None:
    """Verify Spark and Wonder access without printing prompts, responses, or keys."""
    settings = get_settings()
    if not settings.model_api_key_configured:
        typer.echo("model_check=failed reason=MODEL_API_KEY_not_configured", err=True)
        raise typer.Exit(code=1)
    try:
        results = asyncio.run(check_meta_models(settings))
    except Exception as exc:
        status_code = getattr(exc, "status_code", "unavailable")
        typer.echo(
            f"model_check=failed error_type={type(exc).__name__} status={status_code}",
            err=True,
        )
        raise typer.Exit(code=1) from None
    for result in results:
        typer.echo(
            f"role={result.role} model={result.model} status=ok "
            f"latency_ms={result.latency_ms} detail={result.detail}"
        )


@app.command("secret-audit")
def secret_audit() -> None:
    """Check that the configured API key appears only in ignored secret files."""
    settings = get_settings()
    if settings.model_api_key is None or not settings.model_api_key_configured:
        typer.echo("secret_audit=failed reason=MODEL_API_KEY_not_configured", err=True)
        raise typer.Exit(code=1)
    result = audit_exact_secret(Path.cwd(), settings.model_api_key.get_secret_value())
    if result.leak_paths:
        typer.echo(
            f"secret_audit=failed leak_count={len(result.leak_paths)}",
            err=True,
        )
        for path in result.leak_paths:
            typer.echo(f"leak_path={path}", err=True)
        raise typer.Exit(code=1)
    typer.echo(
        f"secret_audit=passed scanned_files={result.scanned_files} "
        f"skipped_files={result.skipped_files}"
    )


if __name__ == "__main__":
    app()
