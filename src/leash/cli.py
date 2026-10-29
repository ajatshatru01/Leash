from __future__ import annotations

import asyncio
from pathlib import Path
from uuid import uuid4

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
        reload_dirs=["src/leash"] if settings.leash_env == "development" else None,
        log_level=settings.leash_log_level.lower(),
    )


@app.command("config-status")
def config_status() -> None:
    """Print configuration presence without exposing secrets."""
    settings = get_settings()
    typer.echo(f"environment={settings.leash_env}")
    typer.echo(f"actor_mode={settings.leash_actor_mode}")
    typer.echo(f"judge_mode={settings.leash_judge_mode}")
    typer.echo(f"executor_mode={settings.leash_executor_mode}")
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


@app.command("check-executor")
def check_executor() -> None:
    """Run one harmless proposal through the Docker-backed Leash pipeline."""
    from leash.api import build_services
    from leash.contracts import ActionKind, ShellActionProposal, ShellParams

    async def run_check() -> None:
        settings = get_settings().model_copy(
            update={"leash_executor_mode": "docker", "leash_judge_mode": "recorded"}
        )
        settings.leash_workspace_root.mkdir(parents=True, exist_ok=True)
        services = build_services(settings)
        await services.audit.initialize()
        proposal = ShellActionProposal(
            kind=ActionKind.SHELL,
            session_id=uuid4(),
            task_id=uuid4(),
            task_text="Verify the isolated Python runtime version.",
            workspace_id="executor-check",
            params=ShellParams(executable="python", argv=("--version",)),
        )
        result = await services.orchestrator.evaluate(proposal)
        if result.execution is None or result.execution.executor != "docker_shell":
            raise RuntimeError("Docker executor did not return a real execution result")
        if result.execution.exit_code != 0:
            raise RuntimeError("Docker executor returned a non-zero exit code")
        typer.echo(
            "executor_check=passed executor=docker_shell "
            f"exit_code={result.execution.exit_code} network=none workspace=readonly"
        )

    try:
        asyncio.run(run_check())
    except Exception as exc:
        typer.echo(
            f"executor_check=failed error_type={type(exc).__name__}",
            err=True,
        )
        raise typer.Exit(code=1) from None


@app.command("capture-receiver")
def capture_receiver() -> None:
    """Run the inert loopback receiver used by the exfiltration demo."""
    settings = get_settings()
    uvicorn.run(
        "leash.capture:app",
        host=settings.leash_capture_host,
        port=settings.leash_capture_port,
        reload=False,
        log_level=settings.leash_log_level.lower(),
    )


if __name__ == "__main__":
    app()
