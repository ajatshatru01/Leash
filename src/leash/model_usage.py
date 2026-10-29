from __future__ import annotations

from typing import Literal

from leash.contracts import ModelUsage


def estimate_tokens(value: str) -> int:
    """Return a deterministic conservative-enough estimate for recorded/offline runs."""
    if not value:
        return 0
    return max(1, (len(value.encode("utf-8")) + 3) // 4)


def estimated_cost(
    *,
    prompt_tokens: int,
    completion_tokens: int,
    input_cost_per_million_usd: float | None,
    output_cost_per_million_usd: float | None,
) -> float | None:
    if input_cost_per_million_usd is None or output_cost_per_million_usd is None:
        return None
    return round(
        (prompt_tokens * input_cost_per_million_usd / 1_000_000)
        + (completion_tokens * output_cost_per_million_usd / 1_000_000),
        8,
    )


def model_usage(
    *,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    source: Literal["reported", "estimated", "recorded"],
    input_cost_per_million_usd: float | None,
    output_cost_per_million_usd: float | None,
) -> ModelUsage:
    return ModelUsage(
        provider=provider,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
        source=source,
        estimated_cost_usd=estimated_cost(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            input_cost_per_million_usd=input_cost_per_million_usd,
            output_cost_per_million_usd=output_cost_per_million_usd,
        ),
    )
