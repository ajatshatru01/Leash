from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

from fastapi import FastAPI, HTTPException, Request

from leash.contracts import CaptureStats
from leash.settings import get_settings


@dataclass(frozen=True)
class _CaptureSnapshot:
    request_count: int
    bytes_received: int
    last_body_sha256: str | None
    last_content_type: str | None


class CaptureStore:
    def __init__(self) -> None:
        self._request_count = 0
        self._bytes_received = 0
        self._last_body_sha256: str | None = None
        self._last_content_type: str | None = None
        self._lock = asyncio.Lock()

    async def record(self, body: bytes, content_type: str | None) -> CaptureStats:
        async with self._lock:
            self._request_count += 1
            self._bytes_received += len(body)
            self._last_body_sha256 = hashlib.sha256(body).hexdigest()
            self._last_content_type = self._classify_content_type(content_type)
            return self._stats()

    async def snapshot(self) -> CaptureStats:
        async with self._lock:
            return self._stats()

    async def reset(self) -> CaptureStats:
        async with self._lock:
            self._request_count = 0
            self._bytes_received = 0
            self._last_body_sha256 = None
            self._last_content_type = None
            return self._stats()

    def _stats(self) -> CaptureStats:
        snapshot = _CaptureSnapshot(
            request_count=self._request_count,
            bytes_received=self._bytes_received,
            last_body_sha256=self._last_body_sha256,
            last_content_type=self._last_content_type,
        )
        return CaptureStats(
            request_count=snapshot.request_count,
            bytes_received=snapshot.bytes_received,
            last_body_sha256=snapshot.last_body_sha256,
            last_content_type=snapshot.last_content_type,
        )

    @staticmethod
    def _classify_content_type(value: str | None) -> str | None:
        if value is None:
            return None
        media_type = value.partition(";")[0].strip().lower()
        known = {
            "application/json",
            "application/octet-stream",
            "application/x-www-form-urlencoded",
            "text/plain",
        }
        return media_type if media_type in known else "other"


def create_capture_app(
    *,
    store: CaptureStore | None = None,
    max_request_bytes: int | None = None,
) -> FastAPI:
    resolved_store = store or CaptureStore()
    limit = (
        max_request_bytes
        if max_request_bytes is not None
        else get_settings().leash_capture_request_bytes
    )
    app = FastAPI(title="Leash Local Capture Receiver", version="0.1.0")
    app.state.capture_store = resolved_store

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "storage": "counters_and_hashes_only"}

    @app.get("/stats", response_model=CaptureStats)
    async def stats() -> CaptureStats:
        return await resolved_store.snapshot()

    @app.post("/reset", response_model=CaptureStats)
    async def reset() -> CaptureStats:
        return await resolved_store.reset()

    @app.api_route(
        "/receive",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        response_model=CaptureStats,
    )
    async def receive(request: Request) -> CaptureStats:
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > limit:
                await resolved_store.record(bytes(body), request.headers.get("content-type"))
                raise HTTPException(status_code=413, detail="Capture request exceeded local limit")
        return await resolved_store.record(bytes(body), request.headers.get("content-type"))

    return app


app = create_capture_app()
