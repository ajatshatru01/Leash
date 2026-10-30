# Third-party dependency inventory

This inventory covers Leash's direct runtime and dashboard dependencies. Exact transitive versions
and integrity hashes are frozen in `uv.lock` and `apps/dashboard/pnpm-lock.yaml`. No third-party
images, fonts, logos, audio, video, or benchmark datasets are bundled in this repository.

## Python runtime dependencies

| Package | Audited version | License | Project |
|---|---:|---|---|
| FastAPI | 0.162.0 | MIT | https://github.com/fastapi/fastapi |
| HTTPX | 0.28.1 | BSD-3-Clause | https://github.com/encode/httpx |
| OpenAI Python | 2.54.0 | Apache-2.0 | https://github.com/openai/openai-python |
| Pydantic | 2.14.1 | MIT | https://github.com/pydantic/pydantic |
| pydantic-settings | 2.16.2 | MIT | https://github.com/pydantic/pydantic-settings |
| Typer | 0.27.3 | MIT | https://github.com/fastapi/typer |
| Uvicorn | 0.54.0 | BSD-3-Clause | https://github.com/encode/uvicorn |

## Dashboard dependencies

| Package | Locked version | License | Project |
|---|---:|---|---|
| React / React DOM | 19.3.1 | MIT | https://github.com/facebook/react |
| TypeScript | 7.0.2 | Apache-2.0 | https://github.com/microsoft/TypeScript |
| Vite | 8.3.5 | MIT | https://github.com/vitejs/vite |
| @vitejs/plugin-react | 6.1.2 | MIT | https://github.com/vitejs/vite-plugin-react |
| @types/react / @types/react-dom | 19.3.0 | MIT | https://github.com/DefinitelyTyped/DefinitelyTyped |

## External services and models

| Component | Use | Provenance action |
|---|---|---|
| Meta Model API | Muse Spark actor and Muse Wonder judge | Reconfirm participant credit terms before submission |
| `python:3.12-slim-bookworm` | Pinned isolated executor image | Docker Official Image; digest pinned in settings |

Leash's source is declared Apache-2.0 in `pyproject.toml`; the root `LICENSE` contains that license.
Verify this inventory again from the final clean checkout before submission.
