# Troubleshooting

| Symptom | Check and action |
|---|---|
| 401 | Supply the same `X-API-Key` as `NETLENS_API_KEY` on the API. Compose loads interpolation from `.env`; restart services after changing it. |
| 503 readiness | Run migrations; check PostgreSQL/Redis addresses and storage permissions. `localhost` inside a container refers to itself; Compose uses service names. |
| Job stays queued | Check the worker and dispatcher. Run `uv run netlens recover` using the same database/storage/Redis configuration. Readiness can be healthy even with no worker. |
| Job stays running after worker crash | Allow the configured stale interval, then run recovery; do not manually delete the capture while a job is active. |
| 409 deletion | An associated job is queued/running. Restore workers or allow bounded stale recovery to settle it. |
| 409 idempotency | The key was used with different parameters. Reuse the original request or choose a new key for a new operation. |
| 413 | File, packet, record, processing, or request-envelope limit exceeded. Read the code/message; raising bounds also requires more memory/time. |
| 422 upload | Invalid file framing, unsupported format/link type/version, partial record, or malformed pcapng block. A suffix change cannot repair file contents. |
| Empty findings | May be expected healthy traffic, no supported traffic, visibility limits, or a pending job. Check statistics, warnings, and status. |
| No DNS timing | DNS over TCP/encrypted DNS is excluded; simple pcapng packets lack timestamps; matching requires both directions and question/port/ID agreement. |
| Provider failed | Inspect `error_code`. Configure the selected model/key/server, check structured-output support, and review timeouts. Deterministic analysis remains retrievable. |
| `report_input_limit` | Analysis has over 100 findings. Inspect paginated findings or analyze a narrower capture. No findings are silently truncated into an AI summary. |
| Ollama connection failure in Compose | Use `host.docker.internal` on Docker Desktop and expose the local Ollama endpoint appropriately. Linux may need an explicit host-gateway mapping. |
| Scapy warns about libpcap | Offline file decoding does not require libpcap/Npcap; live capture is out of scope. |
| Integration tests skipped | Set both disposable service variables described in `docs/testing.md`; never use a deployment Redis database. |
| Windows pytest hangs creating asyncio socketpair | Some execution sandboxes block localhost sockets. Run tests in a normal authorized terminal; do not change detector logic to work around the sandbox. |

`uv run ruff check .` and `uv run pytest -m 'not integration'` are useful starting checks before debugging a service stack. Logs intentionally omit request bodies/provider errors; use synthetic captures when reproducing problems and do not paste private packet contents into bug reports.

If port 8000 is occupied, run `set "NETLENS_API_PORT=18000"` in Command Prompt before Compose startup, then pass `--url http://127.0.0.1:18000` to the end-to-end demo. Do not stop an unrelated service merely to free the default port.
