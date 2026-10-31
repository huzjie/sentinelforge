# HTTP API

Zero-dependency server via the standard library:

    python -m sentinelforge serve --port 8420

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | liveness + sovereignty audit |
| GET | `/v1/info` | engine info (mode, skill, budget) |
| GET | `/v1/modes` | reasoning-mode table |
| GET | `/v1/bench` | benchmark table |
| POST | `/v1/scan` | scan `{"text": "...", "path": "..."}` |

## Example

    curl -s localhost:8420/v1/info
    curl -s -X POST localhost:8420/v1/scan \
      -H 'Content-Type: application/json' \
      -d '{"text": "os.system(\"rm -rf \" + p)", "path": "x.py"}'
