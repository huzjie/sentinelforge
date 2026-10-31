# sentinelforge: sovereign autonomous cyber-defense engine
# Zero runtime dependencies beyond the Python standard library.
FROM python:3.12-slim

WORKDIR /app

COPY sentinelforge ./sentinelforge
COPY pyproject.toml README.md LICENSE ./
COPY recipes ./recipes
COPY prompts ./prompts

RUN pip install --no-cache-dir . && \
    useradd --create-home --uid 10001 sentinel && \
    mkdir -p /data/reports && chown -R sentinel /app /data

USER sentinel
WORKDIR /data

# Run offline by default (sovereignty). Bind-mount your code to scan into /scan.
ENTRYPOINT ["sentinelforge"]
CMD ["scan", "/scan"]
