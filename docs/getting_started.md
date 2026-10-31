# Getting Started

No install needed -- everything is stdlib.

    # 1. smoke test the pipeline on the bundled corpus
    python -m sentinelforge doctor

    # 2. see the five monotonic benchmark metrics
    python -m sentinelforge bench

    # 3. scan a real directory
    python -m sentinelforge scan examples/vulnerable

    # 4. pick a reasoning mode
    python -m sentinelforge --mode high scan examples/vulnerable

    # 5. train the mock model (skill 0.5 -> 1.0)
    python -m sentinelforge train --epochs 10

    # 6. serve the HTTP API
    python -m sentinelforge serve --port 8420

Or install as a package:

    pip install -e .
    sentinelforge doctor
