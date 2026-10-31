# Benchmark Methodology

`python -m sentinelforge bench` scans the model skill from 0.5 (random) to 1.0
(expert) and reports five metrics:

| Metric | Direction | Meaning |
|---|---|---|
| `detect_recall` | up | fraction of true findings flagged |
| `detect_precision` | up | flagged findings that are true |
| `false_positive_rate` | down | benign candidates flagged |
| `triage_accuracy` | up | severity assigned correctly |
| `remediation_quality` | up | patch closeness to gold fix |

The model's confidence formula is

    boost = (skill - 0.5) * 2
    conf  = 0.5 + boost*(signal-0.5) + (1-|boost|)*(noise-0.5)

At `skill=0.5` the model is a coin flip; at `skill=1.0` it is exact. This makes
the improvement both *visible* and *monotonic*, which is the point: the
architecture's value is that a stronger model measurably improves every
downstream stage.
