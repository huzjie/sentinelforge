# -*- coding: utf-8 -*-
"""Command-line interface: doctor / bench / scan / train / serve / export."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .config import load_config
from .core.engine import Engine
from . import bench as benchmod
from .world.corpus import make_samples
from .training.trainer import SkillTrainer


def cmd_doctor(cfg):
    cfg["model"]["skill"] = 0.9
    engine = Engine(cfg)
    samples = make_samples()
    total = 0
    for s in samples[:6]:
        r = engine.scan(s["id"], s["text"])
        total += r["summary"]["findings"]
        print("[doctor] %-16s findings=%-3d critical=%d high=%d risk=%.1f"
              % (s["id"], r["summary"]["findings"], r["summary"]["critical"],
                 r["summary"]["high"], r["summary"]["risk_score"]))
    print("[doctor] mode=%s total_findings=%d sovereignty=%s"
          % (engine.modes.label(), total, engine.sovereignty.audit()["offline"]))
    print("[doctor] OK")


def cmd_bench(cfg):
    rows = benchmod.run_all()
    print("[bench] skill  recall  precision  fpr    triage  remed")
    for r in rows:
        print("[bench] %.2f   %.3f   %.3f      %.3f   %.3f   %.3f" % (
            r["skill"], r["detect_recall"], r["detect_precision"],
            r["false_positive_rate"], r["triage_accuracy"], r["remediation_quality"]))
    s = benchmod.summarize(rows)
    print("[bench] recall %.3f->%.3f | precision %.3f->%.3f | fpr %.3f->%.3f | triage %.3f->%.3f | remed %.3f->%.3f"
          % (s["recall"][0], s["recall"][1], s["precision"][0], s["precision"][1],
             s["fpr"][0], s["fpr"][1], s["triage"][0], s["triage"][1],
             s["remediation"][0], s["remediation"][1]))


def cmd_scan(cfg, args):
    engine = Engine(cfg)
    targets = []
    p = Path(args.path)
    if p.is_dir():
        exts = {".py", ".js", ".ts", ".go", ".java", ".txt", ".json", ".toml", ".yaml", ".yml"}
        targets = [f for f in p.rglob("*") if f.is_file() and f.suffix in exts]
    else:
        targets = [p]
    all_findings = 0
    all_cves = 0
    for f in targets:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        r = engine.scan(str(f), text)
        all_findings += r["summary"]["findings"]
        all_cves += r["summary"]["cves"]
        print("[scan] %-40s findings=%d cves=%d" % (f.name, r["summary"]["findings"], r["summary"]["cves"]))
    print("[scan] TOTAL findings=%d cves=%d across %d files" % (all_findings, all_cves, len(targets)))
    if args.out:
        # write an aggregate report using the last scan's reporter path is not
        # aggregate-safe; emit a simple json summary instead.
        Path(args.out).write_text(json.dumps({"findings": all_findings, "cves": all_cves},
                                              ensure_ascii=False, indent=2), encoding="utf-8")
        print("[scan] wrote %s" % args.out)


def cmd_train(cfg, args):
    t = SkillTrainer(cfg["model"]["skill"], args.lr)
    for i in range(args.epochs):
        step = t.train_step()
        print("[train] step %02d skill=%.3f recall %.3f->%.3f" % (
            i + 1, step["skill"], step["recall_before"], step["recall_after"]))


def cmd_export(cfg, args):
    engine = Engine(cfg)
    s = make_samples()[0]
    r = engine.scan(s["id"], s["text"])
    Path(args.out).write_text(r["report"], encoding="utf-8")
    print("[export] wrote %s" % args.out)


def cmd_serve(cfg, args):
    from .serving.app import serve
    serve(host=args.host, port=args.port, cfg=cfg)


def cmd_modes(cfg, args):
    from .core.modes import MODES
    for name, spec in MODES.items():
        mark = " <-- current" if name == cfg["engine"]["mode"] else ""
        print("[modes] %-6s depth=%d budget=x%.1f correlate=%s patch=%s (%s)%s"
              % (name, spec["depth"], spec["budget_mult"], spec["correlate"],
                 spec["patch"], spec["label"], mark))


def build_parser():
    ap = argparse.ArgumentParser(prog="sentinelforge",
                                 description="sovereign autonomous cyber-defense engine")
    ap.add_argument("--recipe", default=None, help="yaml recipe to merge over defaults")
    ap.add_argument("--mode", default=None, help="low / medium / high (overrides recipe)")
    ap.add_argument("--skill", type=float, default=None, help="model skill 0.0-1.0")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("doctor")
    sub.add_parser("bench")
    sub.add_parser("modes")

    p = sub.add_parser("scan"); p.add_argument("path"); p.add_argument("--out", default=None)
    p = sub.add_parser("train"); p.add_argument("--epochs", type=int, default=10); p.add_argument("--lr", type=float, default=0.05)
    p = sub.add_parser("export"); p.add_argument("--out", default="report.md")
    p = sub.add_parser("serve"); p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8420)
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    cfg = load_config(args.recipe)
    if args.mode:
        cfg["engine"]["mode"] = args.mode
    if args.skill is not None:
        cfg["model"]["skill"] = args.skill
    if args.cmd is None:
        ap.print_help()
        return
    dispatch = {
        "doctor": lambda: cmd_doctor(cfg),
        "bench": lambda: cmd_bench(cfg),
        "scan": lambda: cmd_scan(cfg, args),
        "train": lambda: cmd_train(cfg, args),
        "export": lambda: cmd_export(cfg, args),
        "serve": lambda: cmd_serve(cfg, args),
        "modes": lambda: cmd_modes(cfg, args),
    }
    dispatch[args.cmd]()


if __name__ == "__main__":
    main()
