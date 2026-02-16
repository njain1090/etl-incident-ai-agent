# app/stream_watch.py
import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# IMPORTANT: run as module: python -m app.stream_watch
from app.incident_agent import analyze_incident  # your working agent
from app.signature_store import SignatureStore, make_signature  # you said you created these

DEFAULT_WATCH_DIR = "data/logs_sample"
DEFAULT_GOLD_CSV = "data/gold/incident_intelligence_gold_v4.csv"
DEFAULT_SEEN = "state/stream_seen.json"
DEFAULT_SIG_DB = "state/signatures.sqlite"
DEFAULT_OUT_DIR = "state/agent_outputs"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_seen(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"seen": {}}
    with p.open("r") as f:
        return json.load(f)


def save_seen(path: str, data: dict) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def list_files(root: str):
    rootp = Path(root)
    if not rootp.exists():
        return []
    files = []
    for p in rootp.iterdir():
        if p.is_file():
            files.append(p)
    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=False)


def build_index_from_gold(gold_csv: str) -> dict:
    """
    Map log_file -> row dict (from gold csv).
    If duplicates exist, we keep the latest by file_modified/run_end_time if present.
    """
    df = pd.read_csv(gold_csv)

    # Normalize
    df["log_file"] = df["log_file"].astype(str)

    # Prefer latest rows if duplicates exist
    sort_cols = []
    for c in ["file_modified", "run_end_time", "run_start_time"]:
        if c in df.columns:
            sort_cols.append(c)

    if sort_cols:
        # safest: sort lexicographically; your timestamps are ISO-ish already
        df = df.sort_values(sort_cols, ascending=True)

    idx = {}
    for _, r in df.iterrows():
        idx[r["log_file"]] = r.to_dict()
    return idx


def should_process(full_path: str, seen: dict) -> bool:
    return full_path not in seen.get("seen", {})


def mark_seen(full_path: str, seen: dict) -> None:
    seen.setdefault("seen", {})[full_path] = utc_now_iso()


def write_jsonl(out_path: str, record: dict) -> None:
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "a") as f:
        f.write(json.dumps(record) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch-dir", default=DEFAULT_WATCH_DIR)
    ap.add_argument("--gold-csv", default=DEFAULT_GOLD_CSV)
    ap.add_argument("--seen", default=DEFAULT_SEEN)
    ap.add_argument("--sig-db", default=DEFAULT_SIG_DB)
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    ap.add_argument("--poll-seconds", type=int, default=3)
    ap.add_argument("--once", action="store_true", help="Process backlog once and exit")
    ap.add_argument("--include-warnings", action="store_true", help="Also process WARNING rows")
    ap.add_argument("--max", type=int, default=25, help="Max items to process per run (once mode or per loop)")
    args = ap.parse_args()

    watch_dir = os.path.abspath(args.watch_dir)
    gold_csv = os.path.abspath(args.gold_csv)
    seen_path = os.path.abspath(args.seen)
    sig_db = os.path.abspath(args.sig_db)
    out_dir = os.path.abspath(args.out_dir)

    print(f"Watching:  {watch_dir}")
    print(f"Gold CSV:  {gold_csv}")
    print(f"State:     {seen_path}")
    print(f"Sig DB:    {sig_db}")
    print(f"JSONL out: {out_dir}")
    print("Stop anytime with Ctrl+C\n")

    # Load gold index once (fast)
    gold_index = build_index_from_gold(gold_csv)

    # State
    seen = load_seen(seen_path)

    # Signature store
    sig_store = SignatureStore(sig_db)

    def process_once_pass():
        processed = 0
        files = list_files(watch_dir)

        # Only consider files that exist in gold CSV (so we can attach metadata)
        for p in files:
            full_path = str(p.resolve())
            base = p.name

            if base not in gold_index:
                continue  # ignore unrecognized files (not in gold csv)

            if not should_process(full_path, seen):
                continue

            row = gold_index[base]

            # Default behavior: FAILURE only (FAANG: reduce noise)
            itype = str(row.get("incident_type", "")).upper()
            if itype != "FAILURE" and not args.include_warnings:
                mark_seen(full_path, seen)
                continue

            # Signature: stable key for recurrence tracking
            sig = make_signature(
                row.get("error_family_v3", ""),
                row.get("package_name_inferred", ""),
                row.get("primary_error_message", ""),
                row.get("sources_tasks", ""),
            )

            sig_store.bump(sig)

            # Run agent
            print("=" * 100)
            print(f"NEW LOG: {base}")
            print(f"TYPE: {row.get('incident_type')} | FAMILY: {row.get('error_family_v3')} | CACHE_HIT: (handled inside agent cache)")
            print("-" * 100)

            agent_output = analyze_incident(row)

            print(agent_output)
            print()

            rec = {
                "ts_utc": utc_now_iso(),
                "log_file": base,
                "full_path": full_path,
                "incident_type": row.get("incident_type"),
                "severity": row.get("severity"),
                "error_family_v3": row.get("error_family_v3"),
                "package_name_inferred": row.get("package_name_inferred"),
                "primary_error_message": row.get("primary_error_message"),
                "error_signature": sig,
                "agent_output": agent_output,
            }

            out_path = os.path.join(out_dir, f"stream_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl")
            write_jsonl(out_path, rec)

            mark_seen(full_path, seen)
            processed += 1

            if processed >= args.max:
                break

        save_seen(seen_path, seen)
        return processed

    if args.once:
        n = process_once_pass()
        print(f"[ONCE MODE] processed={n}")
        return

    # continuous watch mode
    while True:
        n = process_once_pass()
        if n == 0:
            time.sleep(args.poll_seconds)


if __name__ == "__main__":
    main()

