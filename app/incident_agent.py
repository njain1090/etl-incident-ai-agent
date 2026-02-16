import os
import re
import json
import time
import hashlib
import sqlite3
from datetime import datetime, timezone

import pandas as pd

# New packages you already installed (based on your imports)
from langchain_ollama import OllamaLLM
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings


# ======================================================================================
# 0) CONFIG
# ======================================================================================

GOLD_CSV = "data/gold/incident_intelligence_gold_v4.csv"
VECTOR_DIR = "state/vectorstore"
CACHE_DB = "state/incident_cache.sqlite"
OUT_DIR = "state/agent_outputs"

MODEL_NAME = "llama3"
TEMPERATURE = 0.1

TOP_K_RAG = 3
MAX_PER_FAMILY = 5          # show up to N incidents per family in console
MAX_TOTAL_PRINT = 25        # cap console output
WRITE_JSONL = True          # write structured incident reports

os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs("state", exist_ok=True)


# ======================================================================================
# 1) RESTART + ESCALATION POLICIES (LOCKED)
# ======================================================================================

NEVER_RESTART_FAMILIES = {
    "MISSING_OBJECT_OR_PERMISSION",
    "MISSING_STORED_PROCEDURE",
    "PERMISSION_DENIED",
    "CONNECTION_FAILED",
    "LOGIN_FAILED",
    "NULL_INSERT_OR_CONSTRAINT",
}

CONDITIONAL_RESTART_FAMILIES = {
    "DATA_TRUNCATION_FAILURE",
    "SCRIPT_COMPONENT_NULLREF",
    "UNKNOWN",
}

def policy_restart_safe(error_family: str, incident_type: str) -> str:
    fam = (error_family or "").upper()
    itype = (incident_type or "").upper()

    # Warnings: not a failure but can impact downstream
    if itype != "FAILURE":
        return "CONDITIONAL (warning-only; validate downstream impact)"

    if fam in NEVER_RESTART_FAMILIES:
        return "NO (deterministic policy: fix root cause first)"

    if fam in CONDITIONAL_RESTART_FAMILIES:
        return "CONDITIONAL (only after validating idempotency + applying fix)"

    return "CONDITIONAL (insufficient evidence)"


def policy_escalation(error_family: str, severity: str, primary_msg: str = "") -> str:
    fam = (error_family or "").upper()
    sev = (severity or "").upper()
    msg = (primary_msg or "").lower()

    # DB/platform issues are not LOW
    if fam in {"PERMISSION_DENIED"}:
        return "HIGH (DBA/Platform; credential/connection broken or access revoked)"
    if fam in {"MISSING_OBJECT_OR_PERMISSION", "MISSING_STORED_PROCEDURE"}:
        return "MED (DBA/Deployment owner; object/proc missing or permissions misconfigured)"
    if fam in {"CONNECTION_FAILED", "LOGIN_FAILED"}:
        return "HIGH (Platform/DBA; connectivity/credentials issue)"

    # High severity failures default to MED
    if sev == "HIGH":
        return "MED (Owning team + On-call; high-severity failure)"

    return "LOW (On-call; local fix/retry after validation)"


# ======================================================================================
# 2) SECONDARY CLASSIFIER (fix UNKNOWN cheaply)
# ======================================================================================

def refine_family(row: dict) -> str:
    fam = (row.get("error_family_v3") or "").upper()
    if fam and fam != "UNKNOWN":
        return fam

    msg = (row.get("primary_error_message") or "").lower()
    ev  = (row.get("evidence_excerpt") or "").lower()
    blob = msg + "\n" + ev

    # Common SSIS / SQL patterns
    if "could not find stored procedure" in blob:
        return "MISSING_STORED_PROCEDURE"

    if "cannot find the object" in blob or "does not exist" in blob:
        # Many are missing object or permission
        return "MISSING_OBJECT_OR_PERMISSION"

    if "failed to acquire connection" in blob or "login failed" in blob:
        return "PERMISSION_DENIED"

    if "cannot insert the value null" in blob or "cannot insert null" in blob:
        return "NULL_INSERT_OR_CONSTRAINT"

    if "truncation may occur" in blob or "string or binary data would be truncated" in blob:
        return "DATA_TRUNCATION_FAILURE"

    if "object reference not set to an instance of an object" in blob:
        return "SCRIPT_COMPONENT_NULLREF"

    return "UNKNOWN"


# ======================================================================================
# 3) SIGNATURE + CACHE (this makes 10k/day feasible)
# ======================================================================================

def _normalize_text(text: str) -> str:
    if not text:
        return ""
    # remove numbers, GUID-like blobs, long hex
    text = re.sub(r"\d+", "<n>", text)
    text = re.sub(r"[0-9a-fA-F]{8,}", "<hex>", text)
    text = re.sub(r"\s+", " ", text).strip().lower()
    return text[:800]

def make_signature(error_family: str, package: str, primary_msg: str, tasks: str = "") -> str:
    base = "||".join([
        (error_family or "").upper(),
        (package or "").lower().strip(),
        _normalize_text(primary_msg),
        _normalize_text(tasks),
    ])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


class IncidentCache:
    def __init__(self, path: str = CACHE_DB):
        self.path = path
        self._init()

    def _init(self):
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                sig TEXT PRIMARY KEY,
                response TEXT NOT NULL,
                family TEXT,
                updated_at TEXT,
                seen_count INTEGER DEFAULT 1
            )
        """)
        con.commit()
        con.close()

    def lookup(self, sig: str):
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute("SELECT response, seen_count FROM cache WHERE sig=?", (sig,))
        row = cur.fetchone()
        con.close()
        return row  # (response, seen_count) or None

    def upsert(self, sig: str, response: str, family: str):
        now_iso = datetime.now(timezone.utc).isoformat()
        con = sqlite3.connect(self.path)
        cur = con.cursor()
        cur.execute("""
            INSERT INTO cache(sig, response, family, updated_at, seen_count)
            VALUES(?,?,?,?,1)
            ON CONFLICT(sig) DO UPDATE SET
                response=excluded.response,
                family=excluded.family,
                updated_at=excluded.updated_at,
                seen_count=cache.seen_count+1
        """, (sig, response, family, now_iso))
        con.commit()
        con.close()


# ======================================================================================
# 4) LLM + VECTOR STORE (RAG)
# ======================================================================================

embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")

vectordb = Chroma(
    persist_directory=VECTOR_DIR,
    embedding_function=embeddings
)

llm = OllamaLLM(model=MODEL_NAME, temperature=TEMPERATURE)


def get_rag_context(query: str, k: int = TOP_K_RAG) -> str:
    try:
        docs = vectordb.similarity_search(query, k=k)
        if not docs:
            return ""
        return "\n".join([d.page_content for d in docs])
    except Exception:
        return ""


# ======================================================================================
# 5) HARD RULES (return immediately, no LLM)
# ======================================================================================

def apply_hard_rules(row: dict, restart_policy: str, esc_policy: str) -> str | None:
    fam = (row.get("error_family_v3") or "").upper()
    msg = row.get("primary_error_message") or ""

    if fam in {"MISSING_OBJECT_OR_PERMISSION"}:
        return f"""RootCause:
Target object missing or permissions not granted (table/view/schema mismatch or access revoked).

RestartSafe: {restart_policy}

NextActions:
- Verify target DB + schema and confirm the object exists.
- Validate SSIS connection manager points to the expected DB.
- Confirm execution account has required permissions (SELECT/EXEC/TRUNCATE as applicable).
- If object recently renamed/migrated, coordinate deployment rollback/forward.

Escalation: {esc_policy}
"""

    if fam in {"MISSING_STORED_PROCEDURE"}:
        return f"""RootCause:
Stored procedure referenced by package is missing in the connected database/schema or execution user lacks EXEC permission.

RestartSafe: {restart_policy}

NextActions:
- Confirm stored procedure exists in correct DB/schema (compare with deployment scripts).
- Verify SSIS connection manager target DB.
- Validate execution account EXEC permissions.
- Coordinate redeploy or hotfix if proc was dropped/renamed.

Escalation: {esc_policy}
"""

    if fam in {"PERMISSION_DENIED"}:
        return f"""RootCause:
Connection/credential or permission issue. Package cannot acquire required connection or access required objects.

RestartSafe: {restart_policy}

NextActions:
- Validate SQL Agent proxy/credential used for SSIS execution.
- Confirm DSN/connection string and secret rotation status (if applicable).
- Check grants/roles for execution account on target DB/schema.
- Coordinate with DBA/platform team to restore least-privilege access.

Escalation: {esc_policy}
"""

    if fam in {"DATA_TRUNCATION_FAILURE"}:
        return f"""RootCause:
Data length mismatch between source/dataflow and target column definition causing truncation.

RestartSafe: {restart_policy}

NextActions:
- Identify offending column(s) from the error message.
- Update target schema length OR cleanse/trim input upstream.
- Re-validate SSIS metadata (pipeline buffer types) after change.
- Rerun the failed step only after fix (avoid repeated partial loads).

Escalation: {esc_policy}
"""

    if fam in {"SCRIPT_COMPONENT_NULLREF"}:
        return f"""RootCause:
Script Component threw NullReferenceException (missing/null input value, bad cast, or unhandled null in script).

RestartSafe: {restart_policy}

NextActions:
- Identify script component and the referenced column(s).
- Add explicit null checks + safe casting; log offending row keys.
- Confirm upstream schema/data changes (new nulls, missing columns).
- Rerun once after code fix; if still failing, isolate sample rows.

Escalation: {esc_policy}
"""

    return None


# ======================================================================================
# 6) LLM ANALYSIS (only for new signatures)
# ======================================================================================

def analyze_incident(row: dict) -> str:
    retrieval_query = f"{row.get('error_family_v3','')} :: {row.get('primary_error_message','')}"
    context = get_rag_context(retrieval_query, k=TOP_K_RAG)

    restart_policy = policy_restart_safe(row.get("error_family_v3"), row.get("incident_type"))
    esc_policy = policy_escalation(row.get("error_family_v3"), row.get("severity"), row.get("primary_error_message"))

    baseline_action = row.get("recommended_action_v3") or "No baseline action available."

    prompt = f"""
You are a Senior Data Engineering On-Call AI.

HARD RULES (do not violate):
- Do NOT change RestartSafe. Use exactly the provided RestartSafe policy.
- Escalation should align to the provided Escalation policy.
- Use baseline recommended_action_v3 as default NextActions; refine only if runbook context adds specifics.
- If error family is UNKNOWN, do NOT guess causes. State Unknown + list evidence + next safe triage steps.

Incident:
- Package: {row.get('package_name_inferred')}
- Error Family: {row.get('error_family_v3')}
- Severity: {row.get('severity')}
- Incident Type: {row.get('incident_type')}
- Primary Error Message: {row.get('primary_error_message')}

RestartSafe (LOCKED POLICY):
{restart_policy}

Escalation Policy (LOCKED GUIDANCE):
{esc_policy}

Baseline NextActions (LOCKED BASELINE):
{baseline_action}

Runbook / Known-Issues Context:
{context}

Return ONLY in this format:

RootCause:
RestartSafe: {restart_policy}
NextActions:
- (step 1)
- (step 2)
Escalation: {esc_policy}
"""
    return llm.invoke(prompt)


# ======================================================================================
# 7) MAIN
# ======================================================================================

def main():
    start = time.time()
    cache = IncidentCache(CACHE_DB)

    df = pd.read_csv(GOLD_CSV)

    # Normalize family via secondary classifier
    df["error_family_v3"] = df.apply(lambda r: refine_family(r.to_dict()), axis=1)

    failures = df[df["incident_type"].astype(str).str.upper() == "FAILURE"].copy()

    # Stable signature for dedupe + cache
    failures["sig"] = failures.apply(
        lambda r: make_signature(
            r.get("error_family_v3"),
            r.get("package_name_inferred"),
            r.get("primary_error_message"),
            r.get("sources_tasks", ""),
        ),
        axis=1
    )

    # Unique incidents (dedupe)
    unique = failures.drop_duplicates("sig").copy()

    # Choose a diverse sample (up to MAX_PER_FAMILY per family)
    sample = (
        unique.groupby("error_family_v3", dropna=False)
        .head(MAX_PER_FAMILY)
        .head(MAX_TOTAL_PRINT)
    )

    out_path = os.path.join(
        OUT_DIR,
        f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    )

    total = len(failures)
    uniq = len(unique)

    print(f"\nTotal failures in CSV: {total}")
    print(f"Unique failure signatures: {uniq}")
    print(f"Showing up to {MAX_TOTAL_PRINT} incidents ({MAX_PER_FAMILY}/family)\n")

    cache_hits = 0
    llm_calls = 0
    written = 0

    for _, row in sample.iterrows():
        rowd = row.to_dict()

        # Locked policies
        restart_policy = policy_restart_safe(rowd.get("error_family_v3"), rowd.get("incident_type"))
        esc_policy = policy_escalation(rowd.get("error_family_v3"), rowd.get("severity"), rowd.get("primary_error_message"))

        # Hard-rules first
        hard = apply_hard_rules(rowd, restart_policy, esc_policy)
        sig = rowd.get("sig")

        # Cache check
        cached = cache.lookup(sig) if sig else None

        if cached:
            cache_hits += 1
            result = cached[0]
        else:
            if hard:
                result = hard
            else:
                llm_calls += 1
                result = analyze_incident(rowd)
            cache.upsert(sig, result, rowd.get("error_family_v3"))

        # Console print
        print("=" * 100)
        print(f"LOG: {rowd.get('log_file')}")
        print(f"FAMILY: {rowd.get('error_family_v3')}")
        print("-" * 100)
        print(result)

        # Write structured JSONL output
        if WRITE_JSONL:
            record = {
                "ts_utc": datetime.now(timezone.utc).isoformat(),
                "log_file": rowd.get("log_file"),
                "package": rowd.get("package_name_inferred"),
                "incident_type": rowd.get("incident_type"),
                "severity": rowd.get("severity"),
                "error_family": rowd.get("error_family_v3"),
                "signature": sig,
                "cache_hit": bool(cached),
                "report_text": result,
                "primary_error_message": rowd.get("primary_error_message"),
                "recommended_action_baseline": rowd.get("recommended_action_v3"),
            }
            with open(out_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
            written += 1

    dur = time.time() - start
    metrics = {
        "total_failures_in_csv": total,
        "unique_signatures": uniq,
        "printed": int(sample.shape[0]),
        "jsonl_written": written,
        "cache_hits": cache_hits,
        "llm_calls": llm_calls,
        "duration_seconds": round(dur, 2),
        "cache_db": CACHE_DB,
        "jsonl_output": out_path if WRITE_JSONL else None
    }

    with open(os.path.join(OUT_DIR, "run_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("\n" + "=" * 100)
    print("DONE")
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()

