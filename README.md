ETL Incident Intelligence AI Agent
Overview

Production-ready AI Agent for automated triage of SSIS ETL failures.

Designed to handle high-volume log ingestion (10k+ logs/day), classify incidents deterministically, enrich with LLM reasoning, and generate structured remediation outputs.

Built using fully open-source stack.

Architecture

Logs → Gold Incident CSV → Stream Watcher →
Signature Deduplication (SQLite) →
Deterministic Policy Layer →
RAG (Chroma Vector Store + Runbooks) →
Ollama (Llama3 LLM) →
Structured JSONL Output →
Operational Dashboard (Failure Trends + Top Failures)

Tech Stack

Python 3.12

Ollama (Llama3)

LangChain (RAG orchestration)

ChromaDB (Vector store)

SQLite (Signature store)

Pandas (data processing)

DuckDB (optional analytics layer)

All tools are free and open-source.

Key Capabilities

Deterministic restart safety enforcement

Signature-based LLM deduplication

Idempotent stream processing

Runbook-aware RAG context retrieval

Structured JSONL incident outputs

Failure trend dashboards

Production-safe local streaming mode

Run Instructions
Build Vector Store
python rag/build_vector_store.py

Run Batch Agent
python app/incident_agent.py

Run Streaming Watcher
python -m app.stream_watch

One-Time Mode (Test)
python -m app.stream_watch --once --max 10

Outputs

state/agent_outputs/*.jsonl → Structured incident decisions

state/signatures.sqlite → Signature dedupe store

state/dashboard_top_failures.csv

state/dashboard_failure_trend.csv

Example Output
RootCause:
Target object missing or permissions misconfigured.

RestartSafe: NO (deterministic policy)

NextActions:
- Verify schema
- Validate execution account permissions

Escalation: MED (DBA)

Design Principles

LLM never overrides deterministic restart policy

High-risk failure families hard-coded

Signature caching reduces token usage

Structured outputs for downstream integration

Stream-safe processing (no reprocessing duplicates)

Future Enhancements

Kafka ingestion

Web dashboard (Streamlit)

Slack/PagerDuty integration

Confidence scoring

Drift detection on error signatures
