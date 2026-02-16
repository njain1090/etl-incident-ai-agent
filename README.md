# ETL Incident Intelligence AI Agent

Production-style AI agent for automated root cause analysis of ETL/SSIS pipeline failures.

## Overview

This project simulates an enterprise-grade incident intelligence platform that:

- Parses ETL log files
- Classifies failure types
- Applies deterministic restart policies
- Uses RAG (Retrieval Augmented Generation) for runbook-aware reasoning
- Generates structured incident response outputs
- Maintains signature store for deduplication
- Produces operational dashboard metrics

Designed as a FAANG-level Data Engineering + AI system.

---

## Architecture

logs → gold incident table → streaming watcher →  
LLM + deterministic rules → signature store →  
JSONL outputs + dashboard analytics

Core Components:

- `incident_agent.py` → LLM + deterministic restart policy engine
- `stream_watch.py` → production-style log watcher
- `signature_store.py` → failure deduplication (SQLite)
- `dashboard_queries.py` → operational metrics generation
- `rag/build_vector_store.py` → embedding-based runbook retrieval

---

## Features

- Deterministic restart-safety enforcement
- Failure signature deduplication
- Vector-based historical context retrieval
- Local LLM (Ollama + Llama3)
- SQLite-backed signature intelligence
- Failure trend analytics
- Stream processing simulation

---

## How to Run

### 1. Install dependencies

pip install -r requirements.txt


### 2. Build vector store


python rag/build_vector_store.py


### 3. Run batch incident analysis


python app/incident_agent.py


### 4. Run streaming watcher


python -m app.stream_watch --once


### 5. Generate dashboard metrics


python app/dashboard_queries.py


---

## Resume-Ready Impact

- Reduced manual triage time by automating ETL root cause classification
- Implemented deterministic restart-safety enforcement policies
- Designed signature-based failure deduplication system
- Built RAG-enabled runbook intelligence layer
- Created operational analytics dashboards for failure trends
- Simulated production-grade streaming incident watcher

---

## Technologies

Python  
LangChain  
Ollama (Llama3)  
ChromaDB  
SQLite  
RAG Architecture  
Vector Embeddings  
ETL Observability  
Failure Signature Modeling  

---

## Disclaimer

All logs and data in this repository are synthetic or anonymized.
No production or proprietary data is included.
