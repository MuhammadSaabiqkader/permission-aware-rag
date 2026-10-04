# Keyline — permission-aware multi-tenant RAG

A small, runnable portfolio demo of a core enterprise RAG requirement: **authorize documents before retrieval**, so a user's question cannot retrieve another tenant's or role-restricted content.

## Run locally

Requires Python 3.10 or newer. No packages or API keys are needed.

```bash
python app.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The SQLite database is created beside `app.py` and seeded with fictional Northstar and BluePeak documents on first run.

### Try the access boundaries

- As **Maya (Northstar analyst)**, ask “What changed in Q3?” She can retrieve the Northstar Q3 report.
- As **Leo (Northstar member)**, ask the same question. The analyst-only report is not in his retrievable document set.
- As **Ari (Northstar admin)**, ask about the incident review. The admin-only review is available.
- As **Nina (BluePeak analyst)**, ask “What were September delivery metrics?” She can retrieve BluePeak data, never Northstar data.

## What this demonstrates

- Tenant and role predicates are applied in the SQLite query **before document content enters matching**.
- Retrieval results include source labels and citations.
- Each query records the user, tenant, query text, timestamp, and retrieved document IDs in an audit table. The UI shows the signed-in demo user's recent events.
- The demo identity is held in a server-side session token; the browser does not choose a tenant ID for retrieval.

## Architecture

```text
Question → demo session identity → SQL tenant + role filter → keyword ranking
        → answer assembled from authorized passages + source cards
        → audit event (user, tenant, query, retrieved document IDs)
```

## Scope and production considerations

This is a dependency-free **retrieval and authorization prototype**, not a full generative RAG service: it uses simple keyword matching and returns the matching source passages instead of calling an LLM or vector database. That keeps the access-control boundary easy to inspect. A next iteration could add embeddings/vector search while retaining tenant and role constraints in the retrieval query, then add an LLM that receives only the already-authorized passages.

The user switcher is intentionally a local demo convenience, not authentication. Before deployment, replace it with verified identity from an authentication provider, store sessions safely, add CSRF protection and rate limits, protect audit data, and use a database and authorization model appropriate to the deployment. Do not expose this demo server to the public internet.

## Stack

Python standard library · SQLite · HTML/CSS/JavaScript
