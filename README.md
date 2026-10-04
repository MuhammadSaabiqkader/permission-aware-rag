# Keyline

Keyline is a full-stack, permission-aware knowledge app for teams. Users create a workspace, upload text or Markdown documents, and ask questions. Retrieval applies workspace and role permissions in the database before any passages are used to form an answer.

## Run locally

Requires Python 3.10+.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS / Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000), create a workspace, and sign in. The first account in a workspace is its admin. The database is created in `storage/keyline.sqlite3` by default.

## Features

- **Real accounts:** workspace-scoped email and password login; passwords are stored as salted scrypt hashes. Sessions use random, server-side tokens in HttpOnly cookies, with CSRF tokens on state-changing requests.
- **Tenant isolation:** users, documents, search passages, and audit events are always scoped to the authenticated workspace.
- **Role permissions:** admins manage members and can access all workspace documents; analysts can access documents shared with analysts; members can access documents shared with everyone.
- **Document library:** upload UTF-8 `.txt` and `.md` files up to 5 MB, split into overlapping passages, choose an access level, review the library, and delete documents as an admin.
- **Actual retrieval:** SQLite FTS5 ranks text passages, with tenant and role filters in the retrieval query. Answers include source references.
- **Audit history:** each question records who asked, the question, and which authorized source documents were retrieved. Admins see workspace events; other roles see their own.
- **Optional generated answers:** configure an OpenAI-compatible Chat Completions endpoint using the environment variables below. Only already-authorized passages are sent to the provider. Without a key, Keyline returns source excerpts directly.
- **Separate frontend and backend:** static HTML/CSS/JavaScript in `static/`, JSON API in FastAPI.

## Optional language model

Set these environment variables before starting the app. The default endpoint is OpenAI's API; a compatible provider can be configured with `OPENAI_BASE_URL` and `OPENAI_MODEL`.

```powershell
$env:OPENAI_API_KEY = "your-key"
$env:OPENAI_MODEL = "gpt-4o-mini"
```

Never put API keys in the repository, frontend code, screenshots, or a public issue. A generated answer is grounded in retrieved passages, but you should review model output before relying on it.

## Production deployment notes

This repository is a full-stack application starter, not a managed hosting setup. Run it behind HTTPS, set `COOKIE_SECURE=1`, use a persistent `DATABASE_PATH`, and keep secrets in the host's secret manager. The included SQLite database is suited to local development and a single app instance; use managed PostgreSQL and add email verification, password reset, monitoring, backups, and deployment-specific rate limiting before serving a larger or public user base.

Example server command:

```bash
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

## Architecture

```text
Browser (static frontend)
  ├─ Auth API → workspace, user, hashed password, session, CSRF
  ├─ Upload API → document → overlapping passages → SQLite FTS5
  └─ Ask API → authenticated workspace + role SQL filter → ranked passages
                                              ├─ optional language model
                                              └─ audit event + cited sources
```

## License

No license has been added yet. Choose a license before accepting outside contributions or permitting reuse.

