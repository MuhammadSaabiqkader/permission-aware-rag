"""Keyline: permission-aware, multi-tenant knowledge retrieval."""

from __future__ import annotations

import hashlib
import hmac
import math
from io import BytesIO
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("POSTGRES_URL")
USE_POSTGRES = bool(DATABASE_URL)
DB_FILE = Path(os.getenv("DATABASE_PATH", str(ROOT / "storage" / "keyline.sqlite3")))
if not USE_POSTGRES:
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
COOKIE_SECURE = os.getenv(
    "COOKIE_SECURE", "1" if os.getenv("VERCEL") == "1" else "0"
).lower() in {"1", "true", "yes"}
SESSION_SECONDS = 7 * 24 * 60 * 60
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ROLES = {"admin", "analyst", "member"}
SAMPLE_DOCUMENT_ACCESS = {
    "01_Employee_Handbook.pdf": "everyone",
    "02_Onboarding_Policy.pdf": "everyone",
    "03_Project_Apollo.pdf": "analyst",
    "04_Project_Risks.pdf": "analyst",
    "05_Financial_Report_2026.pdf": "admin",
    "06_Management_Strategy_2026.pdf": "admin",
}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_PG_POOL = None

app = FastAPI(title="Keyline", version="1.0.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class PostgresConnection:
    def __init__(self, manager):
        self.manager = manager
        self.raw = None

    def __enter__(self):
        self.raw = self.manager.__enter__()
        return self

    def __exit__(self, exc_type, exc, traceback):
        return self.manager.__exit__(exc_type, exc, traceback)

    def execute(self, statement, params=()):
        return self.raw.execute(statement.replace("?", "%s"), params)

    def executemany(self, statement, params):
        return self.raw.executemany(statement.replace("?", "%s"), params)


def connect():
    if USE_POSTGRES:
        global _PG_POOL
        if _PG_POOL is None:
            from psycopg.rows import dict_row
            from psycopg_pool import ConnectionPool
            _PG_POOL = ConnectionPool(
                DATABASE_URL, min_size=0, max_size=5, kwargs={"row_factory": dict_row}
            )
        return PostgresConnection(_PG_POOL.connection())
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize() -> None:
    if os.getenv("VERCEL") == "1" and not USE_POSTGRES:
        raise RuntimeError("Configure DATABASE_URL with a persistent PostgreSQL database on Vercel.")
    if USE_POSTGRES:
        with connect() as db:
            db.execute("CREATE EXTENSION IF NOT EXISTS vector")
            db.execute("""
                CREATE TABLE IF NOT EXISTS workspaces (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    email TEXT NOT NULL, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin','analyst','member')),
                    password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
                    created_at TEXT NOT NULL, UNIQUE(workspace_id, email)
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                    owner_id TEXT NOT NULL REFERENCES users(id), filename TEXT NOT NULL,
                    title TEXT NOT NULL, allowed_roles TEXT NOT NULL,
                    bytes BIGINT NOT NULL, created_at TEXT NOT NULL
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS chunks (
                    id BIGSERIAL PRIMARY KEY,
                    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    workspace_id TEXT NOT NULL, allowed_roles TEXT NOT NULL,
                    title TEXT NOT NULL, source TEXT NOT NULL, content TEXT NOT NULL,
                    embedding vector(1536),
                    search_vector tsvector GENERATED ALWAYS AS (
                        setweight(to_tsvector('simple', coalesce(title, '')), 'A') ||
                        setweight(to_tsvector('simple', coalesce(source, '')), 'B') ||
                        setweight(to_tsvector('simple', coalesce(content, '')), 'C')
                    ) STORED
                )
            """)
            db.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id BIGSERIAL PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
                    query TEXT NOT NULL, retrieved_document_ids TEXT NOT NULL, created_at TEXT NOT NULL
                )
            """)
            db.execute("CREATE INDEX IF NOT EXISTS users_workspace_idx ON users(workspace_id)")
            db.execute("CREATE INDEX IF NOT EXISTS docs_workspace_idx ON documents(workspace_id)")
            db.execute("CREATE INDEX IF NOT EXISTS audit_workspace_idx ON audit_log(workspace_id,id DESC)")
            db.execute("CREATE INDEX IF NOT EXISTS chunks_workspace_idx ON chunks(workspace_id)")
            db.execute("CREATE INDEX IF NOT EXISTS chunks_search_idx ON chunks USING GIN(search_vector)")
            db.execute("CREATE INDEX IF NOT EXISTS chunks_embedding_idx ON chunks USING hnsw(embedding vector_cosine_ops)")
        return
    with connect() as db:
        db.executescript("""
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                email TEXT NOT NULL COLLATE NOCASE, name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin','analyst','member')),
                password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
                created_at TEXT NOT NULL, UNIQUE(workspace_id, email)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL REFERENCES workspaces(id),
                owner_id TEXT NOT NULL REFERENCES users(id), filename TEXT NOT NULL,
                title TEXT NOT NULL, allowed_roles TEXT NOT NULL,
                bytes INTEGER NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chunks (
                id INTEGER PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                workspace_id TEXT NOT NULL, allowed_roles TEXT NOT NULL,
                title TEXT NOT NULL, source TEXT NOT NULL, content TEXT NOT NULL,
                embedding_json TEXT
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
                workspace_id UNINDEXED, allowed_roles UNINDEXED,
                title, source, content, content='chunks', content_rowid='id'
            );
            CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
                INSERT INTO chunks_fts(rowid,workspace_id,allowed_roles,title,source,content)
                VALUES(new.id,new.workspace_id,new.allowed_roles,new.title,new.source,new.content);
            END;
            CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
                INSERT INTO chunks_fts(chunks_fts,rowid,workspace_id,allowed_roles,title,source,content)
                VALUES('delete',old.id,old.workspace_id,old.allowed_roles,old.title,old.source,old.content);
            END;
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY, workspace_id TEXT NOT NULL, user_id TEXT NOT NULL,
                query TEXT NOT NULL, retrieved_document_ids TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS users_workspace_idx ON users(workspace_id);
            CREATE INDEX IF NOT EXISTS docs_workspace_idx ON documents(workspace_id);
            CREATE INDEX IF NOT EXISTS audit_workspace_idx ON audit_log(workspace_id,id DESC);
        """)
        chunk_columns = {row["name"] for row in db.execute("PRAGMA table_info(chunks)")}
        if "embedding_json" not in chunk_columns:
            db.execute("ALTER TABLE chunks ADD COLUMN embedding_json TEXT")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    return digest, salt


def check_password(password: str, digest: str, salt: str) -> bool:
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()
    return hmac.compare_digest(candidate, digest)


def issue_session(db: sqlite3.Connection, user_id: str, response) -> str:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    expires = datetime.now(timezone.utc) + timedelta(seconds=SESSION_SECONDS)
    db.execute("INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)",
               (hashlib.sha256(token.encode()).hexdigest(), user_id, csrf, expires.isoformat()))
    response.set_cookie("keyline_session", token, max_age=SESSION_SECONDS, httponly=True,
                        secure=COOKIE_SECURE, samesite="strict", path="/")
    return csrf


def current_user(request: Request) -> dict:
    token = request.cookies.get("keyline_session")
    if not token:
        raise HTTPException(401, "Sign in to continue.")
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with connect() as db:
        row = db.execute("""
            SELECT u.id,u.workspace_id,u.email,u.name,u.role,w.name AS workspace_name,s.csrf_token
            FROM sessions s JOIN users u ON u.id=s.user_id
            JOIN workspaces w ON w.id=u.workspace_id
            WHERE s.token_hash=? AND s.expires_at > ?
        """, (hashed, now_iso())).fetchone()
    if not row:
        raise HTTPException(401, "Your session expired. Please sign in again.")
    return dict(row)


def authenticated_user(request: Request) -> dict:
    user = current_user(request)
    if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), user["csrf_token"]):
        raise HTTPException(403, "Refresh the page and try again.")
    return user


def require_admin(user: dict) -> None:
    if user["role"] != "admin":
        raise HTTPException(403, "Workspace admin access is required.")


def can_read_sql(alias: str = "d") -> str:
    if USE_POSTGRES:
        return f"({alias}.allowed_roles='everyone' OR position(',' || ? || ',' in ',' || {alias}.allowed_roles || ',') > 0)"
    return f"({alias}.allowed_roles='everyone' OR instr(','||{alias}.allowed_roles||',', ','||?||',') > 0)"


def allowed_roles(access: str) -> str:
    mapping = {"everyone": "everyone", "analyst": "admin,analyst", "admin": "admin"}
    if access not in mapping:
        raise HTTPException(400, "Choose Everyone, Analyst and admin, or Admin only.")
    return mapping[access]


def is_integrity_error(error: Exception) -> bool:
    return isinstance(error, sqlite3.IntegrityError) or error.__class__.__name__ in {
        "IntegrityError", "UniqueViolation", "ForeignKeyViolation", "CheckViolation"
    }


def vector_literal(vector: list[float] | None) -> str | None:
    if vector is None:
        return None
    return "[" + ",".join(format(value, ".8f") for value in vector) + "]"


def embed_texts(texts: list[str]) -> list[list[float]]:
    key = os.getenv("OPENAI_API_KEY")
    if not key or not texts:
        return []
    base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")
    vectors: list[list[float]] = []
    for start in range(0, len(texts), 64):
        payload = json.dumps({"model": model, "input": texts[start:start + 64]}).encode()
        request = urllib.request.Request(
            base + "/embeddings", data=payload,
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                result = json.loads(response.read())
            batch = sorted(result["data"], key=lambda row: row["index"])
            vectors.extend(row["embedding"] for row in batch)
        except (urllib.error.URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError):
            return []
        if len(vectors) != min(start + 64, len(texts)) or any(len(vector) != 1536 for vector in vectors):
            return []
    return vectors


def store_chunks(db, document_id: str, workspace_id: str, roles: str,
                 title: str, source: str, chunks: list[str],
                 embeddings: list[list[float]] | None = None) -> bool:
    if embeddings is None:
        embeddings = embed_texts(chunks)
    if len(embeddings) != len(chunks):
        embeddings = [None] * len(chunks)
    if USE_POSTGRES:
        db.executemany(
            "INSERT INTO chunks(document_id,workspace_id,allowed_roles,title,source,content,embedding) VALUES(?,?,?,?,?,?,?::vector)",
            [(document_id, workspace_id, roles, title, source, chunk, vector_literal(vector))
             for chunk, vector in zip(chunks, embeddings)],
        )
    else:
        db.executemany(
            "INSERT INTO chunks(document_id,workspace_id,allowed_roles,title,source,content,embedding_json) VALUES(?,?,?,?,?,?,?)",
            [(document_id, workspace_id, roles, title, source, chunk,
              json.dumps(vector) if vector is not None else None)
             for chunk, vector in zip(chunks, embeddings)],
        )
    return bool(embeddings and embeddings[0] is not None)


def split_chunks(text: str, size: int = 900, overlap: int = 120) -> list[str]:
    text = re.sub(r"\s+", " ", text).strip()
    chunks, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):
            boundary = text.rfind(" ", start + size // 2, end)
            if boundary > start:
                end = boundary
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(end - overlap, start + 1)
    return chunks


def extract_pdf_text(content: bytes) -> str:
    """Extract selectable text and repair common glyph-map artifacts in generated PDFs."""
    try:
        reader = PdfReader(BytesIO(content), strict=False)
        if reader.is_encrypted:
            raise HTTPException(415, "Encrypted PDFs can't be indexed.")
        if len(reader.pages) > 200:
            raise HTTPException(413, "PDFs may contain up to 200 pages.")
        text = "\n\n".join(page.extract_text() or "" for page in reader.pages)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(415, "This PDF could not be read. Please upload a valid PDF.") from exc
    # Repair characters emitted by PDFs whose fonts omit mappings for visible symbols.
    text = text.replace("\ufffd", "—").replace("\x7f", "•")
    text = re.sub(r"■(?=\s*\d)", "₹", text)
    return text


QUERY_STOPWORDS = {
    "a", "about", "an", "and", "are", "can", "could", "do", "does", "did",
    "for", "from", "how", "i", "in", "is", "it", "me", "of", "on", "please",
    "should", "tell", "that", "the", "this", "to", "was", "what", "when", "where",
    "which", "who", "why", "with", "would",
}


def fts_query(query: str, operator: str = "AND") -> str:
    tokens = [token for token in re.findall(r"[\w]+", query, flags=re.UNICODE)
              if token.casefold() not in QUERY_STOPWORDS]
    if not tokens:
        raise HTTPException(400, "Add a few words to your question.")
    if operator not in {"AND", "OR"}:
        raise ValueError("Unsupported search operator")
    return f" {operator} ".join('"' + token.replace('"', '""') + '"' for token in tokens[:16])


def source_grounded_excerpts(question: str, passages: list[dict]) -> str:
    terms = {token.casefold() for token in re.findall(r"[\w]+", question, flags=re.UNICODE)
             if token.casefold() not in QUERY_STOPWORDS}
    candidates = []
    for passage in passages:
        for sentence in re.split(r"(?<=[.!?])\s+|(?<=•)\s*", passage["content"]):
            sentence = sentence.strip(" \t\n•")
            if not sentence:
                continue
            words = {token.casefold() for token in re.findall(r"[\w]+", sentence, flags=re.UNICODE)}
            matched = terms & words
            if matched:
                score = len(matched) / max(1, len(terms)) + len(matched) * 0.1
                candidates.append((score, sentence))
    candidates.sort(key=lambda item: item[0], reverse=True)
    selected, seen = [], set()
    for _, sentence in candidates:
        key = sentence.casefold()
        if key not in seen:
            selected.append(sentence)
            seen.add(key)
        if len(selected) == 3:
            break
    if not selected:
        selected = [passages[0]["content"][:360].strip()]
    return "\n".join(selected)


def generate_answer(question: str, passages: list[dict]) -> tuple[str, str]:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return source_grounded_excerpts(question, passages), "Source-grounded excerpt · configure an LLM key for synthesized answers"
    base = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    system = "Answer using only the authorized source passages below. If they do not contain the answer, say so. Be concise and do not reveal access rules or hidden content. Cite source titles in square brackets."
    sources = "\n\n".join(f"[{p['title']}]\n{p['content']}" for p in passages)
    payload = json.dumps({"model": model, "messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": f"Question: {question}\n\nAuthorized passages:\n{sources}"},
    ], "temperature": 0.2}).encode()
    request = urllib.request.Request(base + "/chat/completions", data=payload,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.loads(response.read())
        return result["choices"][0]["message"]["content"], f"AI answer · {model} · authorized sources only"
    except (urllib.error.URLError, TimeoutError, KeyError, IndexError, json.JSONDecodeError):
        return source_grounded_excerpts(question, passages), "Source-grounded excerpt · AI provider unavailable"


@app.on_event("startup")
def startup() -> None:
    initialize()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_UPLOAD_BYTES + 100_000:
        raise HTTPException(413, "Request is too large.")
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response


@app.get("/")
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "keyline"}


@app.post("/api/auth/register")
async def register(request: Request):
    data = await request.json()
    name = str(data.get("name", "")).strip()[:80]
    workspace = str(data.get("workspace", "")).strip()[:80]
    email = str(data.get("email", "")).strip().lower()[:254]
    password = str(data.get("password", ""))
    if not name or not workspace or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter your name, workspace, and a valid email address.")
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(400, "Use a password with at least 12 characters.")
    password_hash, salt = make_password(password)
    user_id, workspace_id = secrets.token_hex(16), secrets.token_hex(16)
    try:
        with connect() as db:
            db.execute("INSERT INTO workspaces(id,name,created_at) VALUES(?,?,?)", (workspace_id, workspace, now_iso()))
            db.execute("INSERT INTO users(id,workspace_id,email,name,role,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (user_id, workspace_id, email, name, "admin", password_hash, salt, now_iso()))
    except Exception as exc:
        if is_integrity_error(exc):
            raise HTTPException(409, "An account with that email already exists in this workspace.")
        raise
    from fastapi.responses import JSONResponse
    result = JSONResponse({"ok": True})
    with connect() as db:
        csrf = issue_session(db, user_id, result)
    result.body = json.dumps({"ok": True, "csrf_token": csrf}).encode()
    result.headers["content-length"] = str(len(result.body))
    return result


@app.post("/api/auth/login")
async def login(request: Request):
    data = await request.json()
    email = str(data.get("email", "")).strip().lower()[:254]
    workspace = str(data.get("workspace", "")).strip()[:80]
    password = str(data.get("password", ""))
    ip = request.client.host if request.client else "unknown"
    recent = [stamp for stamp in LOGIN_ATTEMPTS.get(ip, []) if time.time() - stamp < 900]
    if len(recent) >= 10:
        raise HTTPException(429, "Too many sign-in attempts. Try again in 15 minutes.")
    LOGIN_ATTEMPTS[ip] = recent + [time.time()]
    with connect() as db:
        user = db.execute("""
            SELECT u.* FROM users u JOIN workspaces w ON w.id=u.workspace_id
            WHERE u.email=? AND lower(w.name)=lower(?)
        """, (email, workspace)).fetchone()
    if not user or not check_password(password, user["password_hash"], user["password_salt"]):
        raise HTTPException(401, "Email, workspace, or password is incorrect.")
    LOGIN_ATTEMPTS.pop(ip, None)
    from fastapi.responses import JSONResponse
    result = JSONResponse({"ok": True})
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
        csrf = issue_session(db, user["id"], result)
    result.body = json.dumps({"ok": True, "csrf_token": csrf}).encode()
    result.headers["content-length"] = str(len(result.body))
    return result


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return {"user": {k: user[k] for k in ("id", "name", "email", "role", "workspace_id", "workspace_name")},
            "csrf_token": user["csrf_token"]}


@app.post("/api/auth/logout")
def logout(request: Request, user: dict = Depends(authenticated_user)):
    token = request.cookies.get("keyline_session", "")
    with connect() as db:
        db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    from fastapi.responses import JSONResponse
    response = JSONResponse({"ok": True})
    response.delete_cookie("keyline_session", path="/")
    return response


@app.get("/api/workspace")
def workspace(user: dict = Depends(current_user)):
    with connect() as db:
        members = db.execute("SELECT id,name,email,role,created_at FROM users WHERE workspace_id=? ORDER BY name",
                             (user["workspace_id"],)).fetchall()
    return {"name": user["workspace_name"], "members": [dict(m) for m in members] if user["role"] == "admin" else []}


@app.post("/api/workspace/members")
async def add_member(request: Request, user: dict = Depends(authenticated_user)):
    require_admin(user)
    data = await request.json()
    name, email = str(data.get("name", "")).strip()[:80], str(data.get("email", "")).strip().lower()[:254]
    role, password = str(data.get("role", "member")), str(data.get("password", ""))
    if role not in ROLES - {"admin"} or not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(400, "Enter a valid name, email, and analyst or member role.")
    if len(password) < 12 or len(password) > 256:
        raise HTTPException(400, "Set a temporary password with at least 12 characters.")
    digest, salt = make_password(password)
    try:
        with connect() as db:
            db.execute("INSERT INTO users(id,workspace_id,email,name,role,password_hash,password_salt,created_at) VALUES(?,?,?,?,?,?,?,?)",
                       (secrets.token_hex(16), user["workspace_id"], email, name, role, digest, salt, now_iso()))
    except Exception as exc:
        if is_integrity_error(exc):
            raise HTTPException(409, "That email already belongs to a workspace member.")
        raise
    return {"ok": True}


@app.get("/api/documents")
def documents(user: dict = Depends(current_user)):
    predicate = can_read_sql("d")
    with connect() as db:
        rows = db.execute(f"""
            SELECT d.id,d.filename,d.title,d.allowed_roles,d.bytes,d.created_at,u.name AS uploaded_by
            FROM documents d JOIN users u ON u.id=d.owner_id
            WHERE d.workspace_id=? AND {predicate} ORDER BY d.created_at DESC
        """, (user["workspace_id"], user["role"])).fetchall()
    return {"documents": [dict(row) for row in rows]}


@app.post("/api/documents")
async def upload_document(file: UploadFile = File(...), access: str = Form("everyone"),
                          user: dict = Depends(authenticated_user)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".txt", ".md", ".markdown", ".pdf"}:
        raise HTTPException(415, "Upload a PDF, plain text, or Markdown file.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Files must be between 1 byte and 5 MB.")
    if suffix == ".pdf":
        text = extract_pdf_text(content)
    else:
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise HTTPException(415, "The file must contain UTF-8 text.")
    chunks = split_chunks(text)
    if not chunks:
        raise HTTPException(400, "This file has no readable text.")
    embeddings = embed_texts(chunks)
    roles = allowed_roles(access)
    document_id = secrets.token_hex(16)
    filename = Path(file.filename).name[:180]
    title = Path(filename).stem[:180]
    with connect() as db:
        db.execute("INSERT INTO documents(id,workspace_id,owner_id,filename,title,allowed_roles,bytes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (document_id, user["workspace_id"], user["id"], filename, title, roles, len(content), now_iso()))
        semantic_indexed = store_chunks(
            db, document_id, user["workspace_id"], roles, title, filename, chunks, embeddings
        )
    return {"ok": True, "id": document_id, "title": title, "chunks": len(chunks),
            "semantic_indexed": semantic_indexed}


@app.post("/api/documents/import-samples")
def import_sample_documents(user: dict = Depends(authenticated_user)):
    require_admin(user)
    sample_dir = ROOT / "sample-documents"
    imported, skipped = [], []
    prepared = []
    with connect() as db:
        existing = {row["filename"] for row in db.execute(
            "SELECT filename FROM documents WHERE workspace_id=?", (user["workspace_id"],)
        )}
    for filename, access in SAMPLE_DOCUMENT_ACCESS.items():
        if filename in existing:
            skipped.append(filename)
            continue
        path = sample_dir / filename
        if not path.is_file():
            raise HTTPException(503, f"Sample file is missing: {filename}")
        content = path.read_bytes()
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"Sample file exceeds the 5 MB limit: {filename}")
        text = extract_pdf_text(content)
        chunks = split_chunks(text)
        if not chunks:
            raise HTTPException(400, f"Sample file has no readable text: {filename}")
        prepared.append({
            "filename": filename, "access": access, "content": content,
            "chunks": chunks, "embeddings": embed_texts(chunks),
        })
    with connect() as db:
        for sample in prepared:
            filename = sample["filename"]
            roles = allowed_roles(sample["access"])
            chunks = sample["chunks"]
            document_id = secrets.token_hex(16)
            title = Path(filename).stem
            db.execute(
                "INSERT INTO documents(id,workspace_id,owner_id,filename,title,allowed_roles,bytes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (document_id, user["workspace_id"], user["id"], filename, title, roles,
                 len(sample["content"]), now_iso()),
            )
            semantic_indexed = store_chunks(
                db, document_id, user["workspace_id"], roles, title, filename, chunks, sample["embeddings"]
            )
            imported.append({"filename": filename, "chunks": len(chunks),
                             "access": sample["access"], "semantic_indexed": semantic_indexed})
    return {"ok": True, "imported": imported, "skipped": skipped}


@app.delete("/api/documents/{document_id}")
def delete_document(document_id: str, user: dict = Depends(authenticated_user)):
    require_admin(user)
    with connect() as db:
        cursor = db.execute("DELETE FROM documents WHERE id=? AND workspace_id=?", (document_id, user["workspace_id"]))
        if cursor.rowcount == 0:
            raise HTTPException(404, "Document not found in this workspace.")
    return {"ok": True}


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or len(left) != len(right):
        return -1.0
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(a * a for a in left))
    right_norm = math.sqrt(sum(b * b for b in right))
    return dot / (left_norm * right_norm) if left_norm and right_norm else -1.0


def lexical_passages(db, query: str, user: dict):
    access = can_read_sql("c")
    for operator in ("AND", "OR"):
        expression = fts_query(query, operator)
        if USE_POSTGRES:
            rows = db.execute(f"""
                SELECT c.id,c.document_id,c.title,c.source,c.content,
                       ts_rank_cd(c.search_vector, websearch_to_tsquery('simple', ?)) AS relevance
                FROM chunks c
                WHERE c.search_vector @@ websearch_to_tsquery('simple', ?)
                  AND c.workspace_id=? AND {access}
                ORDER BY relevance DESC LIMIT 16
            """, (expression, expression, user["workspace_id"], user["role"])).fetchall()
        else:
            rows = db.execute(f"""
                SELECT c.id,c.document_id,c.title,c.source,c.content,bm25(chunks_fts) AS relevance
                FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid
                WHERE chunks_fts MATCH ? AND c.workspace_id=? AND {access}
                ORDER BY relevance LIMIT 16
            """, (expression, user["workspace_id"], user["role"])).fetchall()
        if rows:
            return rows
    return []


def semantic_passages(db, query_vector: list[float] | None, user: dict):
    if not query_vector:
        return []
    access = can_read_sql("c")
    if USE_POSTGRES:
        vector = vector_literal(query_vector)
        return db.execute(f"""
            SELECT c.id,c.document_id,c.title,c.source,c.content,
                   1 - (c.embedding <=> ?::vector) AS semantic_relevance
            FROM chunks c
            WHERE c.workspace_id=? AND {access} AND c.embedding IS NOT NULL
            ORDER BY c.embedding <=> ?::vector LIMIT 16
        """, (vector, user["workspace_id"], user["role"], vector)).fetchall()
    rows = db.execute(f"""
        SELECT c.id,c.document_id,c.title,c.source,c.content,c.embedding_json
        FROM chunks c
        WHERE c.workspace_id=? AND {access} AND c.embedding_json IS NOT NULL
    """, (user["workspace_id"], user["role"])).fetchall()
    scored = []
    for row in rows:
        passage = dict(row)
        try:
            passage["semantic_relevance"] = cosine_similarity(
                json.loads(passage.pop("embedding_json")), query_vector
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        scored.append(passage)
    return sorted(scored, key=lambda passage: passage["semantic_relevance"], reverse=True)[:16]


@app.post("/api/ask")
async def ask(request: Request, user: dict = Depends(authenticated_user)):
    data = await request.json()
    query = str(data.get("query", "")).strip()[:500]
    if len(query) < 3:
        raise HTTPException(400, "Ask a question with at least three characters.")
    query_vectors = embed_texts([query])
    query_vector = query_vectors[0] if query_vectors else None
    # Authorization predicates run in the database retrieval query. Only these passages
    # are eligible to reach the optional language model below.
    with connect() as db:
        lexical = [dict(row) for row in lexical_passages(db, query, user)]
        semantic = [dict(row) for row in semantic_passages(db, query_vector, user)]
        lexical_scores = {row["id"]: 1.0 / (index + 1) for index, row in enumerate(lexical)}
        semantic_scores = {
            row["id"]: max(0.0, min(1.0, (float(row["semantic_relevance"]) + 1.0) / 2.0))
            for row in semantic
        }
        passage_by_id = {row["id"]: row for row in lexical + semantic}
        candidate_ids = set(lexical_scores) | set(semantic_scores)
        passages = sorted(
            (passage_by_id[row_id] for row_id in candidate_ids),
            key=lambda row: 0.7 * semantic_scores.get(row["id"], 0.0)
                 + 0.3 * lexical_scores.get(row["id"], 0.0),
            reverse=True,
        )[:5]
        passages = [{key: value for key, value in row.items()
                     if key not in {"id", "relevance", "semantic_relevance"}}
                    for row in passages]
        document_ids = list(dict.fromkeys(row["document_id"] for row in passages))
        db.execute("INSERT INTO audit_log(workspace_id,user_id,query,retrieved_document_ids,created_at) VALUES(?,?,?,?,?)",
                   (user["workspace_id"], user["id"], query, json.dumps(document_ids), now_iso()))
    if not passages:
        return {"answer": "I couldn't find an accessible document matching that question. Try different terms or add a document to your workspace.", "sources": [], "mode": "No matching sources"}
    answer, mode = generate_answer(query, passages)
    mode += " · " + ("hybrid semantic + keyword retrieval" if semantic else "keyword retrieval")
    deduped = []
    seen = set()
    for passage in passages:
        if passage["document_id"] not in seen:
            seen.add(passage["document_id"])
            deduped.append({"id": passage["document_id"], "title": passage["title"], "source": passage["source"]})
    return {"answer": answer, "sources": deduped, "mode": mode}


@app.get("/api/audit")
def audit(user: dict = Depends(current_user)):
    with connect() as db:
        rows = db.execute("""
            SELECT a.id,a.query,a.retrieved_document_ids,a.created_at,u.name AS user_name
            FROM audit_log a JOIN users u ON u.id=a.user_id
            WHERE a.workspace_id=? AND (?='admin' OR a.user_id=?)
            ORDER BY a.id DESC LIMIT 30
        """, (user["workspace_id"], user["role"], user["id"])).fetchall()
    return {"events": [{"id": row["id"], "query": row["query"],
            "source_count": len(json.loads(row["retrieved_document_ids"])),
            "created_at": row["created_at"], "user_name": row["user_name"]} for row in rows]}
