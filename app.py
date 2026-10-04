"""Keyline: permission-aware, multi-tenant knowledge retrieval."""

from __future__ import annotations

import hashlib
import hmac
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

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_FILE = Path(os.getenv("DATABASE_PATH", str(ROOT / "storage" / "keyline.sqlite3")))
DB_FILE.parent.mkdir(parents=True, exist_ok=True)
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
SESSION_SECONDS = 7 * 24 * 60 * 60
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
ROLES = {"admin", "analyst", "member"}
LOGIN_ATTEMPTS: dict[str, list[float]] = {}

app = FastAPI(title="Keyline", version="1.0.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize() -> None:
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
                title TEXT NOT NULL, source TEXT NOT NULL, content TEXT NOT NULL
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
    return f"({alias}.allowed_roles='everyone' OR instr(','||{alias}.allowed_roles||',', ','||?||',') > 0)"


def allowed_roles(access: str) -> str:
    mapping = {"everyone": "everyone", "analyst": "admin,analyst", "admin": "admin"}
    if access not in mapping:
        raise HTTPException(400, "Choose Everyone, Analyst and admin, or Admin only.")
    return mapping[access]


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


def fts_query(query: str) -> str:
    tokens = re.findall(r"[\w]+", query, flags=re.UNICODE)
    if not tokens:
        raise HTTPException(400, "Add a few words to your question.")
    return " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens[:16])


def generate_answer(question: str, passages: list[dict]) -> tuple[str, str]:
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        excerpt = "\n\n".join(f"{p['title']} — {p['content']}" for p in passages)
        return excerpt, "Source-grounded retrieval · configure an LLM key for synthesized answers"
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
        excerpt = "\n\n".join(f"{p['title']} — {p['content']}" for p in passages)
        return excerpt, "Source-grounded retrieval · AI provider unavailable; showing authorized excerpts"


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
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email already exists in this workspace.")
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
            WHERE u.email=? AND w.name=? COLLATE NOCASE
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
    except sqlite3.IntegrityError:
        raise HTTPException(409, "That email already belongs to a workspace member.")
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
    if file.filename is None or Path(file.filename).suffix.lower() not in {".txt", ".md", ".markdown"}:
        raise HTTPException(415, "Upload a plain text or Markdown file (.txt, .md).")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Files must be between 1 byte and 5 MB.")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(415, "The file must contain UTF-8 text.")
    chunks = split_chunks(text)
    if not chunks:
        raise HTTPException(400, "This file has no readable text.")
    roles = allowed_roles(access)
    document_id = secrets.token_hex(16)
    filename = Path(file.filename).name[:180]
    title = Path(filename).stem[:180]
    with connect() as db:
        db.execute("INSERT INTO documents(id,workspace_id,owner_id,filename,title,allowed_roles,bytes,created_at) VALUES(?,?,?,?,?,?,?,?)",
                   (document_id, user["workspace_id"], user["id"], filename, title, roles, len(content), now_iso()))
        db.executemany("INSERT INTO chunks(document_id,workspace_id,allowed_roles,title,source,content) VALUES(?,?,?,?,?,?)",
                       [(document_id, user["workspace_id"], roles, title, filename, chunk) for chunk in chunks])
    return {"ok": True, "id": document_id, "title": title, "chunks": len(chunks)}


@app.delete("/api/documents/{document_id}")
def delete_document(document_id: str, user: dict = Depends(authenticated_user)):
    require_admin(user)
    with connect() as db:
        cursor = db.execute("DELETE FROM documents WHERE id=? AND workspace_id=?", (document_id, user["workspace_id"]))
        if cursor.rowcount == 0:
            raise HTTPException(404, "Document not found in this workspace.")
    return {"ok": True}


@app.post("/api/ask")
async def ask(request: Request, user: dict = Depends(authenticated_user)):
    data = await request.json()
    query = str(data.get("query", "")).strip()[:500]
    if len(query) < 3:
        raise HTTPException(400, "Ask a question with at least three characters.")
    match = fts_query(query)
    # Authorization predicates run in the database retrieval query. Only these passages
    # are eligible to reach the optional language model below.
    with connect() as db:
        rows = db.execute("""
            SELECT c.document_id,c.title,c.source,c.content,bm25(chunks_fts) AS relevance
            FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid
            WHERE chunks_fts MATCH ? AND c.workspace_id=?
              AND (c.allowed_roles='everyone' OR instr(','||c.allowed_roles||',', ','||?||',') > 0)
            ORDER BY relevance LIMIT 8
        """, (match, user["workspace_id"], user["role"])).fetchall()
        passages = [dict(row) for row in rows]
        document_ids = list(dict.fromkeys(row["document_id"] for row in passages))
        db.execute("INSERT INTO audit_log(workspace_id,user_id,query,retrieved_document_ids,created_at) VALUES(?,?,?,?,?)",
                   (user["workspace_id"], user["id"], query, json.dumps(document_ids), now_iso()))
    if not passages:
        return {"answer": "I couldn't find an accessible document matching that question. Try different terms or add a document to your workspace.", "sources": [], "mode": "No matching sources"}
    answer, mode = generate_answer(query, passages)
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

