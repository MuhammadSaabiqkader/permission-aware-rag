from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "rag_demo.db"
LOCK = threading.Lock()
SESSIONS: dict[str, str] = {}
USERS = {
    "maya": {"name": "Maya Chen", "role": "analyst", "tenant": "northstar"},
    "leo": {"name": "Leo Park", "role": "member", "tenant": "northstar"},
    "admin": {"name": "Ari Patel", "role": "admin", "tenant": "northstar"},
    "nina": {"name": "Nina Shah", "role": "analyst", "tenant": "bluepeak"},
}

SEED = [
    ("northstar", "everyone", "Getting started", "Northstar's support team handles account setup, billing questions, and product access. Standard support hours are Monday through Friday, 9 AM to 5 PM.", "Company handbook"),
    ("northstar", "analyst,admin", "Q3 customer trends", "Northstar saw 18% quarter-over-quarter growth in active teams in Q3. Most new customers came from healthcare and education. The median onboarding time was 6 days.", "Q3 analytics report"),
    ("northstar", "admin", "Internal incident review", "Incident N-204 was caused by an expired database certificate. No customer records were exposed. The certificate rotation checklist now requires a second reviewer.", "Security review"),
    ("bluepeak", "everyone", "BluePeak product overview", "BluePeak helps logistics teams coordinate deliveries, monitor fleet status, and notify customers about shipment changes.", "Product guide"),
    ("bluepeak", "analyst,admin", "BluePeak monthly metrics", "BluePeak processed 42,000 deliveries in September. On-time delivery reached 96%, up 3 percentage points from August. The busiest region was the Pacific Northwest.", "Operations report"),
]


def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    with connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
                allowed_roles TEXT NOT NULL, title TEXT NOT NULL,
                content TEXT NOT NULL, source TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY, created_at TEXT NOT NULL,
                user_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
                query TEXT NOT NULL, retrieved_ids TEXT NOT NULL
            );
        """)
        if db.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 0:
            db.executemany("INSERT INTO documents(tenant_id,allowed_roles,title,content,source) VALUES(?,?,?,?,?)", SEED)


def page():
    return r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Keyline · Secure knowledge</title><style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600;700&display=swap');
:root{color-scheme:dark;--bg:#101412;--panel:#171d19;--line:#28332c;--text:#e9eee9;--muted:#95a198;--green:#b6ef76;--soft:#223021}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0%,#202c20 0,transparent 38%),var(--bg);font:15px 'DM Sans',sans-serif;color:var(--text);min-height:100vh}.wrap{max-width:1120px;margin:auto;padding:36px 28px 60px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:22px}.brand{display:flex;gap:12px;align-items:center;font-size:17px;font-weight:700;letter-spacing:-.4px}.mark{width:35px;height:35px;border-radius:10px;background:var(--green);color:#152011;display:grid;place-items:center;font-weight:800}.badge{font:11px 'DM Mono';padding:7px 10px;border:1px solid #354438;border-radius:20px;color:#c9dbca}.hero{padding:48px 0 32px;max-width:690px}.eyebrow{font:11px 'DM Mono';color:var(--green);letter-spacing:1.6px;text-transform:uppercase}.hero h1{font-size:clamp(34px,5vw,54px);letter-spacing:-2px;line-height:1.04;margin:13px 0}.hero p{color:var(--muted);font-size:16px;line-height:1.65;margin:15px 0 0}.layout{display:grid;grid-template-columns:270px 1fr;gap:18px}.card{background:linear-gradient(145deg,#1b221d,#151a17);border:1px solid var(--line);border-radius:16px;padding:22px}.card h2{font-size:13px;text-transform:uppercase;letter-spacing:1px;color:#bdc8bf;margin:0 0 17px}.label{font:10px 'DM Mono';text-transform:uppercase;letter-spacing:1px;color:var(--muted);display:block;margin:16px 0 7px}select,textarea{width:100%;background:#101512;border:1px solid #344037;color:var(--text);border-radius:9px;padding:12px;font:14px 'DM Sans';outline:none}select:focus,textarea:focus{border-color:var(--green)}.identity{padding:14px;background:#111712;border:1px solid var(--line);border-radius:11px;margin-top:14px}.name{font-weight:600}.meta{font:11px 'DM Mono';color:var(--muted);margin-top:6px}.chip{display:inline-block;background:#263225;color:var(--green);font:10px 'DM Mono';padding:5px 8px;border-radius:20px;margin:10px 5px 0 0}.note{font-size:12px;color:var(--muted);line-height:1.55;margin-top:18px}.main{min-height:460px}.promptbox{display:flex;gap:12px;align-items:stretch}textarea{resize:vertical;min-height:90px;line-height:1.5;flex:1}button{border:0;background:var(--green);color:#182114;border-radius:9px;padding:0 18px;font:600 13px 'DM Sans';cursor:pointer}button:hover{background:#ccf69e}button:disabled{opacity:.5;cursor:wait}.examples{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0 25px}.example{background:#1a211c;border:1px solid var(--line);border-radius:20px;padding:7px 10px;color:#c7d1c9;font-size:11px;cursor:pointer}.answer{border-top:1px solid var(--line);padding-top:22px}.empty{text-align:center;color:var(--muted);padding:58px 12px}.empty .icon{font-size:26px;color:var(--green);margin-bottom:10px}.answertext{font-size:16px;line-height:1.7;white-space:pre-wrap}.sources{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;margin-top:18px}.source{border:1px solid var(--line);background:#111612;border-radius:10px;padding:12px}.source strong{font-size:12px;display:block}.source small{font:10px 'DM Mono';color:var(--muted);display:block;margin-top:6px}.stats{display:flex;gap:8px;flex-wrap:wrap;margin:19px 0 0}.stat{font:10px 'DM Mono';border:1px solid var(--line);padding:7px 9px;border-radius:8px;color:#b8c6ba}.error{color:#ffab9c}.audit{margin-top:18px}.audit-row{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:11px 0;font-size:12px;gap:12px}.audit-row span:last-child{font:10px 'DM Mono';color:var(--muted);text-align:right}.hidden{display:none}@media(max-width:760px){.wrap{padding:20px 15px}.layout{grid-template-columns:1fr}.hero{padding:34px 0 24px}.sidebar{order:0}.main{order:1}.promptbox{flex-direction:column}.promptbox button{padding:13px}.top{padding-bottom:16px}}
</style></head><body><div class="wrap"><header class="top"><div class="brand"><div class="mark">K</div>keyline <span style="font-weight:400;color:var(--muted)">/ secure knowledge</span></div><div class="badge">LOCAL DEMO · TENANT ISOLATION ON</div></header><section class="hero"><div class="eyebrow">Permission-aware retrieval</div><h1>Your team's knowledge.<br>Only your team's.</h1><p>Ask a question and see access controls applied before retrieval. Every answer includes source citations and an audit trail.</p></section><div class="layout"><aside class="card sidebar"><h2>Session identity</h2><label class="label" for="user">Act as demo user</label><select id="user"><option value="maya">Maya Chen · Northstar analyst</option><option value="leo">Leo Park · Northstar member</option><option value="admin">Ari Patel · Northstar admin</option><option value="nina">Nina Shah · BluePeak analyst</option></select><div class="identity"><div class="name" id="displayname">Maya Chen</div><div class="meta" id="tenant">northstar</div><span class="chip" id="role">ANALYST</span><span class="chip">DEMO ACCOUNT</span></div><p class="note">This selector simulates identity for a local demo. In production, identity must come from a verified authentication provider; never trust a client-supplied user or tenant ID.</p></aside><main class="card main"><h2>Ask your knowledge base</h2><div class="promptbox"><textarea id="query" placeholder="Ask about a report, policy, metric, or incident…"></textarea><button id="ask">Search securely ↗</button></div><div class="examples"><span class="example">What changed in Q3?</span><span class="example">Summarize the incident review</span><span class="example">What were September delivery metrics?</span></div><section id="result" class="answer"><div class="empty"><div class="icon">✳</div><div>Your answer will appear here, with the documents that informed it.</div></div></section><section class="audit"><h2>Recent retrieval audit</h2><div id="auditrows"><div class="meta">Audit events are recorded for this session.</div></div></section></main></div></div><script>
const users={maya:['Maya Chen','northstar','analyst'],leo:['Leo Park','northstar','member'],admin:['Ari Patel','northstar','admin'],nina:['Nina Shah','bluepeak','analyst']};const user=document.querySelector('#user');function ident(){const [n,t,r]=users[user.value];document.querySelector('#displayname').textContent=n;document.querySelector('#tenant').textContent=t;document.querySelector('#role').textContent=r.toUpperCase()}user.onchange=async()=>{ident();await fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:user.value})});loadAudit()};document.querySelectorAll('.example').forEach(x=>x.onclick=()=>{document.querySelector('#query').value=x.textContent;ask()});document.querySelector('#ask').onclick=ask;document.querySelector('#query').onkeydown=e=>{if(e.key==='Enter'&&(e.ctrlKey||e.metaKey))ask()};async function ask(){const q=document.querySelector('#query').value.trim();if(!q)return;const b=document.querySelector('#ask'),r=document.querySelector('#result');b.disabled=true;b.textContent='Searching…';r.innerHTML='<div class="meta">Applying tenant and role filters before retrieval…</div>';try{const res=await fetch('/api/ask',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({query:q})});const d=await res.json();if(!res.ok)throw Error(d.error||'Request failed');if(!d.sources.length){r.innerHTML='<div class="answertext">No accessible documents matched that question. Try another query or switch to a demo identity with broader access.</div><div class="stats"><span class="stat">0 authorized sources</span><span class="stat">Access filter applied before retrieval</span></div>';return}r.innerHTML='<div class="answertext">'+esc(d.answer)+'</div><div class="sources">'+d.sources.map(s=>'<div class="source"><strong>'+esc(s.title)+'</strong><small>'+esc(s.source)+' · '+esc(s.tenant)+'</small></div>').join('')+'</div><div class="stats"><span class="stat">'+d.sources.length+' authorized source'+(d.sources.length===1?'':'s')+'</span><span class="stat">Tenant + role filtered in SQL</span><span class="stat">Audit event recorded</span></div>'}catch(e){r.innerHTML='<div class="error">'+esc(e.message)+'</div>'}finally{b.disabled=false;b.textContent='Search securely ↗';loadAudit()}}function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}async function loadAudit(){const d=await(await fetch('/api/audit')).json();document.querySelector('#auditrows').innerHTML=d.events.length?d.events.map(x=>'<div class="audit-row"><span>'+esc(x.query)+'</span><span>'+esc(x.user)+' · '+x.count+' source(s)<br>'+esc(x.time)+'</span></div>').join(''):'<div class="meta">No retrievals yet.</div>'}fetch('/api/session',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:user.value})}).then(loadAudit);
</script></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = min(int(self.headers.get("Content-Length", "0")), 10000)
        return json.loads(self.rfile.read(length) or b"{}")

    def current_user(self):
        cookie = self.headers.get("Cookie", "")
        token = next((x.split("=", 1)[1] for x in cookie.split("; ") if x.startswith("sid=")), "")
        return SESSIONS.get(token)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            data = page().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        elif path == "/api/audit":
            user_id = self.current_user()
            if not user_id:
                return self.send_json({"events": []}, 401)
            user = USERS[user_id]
            with connect() as db:
                rows = db.execute("SELECT created_at,query,retrieved_ids FROM audit_log WHERE user_id=? AND tenant_id=? ORDER BY id DESC LIMIT 8", (user_id, user["tenant"])).fetchall()
            events = [{"time": x["created_at"], "query": x["query"], "count": len(json.loads(x["retrieved_ids"])), "user": user["name"]} for x in rows]
            self.send_json({"events": events})
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.body()
        except (ValueError, json.JSONDecodeError):
            return self.send_json({"error": "Invalid JSON"}, 400)
        if path == "/api/session":
            user_id = data.get("user")
            if user_id not in USERS:
                return self.send_json({"error": "Unknown demo identity"}, 400)
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = user_id
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"sid={token}; HttpOnly; SameSite=Strict; Path=/")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")
        elif path == "/api/ask":
            user_id = self.current_user()
            if not user_id:
                return self.send_json({"error": "Select a demo identity first"}, 401)
            query = str(data.get("query", "")).strip()[:500]
            if not query:
                return self.send_json({"error": "Enter a question"}, 400)
            user = USERS[user_id]
            terms = [w.lower() for w in query.split() if len(w) > 2]
            # Tenant and role authorization is enforced in SQL before content is returned to retrieval.
            with connect() as db:
                authorized = db.execute("SELECT id,tenant_id,allowed_roles,title,content,source FROM documents WHERE tenant_id=? AND (allowed_roles='everyone' OR instr(','||allowed_roles||',', ','||?||',') > 0)", (user["tenant"], user["role"])).fetchall()
                scored = []
                for doc in authorized:
                    words = set((doc["title"] + " " + doc["content"] + " " + doc["source"]).lower().replace("-", " ").split())
                    score = sum(1 for t in terms if t in words)
                    if score:
                        scored.append((score, doc))
                scored.sort(key=lambda item: item[0], reverse=True)
                picked = [d for _, d in scored[:3]]
                ids = [d["id"] for d in picked]
                now = datetime.now(timezone.utc).isoformat(timespec="seconds")
                db.execute("INSERT INTO audit_log(created_at,user_id,tenant_id,query,retrieved_ids) VALUES(?,?,?,?,?)", (now, user_id, user["tenant"], query, json.dumps(ids)))
                db.commit()
            if picked:
                answer = "Here are the most relevant details from documents you are allowed to access:\n\n" + "\n\n".join(f"{d['title']}: {d['content']}" for d in picked)
            else:
                answer = "No accessible document matched those keywords."
            self.send_json({"answer": answer, "sources": [{"title": d["title"], "source": d["source"], "tenant": d["tenant_id"]} for d in picked]})
        else:
            self.send_error(404)


if __name__ == "__main__":
    initialize()
    host, port = os.getenv("HOST", "127.0.0.1"), int(os.getenv("PORT", "8000"))
    print(f"Keyline demo running at http://{host}:{port}")
    print("Demo identities: Maya (analyst), Leo (member), Ari (admin), Nina (other tenant)")
    ThreadingHTTPServer((host, port), Handler).serve_forever()
