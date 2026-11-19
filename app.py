import ast
import operator
import sqlite3
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="NovaPay Cloud — Production Portal")

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT, tier TEXT, balance REAL)")
conn.executemany(
    "INSERT INTO accounts (owner, tier, balance) VALUES (?, ?, ?)",
    [
        ("khushi", "Enterprise", 48500.00),
        ("admin", "Root-Vault", 999999.00),
        ("rahul", "Standard", 3200.50),
    ],
)
conn.commit()

SAFE_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
}


def safe_eval_math(expr: str) -> float:
    def _eval(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPS:
            return SAFE_OPS[type(node.op)](_eval(node.left), _eval(node.right))
        if isinstance(node, ast.UnaryOp) and type(node.op) in SAFE_OPS:
            return SAFE_OPS[type(node.op)](_eval(node.operand))
        raise ValueError("Unsafe expression blocked by AST guard.")

    tree = ast.parse(expr.strip(), mode="eval")
    return _eval(tree.body)


def detect_active_flaws() -> dict:
    with open(__file__, "r", encoding="utf-8") as f:
        code = f.read()
    # Check only the active route implementations at the bottom of the file
    active_section = code.split("# --- ACTIVE PRODUCTION ENDPOINTS ---")[-1]
    return {
        "cwe_95": "eval(" in active_section,
        "cwe_89": "f\"SELECT" in active_section or "f'SELECT" in active_section,
    }


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard():
    flaws = detect_active_flaws()
    active_count = sum(flaws.values())

    if active_count > 0:
        return HTMLResponse(
            status_code=503,
            content="""
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="UTF-8" />
              <meta http-equiv="refresh" content="4" />
              <title>503 Service Crashed — NovaPay Cloud</title>
              <style>
                * { box-sizing: border-box; margin: 0; padding: 0; }
                body { font-family: 'Inter', system-ui, sans-serif; background: #09090b; color: #fafafa; display: grid; place-items: center; min-height: 100vh; padding: 24px; }
                .crash-box { max-width: 640px; width: 100%; background: #18181b; border: 1px solid #dc2626; border-radius: 14px; padding: 32px; box-shadow: 0 20px 50px rgba(220, 38, 38, 0.2); }
                .pill { display: inline-block; background: #450a0a; color: #fca5a5; border: 1px solid #dc2626; padding: 4px 12px; border-radius: 99px; font-size: 12px; font-weight: 700; margin-bottom: 16px; }
                h1 { font-size: 26px; font-weight: 700; color: #f87171; margin-bottom: 10px; }
                p { font-size: 14px; color: #a1a1aa; line-height: 1.6; margin-bottom: 18px; }
                .trace { background: #09090b; border: 1px solid #27272a; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 12px; color: #fca5a5; line-height: 1.6; margin-bottom: 18px; }
                .pulse { font-size: 12.5px; color: #fbbf24; font-weight: 600; }
              </style>
            </head>
            <body>
              <div class="crash-box">
                <div class="pill">HTTP 503 • CRITICAL SYSTEM CRASH</div>
                <h1>Web Application Crashed &amp; Offline</h1>
                <p>NovaPay Production Portal experienced a critical security breach and emergency shutdown due to unvalidated code injection in <code>app.py</code>. All user endpoints are suspended until PatchBot deploys a verified fix.</p>
                <div class="trace">
                  FATAL [SecurityWatchdog]: Uncaught CWE-95 (Arbitrary eval() RCE) &amp; CWE-89 (SQL Injection) detected in runtime!<br>
                  STATUS: Service Unavailable (503) — Production Traffic Halted.<br>
                  ACTION REQUIRED: Trigger PatchBot Remediation Agent on port 8000.
                </div>
                <div class="pulse">⟳ Auto-checking recovery status every 4 seconds... (Will restore automatically once PatchBot heals app.py)</div>
              </div>
            </body>
            </html>
            """,
        )

    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>NovaPay Cloud — Production Portal</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a; padding: 32px 20px; }
        .container { max-width: 960px; margin: 0 auto; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid #e2e8f0; }
        h1 { font-size: 22px; font-weight: 700; }
        .sub { font-size: 13.5px; color: #64748b; margin-top: 3px; }
        .badge.ok { padding: 6px 12px; border-radius: 99px; font-size: 12.5px; font-weight: 600; background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }
        .inject-panel { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 22px; display: flex; justify-content: space-between; align-items: center; }
        .btn { padding: 8px 14px; border-radius: 7px; font-size: 12.5px; font-weight: 600; cursor: pointer; border: 1px solid #cbd5e1; background: #fff; color: #0f172a; }
        .btn-danger { background: #dc2626; color: #fff; border-color: #dc2626; }
        .app-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; }
        input { width: 100%; padding: 9px 11px; border: 1px solid #cbd5e1; border-radius: 7px; font-size: 13px; margin: 10px 0; }
        .exploit-tip { font-family: monospace; font-size: 11.5px; background: #f1f5f9; padding: 7px 10px; border-radius: 6px; margin-top: 8px; }
        pre#output { margin-top: 20px; background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 10px; font-size: 12.5px; overflow-x: auto; min-height: 90px; }
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <div>
            <h1>NovaPay Cloud — Production Portal</h1>
            <p class="sub">Monitored externally by PatchBot Autonomous Security Agent.</p>
          </div>
          <span class="badge ok">✓ System Online &amp; Hardened (Protected by PatchBot)</span>
        </header>

        <div class="inject-panel">
          <div>
            <strong style="font-size:14.5px;">Simulate Production Breach &amp; Crash</strong>
            <div style="font-size:12.5px;color:#64748b;margin-top:2px;">Injects CWE-95 &amp; CWE-89 vulnerabilities into app.py, triggering an immediate 503 Web Crash until PatchBot heals it.</div>
          </div>
          <form action="/chaos/inject-flaws" method="post">
            <button class="btn btn-danger" type="submit">Inject Bug &amp; Crash Web</button>
          </form>
        </div>

        <div class="app-grid">
          <div class="card">
            <h3>1. Account Balance Lookup (Protected)</h3>
            <div class="exploit-tip">Test payload: <strong>' OR '1'='1</strong></div>
            <form onsubmit="runTest(event, '/api/account', 'owner')">
              <input type="text" id="owner" value="' OR '1'='1" />
              <button class="btn" type="submit">Query Account</button>
            </form>
          </div>
          <div class="card">
            <h3>2. Tax &amp; Fee Calculator (Protected)</h3>
            <div class="exploit-tip">Test payload: <strong>__import__('os').getcwd()</strong></div>
            <form onsubmit="runTest(event, '/api/calc', 'formula')">
              <input type="text" id="formula" value="__import__('os').getcwd()" />
              <button class="btn" type="submit">Run Calculation</button>
            </form>
          </div>
        </div>

        <pre id="output">// Response telemetry will appear here...</pre>
      </div>
      <script>
        async function runTest(e, endpoint, fieldId) {
          e.preventDefault();
          const formData = new URLSearchParams();
          formData.append(fieldId, document.getElementById(fieldId).value);
          const res = await fetch(endpoint, { method: 'POST', body: formData });
          document.getElementById('output').textContent = JSON.stringify(await res.json(), null, 2);
        }
      </script>
    </body>
    </html>
    """


@app.post("/chaos/inject-flaws")
def inject_flaws():
    with open(__file__, "r", encoding="utf-8") as f:
        code = f.read()

    marker = "# --- ACTIVE PRODUCTION ENDPOINTS ---"
    head, _ = code.split(marker, 1)

    vulnerable_endpoints = f"""{marker}
@app.post("/api/account")
def get_account(owner: str = Form(...)):
    query = f"SELECT id, owner, tier, balance FROM accounts WHERE owner = '{{owner}}'"
    rows = conn.execute(query).fetchall()
    return {{"mode": "VULNERABLE (CWE-89)", "query": query, "leaked_records": rows}}


@app.post("/api/calc")
def calc_fee(formula: str = Form(...)):
    try:
        return {{"mode": "VULNERABLE (CWE-95)", "result": str(eval(formula))}}
    except Exception as e:
        return JSONResponse(status_code=400, content={{"error": str(e)}})
"""
    with open(__file__, "w", encoding="utf-8") as f:
        f.write(head + vulnerable_endpoints)
    return RedirectResponse("/", status_code=303)


# --- ACTIVE PRODUCTION ENDPOINTS ---
@app.post("/api/account")
def get_account(owner: str = Form(...)):
    rows = conn.execute("SELECT id, owner, tier, balance FROM accounts WHERE owner = ?", (owner,)).fetchall()
    return {"mode": "PROTECTED (Parameterized SQL)", "matched_records": rows}


@app.post("/api/calc")
def calc_fee(formula: str = Form(...)):
    try:
        return {"mode": "PROTECTED (AST Safe Evaluator)", "result": safe_eval_math(formula)}
    except Exception as e:
        return JSONResponse(status_code=400, content={"blocked": True, "reason": str(e)})