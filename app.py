import ast
import operator
import sqlite3
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

app = FastAPI(title="NovaPay — Target Web Application")

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


CHAOS_STATE = {
    "cwe_95_rce": True,
    "cwe_89_sqli": True,
    "cwe_693_headers": True,
}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    if not CHAOS_STATE["cwe_693_headers"]:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rce_on = CHAOS_STATE["cwe_95_rce"]
    sqli_on = CHAOS_STATE["cwe_89_sqli"]
    hdr_on = CHAOS_STATE["cwe_693_headers"]
    total_bugs = sum([rce_on, sqli_on, hdr_on])

    status_badge = (
        f'<span class="badge bad">● {total_bugs} Active Vulnerabilities</span>'
        if total_bugs > 0
        else '<span class="badge ok">✓ All Vulnerabilities Healed</span>'
    )

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <title>NovaPay Cloud — Live Target App</title>
      <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: system-ui, sans-serif; background: #f8fafc; color: #0f172a; padding: 32px 20px; }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 18px; border-bottom: 1px solid #e2e8f0; }}
        h1 {{ font-size: 22px; font-weight: 700; }}
        .sub {{ font-size: 13.5px; color: #64748b; margin-top: 3px; }}
        .badge {{ padding: 6px 12px; border-radius: 99px; font-size: 12.5px; font-weight: 600; }}
        .badge.bad {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}
        .badge.ok {{ background: #ecfdf5; color: #047857; border: 1px solid #a7f3d0; }}
        .chaos-panel {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 22px; }}
        .chaos-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }}
        .chaos-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }}
        .bug-card {{ border: 1px solid #e2e8f0; border-radius: 9px; padding: 14px; background: #f8fafc; }}
        .bug-card.active {{ border-color: #fca5a5; background: #fef2f2; }}
        .bug-title {{ font-size: 13px; font-weight: 700; margin-bottom: 4px; }}
        .bug-desc {{ font-size: 12px; color: #475569; margin-bottom: 12px; }}
        .btn {{ padding: 8px 13px; border-radius: 7px; font-size: 12.5px; font-weight: 600; cursor: pointer; border: 1px solid #cbd5e1; background: #fff; color: #0f172a; }}
        .btn-danger {{ background: #dc2626; color: #fff; border-color: #dc2626; }}
        .btn-heal {{ background: #047857; color: #fff; border-color: #047857; }}
        .app-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; }}
        input {{ width: 100%; padding: 9px 11px; border: 1px solid #cbd5e1; border-radius: 7px; font-size: 13px; margin: 10px 0; }}
        .exploit-tip {{ font-family: monospace; font-size: 11.5px; background: #f1f5f9; padding: 7px 10px; border-radius: 6px; margin-top: 8px; }}
        pre#output {{ margin-top: 20px; background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 10px; font-size: 12.5px; overflow-x: auto; min-height: 90px; }}
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <div>
            <h1>NovaPay Cloud — Live Target Application</h1>
            <p class="sub">Toggle security vulnerabilities live and test PatchBot's autonomous remediation.</p>
          </div>
          {status_badge}
        </header>

        <div class="chaos-panel">
          <div class="chaos-head">
            <strong>Chaos Fault-Injection Controls</strong>
            <div style="display:flex;gap:8px;">
              <form action="/chaos/inject-all" method="post"><button class="btn btn-danger" type="submit">Inject All Bugs</button></form>
              <form action="/chaos/heal-all" method="post"><button class="btn btn-heal" type="submit">Heal All Bugs</button></form>
            </div>
          </div>
          <div class="chaos-grid">
            <div class="bug-card {'active' if rce_on else ''}">
              <div class="bug-title">CWE-95: Unsafe eval() RCE</div>
              <div class="bug-desc">Status: <strong>{'INJECTED (Vulnerable)' if rce_on else 'PATCHED (AST Guarded)'}</strong></div>
              <form action="/chaos/toggle/cwe_95_rce" method="post"><button class="btn" type="submit">{'Fix CWE-95' if rce_on else 'Inject CWE-95'}</button></form>
            </div>
            <div class="bug-card {'active' if sqli_on else ''}">
              <div class="bug-title">CWE-89: SQL Injection</div>
              <div class="bug-desc">Status: <strong>{'INJECTED (Raw SQL)' if sqli_on else 'PATCHED (Parameterized)'}</strong></div>
              <form action="/chaos/toggle/cwe_89_sqli" method="post"><button class="btn" type="submit">{'Fix CWE-89' if sqli_on else 'Inject CWE-89'}</button></form>
            </div>
            <div class="bug-card {'active' if hdr_on else ''}">
              <div class="bug-title">CWE-693: Missing Headers</div>
              <div class="bug-desc">Status: <strong>{'INJECTED (No CSP/HSTS)' if hdr_on else 'PATCHED (Headers Active)'}</strong></div>
              <form action="/chaos/toggle/cwe_693_headers" method="post"><button class="btn" type="submit">{'Fix Headers' if hdr_on else 'Inject Missing Headers'}</button></form>
            </div>
          </div>
        </div>

        <div class="app-grid">
          <div class="card">
            <h3>1. Account Balance Lookup (CWE-89)</h3>
            <div class="exploit-tip">Payload: <strong>' OR '1'='1</strong></div>
            <form onsubmit="runTest(event, '/api/account', 'owner')">
              <input type="text" id="owner" value="' OR '1'='1" />
              <button class="btn" type="submit">Query Account</button>
            </form>
          </div>
          <div class="card">
            <h3>2. Tax & Fee Calculator (CWE-95)</h3>
            <div class="exploit-tip">Payload: <strong>__import__('os').getcwd()</strong></div>
            <form onsubmit="runTest(event, '/api/calc', 'formula')">
              <input type="text" id="formula" value="__import__('os').getcwd()" />
              <button class="btn" type="submit">Run Calculation</button>
            </form>
          </div>
        </div>

        <pre id="output">// Response telemetry will appear here...</pre>
      </div>
      <script>
        async function runTest(e, endpoint, fieldId) {{
          e.preventDefault();
          const formData = new URLSearchParams();
          formData.append(fieldId, document.getElementById(fieldId).value);
          const res = await fetch(endpoint, {{ method: 'POST', body: formData }});
          document.getElementById('output').textContent = JSON.stringify(await res.json(), null, 2);
        }}
      </script>
    </body>
    </html>
    """


@app.post("/chaos/toggle/{bug_key}")
def toggle_bug(bug_key: str):
    if bug_key in CHAOS_STATE:
        CHAOS_STATE[bug_key] = not CHAOS_STATE[bug_key]
    return RedirectResponse("/", status_code=303)


@app.post("/chaos/inject-all")
def inject_all():
    for k in CHAOS_STATE:
        CHAOS_STATE[k] = True
    return RedirectResponse("/", status_code=303)


@app.post("/chaos/heal-all")
def heal_all():
    for k in CHAOS_STATE:
        CHAOS_STATE[k] = False
    return RedirectResponse("/", status_code=303)


@app.post("/api/account")
def get_account(owner: str = Form(...)):
    if CHAOS_STATE["cwe_89_sqli"]:
        query = f"SELECT id, owner, tier, balance FROM accounts WHERE owner = '{owner}'"
        rows = conn.execute(query).fetchall()
        return {"mode": "VULNERABLE (CWE-89)", "query": query, "leaked_records": rows}
    rows = conn.execute("SELECT id, owner, tier, balance FROM accounts WHERE owner = ?", (owner,)).fetchall()
    return {"mode": "PROTECTED (Parameterized SQL)", "matched_records": rows}


@app.post("/api/calc")
def calc_fee(formula: str = Form(...)):
    if CHAOS_STATE["cwe_95_rce"]:
        try:
            return {"mode": "VULNERABLE (CWE-95)", "result": str(eval(formula))}
        except Exception as e:
            return JSONResponse(status_code=400, content={"error": str(e)})
    try:
        return {"mode": "PROTECTED (AST Safe Evaluator)", "result": safe_eval_math(formula)}
    except Exception as e:
        return JSONResponse(status_code=400, content={"blocked": True, "reason": str(e)})