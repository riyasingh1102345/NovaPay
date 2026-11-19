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
    return {}


# --- ACTIVE PRODUCTION ENDPOINTS ---
@app.post("/api/account")
def get_account(owner: str = Form(...)):
    query = "SELECT id, owner, tier, balance FROM accounts WHERE owner = ?"
    rows = conn.execute(query, (owner,)).fetchall()
    return {"mode": "SECURE", "query": query, "leaked_records": rows}


@app.post("/api/calc")
def calc_fee(formula: str = Form(...)):
    try:
        return {"mode": "SECURE", "result": str(safe_eval_math(formula))}
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(e)})