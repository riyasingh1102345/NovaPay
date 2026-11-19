import ast

def test_no_unsafe_eval_or_sqli():
    with open("app.py", "r", encoding="utf-8") as f:
        code = f.read()
    active_section = code.split("# --- ACTIVE PRODUCTION ENDPOINTS ---")[-1]
    assert "eval(" not in active_section, "CWE-95: Unsafe eval() still present in active endpoints!"
    assert 'f"SELECT' not in active_section and "f'SELECT" not in active_section, "CWE-89: Raw SQL f-string still present!"
    ast.parse(code)
