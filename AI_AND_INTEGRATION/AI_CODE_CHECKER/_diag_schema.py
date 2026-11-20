from schemas.ai import SecurityFinding

print("config:", SecurityFinding.model_config)

def check(label, payload):
    try:
        SecurityFinding.model_validate(payload)
        print(f"{label}: ACCEPTED")
    except Exception as e:
        print(f"{label}: REJECTED ({type(e).__name__})")

base = {"rule_id": "R", "file": "f", "severity": "HIGH", "message": "m"}

check("blank_rule_id",  {**base, "rule_id": "   "})
check("blank_message",  {**base, "message": "   "})
check("extra_field",    {**base, "extra": "x"})
check("line_zero",      {**base, "line": 0})
check("line_neg",       {**base, "line": -1})
check("line_true",      {**base, "line": True})
check("line_str",       {**base, "line": "42"})
check("line_float",     {**base, "line": 1.5})