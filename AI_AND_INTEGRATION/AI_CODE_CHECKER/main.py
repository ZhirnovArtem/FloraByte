import asyncio
import json

from services.ai_service import AIServiceError, analyze_findings


async def main():
    test_findings = [
        {
            "rule_id": "HARDCODED_PASSWORD",
            "file": "src/main/App.kt",
            "line": 42,
            "severity": "HIGH",
            "message": "Hardcoded password detected",
            "evidence": "password = [REDACTED]",
        }
    ]

    try:
        result = await analyze_findings(test_findings)
    except AIServiceError as exc:
        print(f"Ошибка AI-анализа: {exc}")
        raise SystemExit(1) from exc

    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
