import json
import os
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from openai import OpenAI
from pydantic import BaseModel, ValidationError

load_dotenv()

API_KEY=<baseten_key>
BASE_URL=<baseten_openai_base_url>
MODEL_NAME=<muse_spark_open_1026>
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if origin.strip()
]

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "index.html"


class LazyOpenAIClient:
    def __init__(self):
        self._client = None

    def _ensure(self):
        missing = []
        if not API_KEY:
            missing.append("API_KEY")
        if not BASE_URL:
            missing.append("BASE_URL")
        if not MODEL_NAME:
            missing.append("MODEL_NAME")
        if missing:
            raise RuntimeError(
                "Missing required environment variable(s) for the OpenAI-compatible client: "
                + ", ".join(missing)
            )

        if self._client is None:
            self._client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
        return self._client

    def __getattr__(self, name):
        return getattr(self._ensure(), name)


client = LazyOpenAIClient()
app = FastAPI(title="SentryVision", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    solidity_code: str


class Finding(BaseModel):
    title: str
    severity: Literal["Critical", "High", "Medium", "Low", "Info"]
    what_happens: str
    why_it_matters: str
    what_to_do: str
    mermaid_diagram: str


class AuditResponse(BaseModel):
    summary: str
    findings: list[Finding]


RATE_LIMIT_WINDOW = timedelta(minutes=1)
MAX_REQUESTS_PER_WINDOW = 6
request_history: dict[str, deque[datetime]] = defaultdict(deque)


def enforce_rate_limit(client_ip: str) -> None:
    now = datetime.utcnow()
    history = request_history[client_ip]

    while history and now - history[0] > RATE_LIMIT_WINDOW:
        history.popleft()

    if len(history) >= MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. Please try again later.",
        )

    history.append(now)


def parse_and_validate_model_output(raw_content):
    if raw_content is None:
        raise ValueError("Model returned no content")

    try:
        parsed = json.loads(raw_content) if isinstance(raw_content, str) else raw_content
        if not isinstance(parsed, dict):
            raise ValueError("Model output is not a JSON object")
        return AuditResponse.model_validate(parsed)
    except (TypeError, ValueError, ValidationError):
        raise


@app.get("/")
async def serve_frontend():
    """Serve the single-page UI from the same origin as /analyze."""
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return FileResponse(INDEX_FILE)


@app.post("/analyze")
async def analyze_contract(request: Request, payload: AuditRequest):
    client_ip = request.client.host if request.client else "unknown"
    enforce_rate_limit(client_ip)

    if len(payload.solidity_code) > 60000:
        raise HTTPException(
            status_code=413,
            detail="Solidity input exceeds the maximum allowed length.",
        )

    try:
        model_client = client._ensure()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    system_prompt = """You are an expert Web3 security auditor helping a non-technical founder understand the risks in a Solidity contract.

    Review the entire contract and find every relevant vulnerability, not just the first one. Look for reentrancy, access control failures, unchecked external calls, unsafe arithmetic, bad state updates, front-running patterns, privilege escalation, and any other meaningful security issues in the code.

    Return valid JSON only in this exact shape:
    {
      "summary": "A short plain-language summary of the overall risk.",
      "findings": [
        {
          "title": "Short issue title",
          "severity": "Critical|High|Medium|Low|Info",
          "what_happens": "Plain-language explanation of how the issue happens.",
          "why_it_matters": "Plain-language explanation of why this matters to developers and non-technical founders.",
          "what_to_do": "Plain-language guidance on what to fix.",
          "mermaid_diagram": "A Mermaid flowchart string showing the exploit flow."
        }
      ]
    }

    Important rules:
    - Include every material issue you can identify, not just one.
    - Use plain language a developer and non-technical founder can understand.
    - Keep the response concise but complete.
    - Do not include markdown fences.
    - Use severity from this exact list only: Critical, High, Medium, Low, Info.
    - If there are no issues, return an empty findings array and a short summary.
    """

    for attempt in range(2):
        try:
            response = model_client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": payload.solidity_code},
                ],
                temperature=0.2,
                response_format={"type": "json_object"},
                timeout=60,
            )
            raw_content = response.choices[0].message.content
            validated = parse_and_validate_model_output(raw_content)
            return validated.model_dump()

        except (TypeError, ValueError, ValidationError):
            if attempt == 0:
                continue
            raise HTTPException(
                status_code=502,
                detail="Analysis could not be validated; please try again.",
            ) from None
        except Exception:
            if attempt == 0:
                continue
            raise HTTPException(
                status_code=502,
                detail="Analysis could not be validated; please try again.",
            ) from None

    raise HTTPException(
        status_code=502,
        detail="Analysis could not be validated; please try again.",
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
