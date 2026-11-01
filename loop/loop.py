"""Generic agentic investigation loop.

The model chooses every tool call; nothing here is specific to one case.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scamaware import Pipeline, Settings

BASE_DIR = Path(__file__).resolve().parent
SYSTEM_PATH = str(BASE_DIR / "system instructions.md")
OBJECTIVE_PATH = str(BASE_DIR / "objective.md")
MEMO_PATH = str(BASE_DIR / "memo.md")

# complete(messages, tools) -> {"content": str, "tool_calls": [{"name": ..., "args": {...}}]}
Tool = Callable[[dict[str, Any]], str]
Complete = Callable[
    [list[dict[str, Any]], Mapping[str, Tool]], dict[str, Any]
]

TOOL_SPECS: dict[str, dict[str, Any]] = {
    "check_message": {
        "description": "Check a suspicious message and return its verdict, signals, and reply.",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
}


def check_message(args: dict[str, Any]) -> str:
    """Check one message with the scam-aware pipeline. Args: {"text": str}."""
    result = Pipeline().check(str(args.get("text", "")))
    return json.dumps(result.to_dict(), ensure_ascii=False)


def build_tools() -> dict[str, Tool]:
    """Tools the model may call. The model chooses when to call them."""
    return {"check_message": check_message}


def read_text(path: str | Path) -> str:
    """Read a text file, failing with a clear message when missing."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Missing input file: {p}")
    return p.read_text(encoding="utf-8")


def run_turn(
    messages: list[dict[str, Any]],
    complete: Complete,
    tools: Mapping[str, Tool],
) -> tuple[bool, str]:
    """Run one turn. Returns (done, text); done True carries the final answer."""
    response = complete(messages, tools)
    content = str(response.get("content", ""))
    calls = response.get("tool_calls", []) or []
    if not calls:
        messages.append({"role": "assistant", "content": content})
        return True, content
    messages.append({"role": "assistant", "content": content, "tool_calls": calls})
    for call in calls:
        name = str(call.get("name", ""))
        args = dict(call.get("args", {}) or {})
        func = tools.get(name)
        if func is None:
            result = f"Unknown tool: {name}"
        else:
            try:
                result = str(func(args))
            except Exception as exc:  # let the model see the failure and retry
                result = f"Tool {name} failed: {exc}"
        messages.append({"role": "tool", "name": name, "content": result})
    return False, ""


def run_loop(
    system: str,
    objective: str,
    complete: Complete,
    tools: Mapping[str, Tool],
    max_turns: int = 10,
) -> str:
    """Repeat turns until the model answers without tool calls or turns run out."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": objective},
    ]
    for _ in range(max_turns):
        done, text = run_turn(messages, complete, tools)
        if done:
            return text
    return f"Stopped after {max_turns} turns without a final answer."


def file_memo(findings: str, path: str | Path = MEMO_PATH) -> str:
    """File the findings memo. Returns the memo path."""
    p = Path(path)
    p.write_text(f"# Findings memo\n\n{findings}\n", encoding="utf-8")
    return str(p)


def run_agent(
    system: str,
    objective: str,
    complete: Complete,
    tools: Mapping[str, Tool],
    max_turns: int = 10,
    memo_path: str | Path = MEMO_PATH,
) -> tuple[str, str]:
    """Run the loop, then always file a memo with the findings."""
    try:
        findings = run_loop(system, objective, complete, tools, max_turns)
    except Exception as exc:
        memo = file_memo(f"Agent stopped with an error: {exc}", memo_path)
        raise RuntimeError(f"{exc} (memo filed at {memo})") from exc
    memo = file_memo(findings, memo_path)
    return findings, memo


def _openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Translate internal history to chat-completions messages with linked tool calls."""
    out: list[dict[str, Any]] = []
    pending: list[str] = []
    counter = 0
    for m in messages:
        role = str(m.get("role", ""))
        if role == "system":
            out.append({"role": "system", "content": str(m.get("content", ""))})
        elif role == "user":
            out.append({"role": "user", "content": str(m.get("content", ""))})
        elif role == "assistant":
            calls = m.get("tool_calls", []) or []
            if not calls:
                out.append({"role": "assistant", "content": str(m.get("content", ""))})
                continue
            tool_calls = []
            for call in calls:
                counter += 1
                tid = f"tc_{counter}"
                pending.append(tid)
                tool_calls.append(
                    {
                        "id": tid,
                        "type": "function",
                        "function": {
                            "name": str(call.get("name", "")),
                            "arguments": json.dumps(dict(call.get("args", {}) or {})),
                        },
                    }
                )
            out.append(
                {
                    "role": "assistant",
                    "content": str(m.get("content", "")) or None,
                    "tool_calls": tool_calls,
                }
            )
        elif role == "tool":
            tid = pending.pop(0) if pending else f"tc_{counter}"
            out.append({"role": "tool", "tool_call_id": tid, "content": str(m.get("content", ""))})
    return out


def _openai_tools(tools: Mapping[str, Tool]) -> list[dict[str, Any]]:
    """Translate tool specs to chat-completions function tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": TOOL_SPECS[name]["description"],
                "parameters": {
                    "type": "object",
                    "properties": TOOL_SPECS[name]["properties"],
                    "required": TOOL_SPECS[name].get("required", []),
                },
            },
        }
        for name in tools
        if name in TOOL_SPECS
    ]


def _parse_openai_response(data: dict[str, Any]) -> dict[str, Any]:
    """Parse a chat-completions response into {"content", "tool_calls"}."""
    choices = data.get("choices", []) or []
    message = choices[0].get("message", {}) if choices else {}
    tool_calls = []
    for call in message.get("tool_calls", []) or []:
        fn = call.get("function", {}) or {}
        raw = fn.get("arguments", {}) or {}
        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except ValueError:
            args = {}
        tool_calls.append({"name": str(fn.get("name", "")), "args": args})
    return {"content": str(message.get("content", "") or ""), "tool_calls": tool_calls}


def complete(
    messages: list[dict[str, Any]], tools: Mapping[str, Tool]
) -> dict[str, Any]:
    """One Meta model call with tool specs. Returns {"content", "tool_calls"}.

    Configured by META_API_KEY (required), META_API_BASE and META_MODEL.
    """
    try:
        import httpx
    except ImportError as exc:
        raise RuntimeError("httpx is not installed: pip install httpx") from exc
    key = os.environ.get("META_API_KEY", "")
    if not key:
        raise RuntimeError("Missing META_API_KEY: set it in the environment.")
    base = os.environ.get("META_API_BASE", "https://api.meta.ai/v1").rstrip("/")
    model = os.environ.get("META_MODEL", "muse-spark-1.3")
    body: dict[str, Any] = {"model": model, "messages": _openai_messages(messages)}
    specs = _openai_tools(tools)
    if specs:
        body["tools"] = specs
    resp = httpx.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "content-type": "application/json"},
        json=body,
        timeout=Settings.from_env().llm_timeout_s,
    )
    resp.raise_for_status()
    return _parse_openai_response(resp.json())


def main() -> None:
    """Load prompt + objective, run, file memo."""
    system = read_text(SYSTEM_PATH)
    objective = read_text(OBJECTIVE_PATH)
    findings, memo = run_agent(system, objective, complete, build_tools())
    print(f"Done. Memo filed at: {memo}\n{findings}")


if __name__ == "__main__":
    main()
