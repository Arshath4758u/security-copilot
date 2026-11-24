"""LLM client: asks Ollama for JSON, validates with Pydantic, retries with the error message.
Change the model with:  set COPILOT_MODEL=llama3.1   (PowerShell: $env:COPILOT_MODEL="llama3.1")"""
import os

import ollama

CHAT_MODEL = os.getenv("COPILOT_MODEL", "llama3")


def chat_json(system, user, model_cls, retries=2):
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    last_error = None
    for _ in range(retries + 1):
        resp = ollama.chat(
            model=CHAT_MODEL,
            messages=messages,
            format="json",
            options={"temperature": 0},
        )
        raw = resp["message"]["content"]
        try:
            return model_cls.model_validate_json(raw)
        except ValueError as e:  # pydantic's ValidationError is a ValueError
            last_error = e
            messages.append({"role": "assistant", "content": raw})
            messages.append({
                "role": "user",
                "content": f"That JSON was invalid: {e}. Return ONLY corrected JSON.",
            })
    raise RuntimeError(f"LLM did not return valid JSON after {retries + 1} tries: {last_error}")
