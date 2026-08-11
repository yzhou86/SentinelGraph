"""A minimal server-side client for Chat Completions-compatible model APIs."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .config import Settings


class OpenAICompatibleClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def info(self) -> dict[str, Any]:
        return {
            "enabled": self.settings.llm_enabled,
            "configured": bool(self.settings.llm_api_key and self.settings.llm_model),
            "api_base": self.settings.llm_api_base,
            "model": self.settings.llm_model,
            "timeout_seconds": self.settings.llm_timeout_seconds,
            "protocol": "chat_completions",
        }

    def chat(self, messages: list[dict[str, str]], max_tokens: int = 800) -> dict[str, Any]:
        if not self.settings.llm_enabled:
            raise ValueError("LLM is disabled; set LLM_ENABLED=true to enable live inference")
        if not self.settings.llm_api_key or not self.settings.llm_model:
            raise ValueError("LLM_API_KEY and LLM_MODEL must be configured")
        response = httpx.post(
            f"{self.settings.llm_api_base.rstrip('/')}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.settings.llm_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.settings.llm_model,
                "messages": messages,
                "temperature": 0.2,
                "max_tokens": max_tokens,
            },
            timeout=self.settings.llm_timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        choices = body.get("choices") or []
        if not choices:
            raise ValueError("provider returned no choices")
        content = choices[0].get("message", {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise ValueError("provider returned an empty assistant message")
        return {
            "provider": "openai-compatible",
            "model": body.get("model", self.settings.llm_model),
            "answer": content,
            "usage": body.get("usage"),
        }

    def test(self) -> dict[str, Any]:
        result = self.chat(
            [{"role": "user", "content": "Reply with exactly: CONNECTION_OK"}], max_tokens=16
        )
        return {"connected": True, **result}

    def investigate(self, investigation: dict[str, Any]) -> dict[str, Any]:
        evidence = json.dumps(investigation, ensure_ascii=False, default=str)[:24_000]
        return self.chat(
            [
                {
                    "role": "system",
                    "content": "You are a security analyst. Use only the supplied evidence. Cite event_uid or alert_id for each claim. State uncertainty and never treat vector similarity alone as proof.",
                },
                {
                    "role": "user",
                    "content": f"Investigate this evidence and propose prioritized actions:\n{evidence}",
                },
            ]
        )

    def extract_text_relations(
        self, content: str, entities: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Ask a compatible model for bounded, reviewable relations only.

        Entity creation stays deterministic.  The model can only suggest a
        whitelisted relation between identifiers supplied by the service.
        """
        entity_list = [
            {
                "entity_id": entity["entity_id"],
                "entity_type": entity["entity_type"],
                "name": entity["name"],
            }
            for entity in entities
        ]
        result = self.chat(
            [
                {
                    "role": "system",
                    "content": (
                        "Extract only relations directly supported by the supplied security text. "
                        "You may only use the listed entity_id values. Return JSON only in this shape: "
                        '{"relations":[{"source_id":"...","target_id":"...",'
                        '"relation":"communicates_with|targets|hosted_on|uses|affects|associated_with",'
                        '"confidence":0.0,"evidence":"short exact supporting excerpt"}]}. '
                        'If unsupported, return {"relations":[]}. Do not infer attribution.'
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Entities:\n{json.dumps(entity_list, ensure_ascii=False)}\n\n"
                        f"Security text:\n{content[:12_000]}"
                    ),
                },
            ],
            max_tokens=1200,
        )
        answer = result["answer"].strip()
        if answer.startswith("```"):
            answer = re.sub(r"^```(?:json)?\s*|\s*```$", "", answer, flags=re.IGNORECASE)
        try:
            payload = json.loads(answer)
        except json.JSONDecodeError as error:
            raise ValueError("LLM did not return valid relation JSON") from error
        if not isinstance(payload, dict) or not isinstance(payload.get("relations"), list):
            raise ValueError("LLM relation JSON must contain a relations list")
        return {"proposal": payload, "provider": result["provider"], "model": result["model"]}
