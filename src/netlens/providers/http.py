import json

import httpx
from pydantic import ValidationError

from netlens.config import Settings
from netlens.providers.base import SYSTEM, ProviderError, ProviderResult
from netlens.schemas import ReportContent


def anthropic_schema():
    """Simplify documented unsupported constraints; still validate the original locally."""
    removed = {
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "maxItems",
    }

    def simplify(value):
        if isinstance(value, list):
            return [simplify(item) for item in value]
        if not isinstance(value, dict):
            return value
        constraints = {
            k: v for k, v in value.items() if k in removed or (k == "minItems" and v > 1)
        }
        result = {k: simplify(v) for k, v in value.items() if k not in constraints}
        if constraints:
            result["description"] = (
                result.get("description", "")
                + " Local validation constraints: "
                + json.dumps(constraints)
            )
        return result

    return simplify(ReportContent.model_json_schema())


class HTTPProvider:
    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        self.transport = transport

    def post(self, url, headers, body):
        try:
            with httpx.Client(
                timeout=self.settings.provider_timeout_seconds,
                transport=self.transport,
                follow_redirects=False,
            ) as client:
                with client.stream("POST", url, headers=headers, json=body) as response:
                    if response.status_code >= 400:
                        code = (
                            "rate_limit" if response.status_code == 429 else "provider_http_error"
                        )
                        raise ProviderError(
                            code, response.status_code == 429 or response.status_code >= 500
                        )
                    raw = bytearray()
                    for chunk in response.iter_bytes():
                        raw.extend(chunk)
                        if len(raw) > 262144:
                            raise ProviderError("provider_output_limit")
                    return json.loads(raw)
        except httpx.TimeoutException as exc:
            raise ProviderError("provider_timeout", True) from exc
        except httpx.RequestError as exc:
            raise ProviderError("provider_connection", True) from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise ProviderError("malformed_provider_output") from exc

    def parse(self, text, model, usage=None):
        try:
            return ProviderResult(ReportContent.model_validate_json(text), model, usage)
        except (ValidationError, TypeError, ValueError) as exc:
            raise ProviderError("malformed_provider_output") from exc
