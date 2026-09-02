import time

from netlens.config import Settings
from netlens.providers.base import PROMPT_VERSION, ProviderError, validate_references
from netlens.providers.http import AnthropicProvider, OllamaProvider, OpenAIProvider
from netlens.providers.mock import MockProvider
from netlens.schemas import ProviderMetadata


def generate_report(provider: str, context: dict, settings: Settings, transport=None):
    adapters = {
        "mock": MockProvider(),
        "openai": OpenAIProvider(settings, transport),
        "anthropic": AnthropicProvider(settings, transport),
        "ollama": OllamaProvider(settings, transport),
    }
    started = time.perf_counter()
    original = provider
    providers = [provider]
    if settings.fallback_provider and settings.fallback_provider != provider:
        providers.append(settings.fallback_provider)
    last = None
    for provider in providers:
        for attempt in range(settings.provider_retries + 1):
            try:
                result = adapters[provider].generate(context)
                validate_references(result.content, context)
                return result.content, ProviderMetadata(
                    provider=provider,
                    model=result.model,
                    prompt_version=PROMPT_VERSION,
                    latency_ms=round((time.perf_counter() - started) * 1000, 3),
                    usage=result.usage,
                    fallback_from=original if original != provider else None,
                )
            except ProviderError as exc:
                last = exc
                if not exc.transient or attempt == settings.provider_retries:
                    break
                time.sleep(min(0.1 * 2**attempt, 1))
    raise last or ProviderError("unknown_provider")
