"""Embeddings through any OpenAI-compatible endpoint (POST {base_url}/embeddings), with an offline fallback.

The fallback is a signed feature-hashing embedder: deterministic, dependency-free and good enough
to demo hybrid search without credentials. It is lexical, NOT semantic: configure a provider for real use.
"""
import hashlib
import itertools
import math
import re

from . import embedcfg, vault
from .llm_http import LLMError, error_detail, post_json

_TOKEN = re.compile(r"[a-z0-9]+")
BATCH = 64


class EmbeddingError(LLMError):
    """Raised with a message that is safe to show: it never contains the API key."""


def hash_embed(text: str, dim: int) -> list[float]:
    vec = [0.0] * dim
    tokens = _TOKEN.findall(text.lower())
    for tok in tokens + [f"{a}_{b}" for a, b in itertools.pairwise(tokens)]:
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=8).digest(), "big")
        vec[h % dim] += 1.0 if (h >> 63) & 1 else -1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def embed(texts: list[str], cfg: embedcfg.EmbeddingConfig | None = None) -> list[list[float]]:
    cfg = cfg or embedcfg.current()
    if not cfg.base_url:
        return [hash_embed(t, cfg.dim) for t in texts]
    try:
        key = cfg.api_key()
    except vault.VaultLocked:
        raise  # surfaced as HTTP 423 so the UI can ask the admin to unlock
    except vault.VaultError as exc:
        raise EmbeddingError(str(exc)) from exc
    out: list[list[float]] = []
    for i in range(0, len(texts), BATCH):
        body: dict = {"model": cfg.model, "input": texts[i : i + BATCH]}
        if cfg.send_dimensions:
            body["dimensions"] = cfg.dim
        try:
            resp = post_json(cfg.base_url, "/embeddings", key, body, trusted=cfg.trusted)
        except LLMError as exc:
            raise EmbeddingError(str(exc)) from exc
        if resp.status_code >= 400:
            hint = " (if it mentions 'dimensions', turn off the dimensions field for this provider)" if cfg.send_dimensions else ""
            raise EmbeddingError(f"embeddings endpoint returned HTTP {resp.status_code}: {error_detail(resp, key)}{hint}")
        try:
            data = sorted(resp.json()["data"], key=lambda d: d["index"])
            vecs = [d["embedding"] for d in data]
        except (KeyError, TypeError, ValueError) as exc:
            raise EmbeddingError("unexpected response from the embeddings endpoint (no data[].embedding)") from exc
        if len(vecs) != len(body["input"]):
            raise EmbeddingError("embeddings endpoint returned a different number of vectors than inputs")
        if vecs and len(vecs[0]) != cfg.dim:
            raise EmbeddingError(
                f"model returned {len(vecs[0])} dimensions but {cfg.dim} were configured. "
                f"Set the dimension to {len(vecs[0])} (or a size the model supports) and switch again."
            )
        out.extend(vecs)
    return out
