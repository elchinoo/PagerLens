"""The key/value settings store now lives in agentpg-kit; this module keeps the old import path."""
from apgkit.settings_store import delete, get, put

__all__ = ["delete", "get", "put"]
