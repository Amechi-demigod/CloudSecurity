"""Application settings, loaded from environment variables.

Everything is configured through env vars so that no secrets ever need to live
in the repository. See `.env.example` at the repo root for the full reference.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str) -> list[str]:
    raw = os.getenv(name, "")
    return [p.strip() for p in raw.replace(";", ",").split(",") if p.strip()]


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./cnapp.db"))

    # Simulated data mode (default ON): seeds a fake multi-subscription Azure
    # environment on first start and runs a background runtime-event simulator.
    simulation_mode: bool = field(default_factory=lambda: _bool("SIMULATION_MODE", True))
    simulator_enabled: bool = field(default_factory=lambda: _bool("SIMULATOR_ENABLED", True))
    simulator_interval_seconds: float = field(
        default_factory=lambda: float(os.getenv("SIMULATOR_INTERVAL_SECONDS", "15"))
    )
    # Probability that a simulator tick also plays out an attack scenario.
    simulator_attack_probability: float = field(
        default_factory=lambda: float(os.getenv("SIMULATOR_ATTACK_PROBABILITY", "0.05"))
    )
    seed: int = field(default_factory=lambda: int(os.getenv("SEED", "42")))

    # Optional shared secret required on POST /api/runtime/events (sensor ingest).
    runtime_ingest_token: str | None = field(default_factory=lambda: os.getenv("RUNTIME_INGEST_TOKEN") or None)

    cors_origins: list[str] = field(
        default_factory=lambda: _list("CORS_ORIGINS") or ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    # Azure read-only posture connector (opt-in).
    azure_tenant_id: str | None = field(default_factory=lambda: os.getenv("AZURE_TENANT_ID") or None)
    azure_client_id: str | None = field(default_factory=lambda: os.getenv("AZURE_CLIENT_ID") or None)
    azure_client_secret: str | None = field(default_factory=lambda: os.getenv("AZURE_CLIENT_SECRET") or None)
    azure_subscription_ids: list[str] = field(default_factory=lambda: _list("AZURE_SUBSCRIPTION_IDS"))
    # When true, fall back to DefaultAzureCredential (az login, managed identity, ...)
    # if no client secret is provided.
    azure_use_default_credential: bool = field(
        default_factory=lambda: _bool("AZURE_USE_DEFAULT_CREDENTIAL", False)
    )


settings = Settings()


def reload_settings() -> Settings:
    """Re-read env vars (used by tests)."""
    global settings
    settings = Settings()
    return settings
