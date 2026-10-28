"""Load .env and expose settings for collectors and LLM providers."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import dotenv_values, load_dotenv
from pydantic import BaseModel, Field

from osint_hub import util


def _empty_to_none(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _load_env_file() -> None:
    """Load `.env` without overriding real shell secrets.

    Empty placeholders (``KEY=``) are treated as unset so filling a key in
    `.env` is picked up on the next `load_settings()` call.
    """
    env_path = util.find_env_file()
    if env_path:
        load_dotenv(env_path, override=False)
        for key, value in dotenv_values(env_path).items():
            if not key or value is None:
                continue
            if not (os.environ.get(key) or "").strip() and value.strip():
                os.environ[key] = value
    else:
        load_dotenv(override=False)


class Settings(BaseModel):
    shodan_api_key: str | None = None
    github_token: str | None = None
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"
    ollama_api_key: str | None = None
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-sonnet-4-5"
    anthropic_max_tokens: int = Field(default=16384, ge=1024, le=128000)
    censys_api_id: str | None = None
    censys_api_secret: str | None = None
    censys_api_token: str | None = None
    censys_organization_id: str | None = None
    hunter_api_key: str | None = None
    tomba_api_key: str | None = None
    tomba_secret: str | None = None
    securitytrails_api_key: str | None = None
    greynoise_api_key: str | None = None
    urlscan_api_key: str | None = None
    virustotal_api_key: str | None = None
    pdcp_api_key: str | None = None
    leakix_api_key: str | None = None
    hibp_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    ipinfo_token: str | None = None
    github_max_results: int = Field(default=30, ge=1, le=100)
    shodan_max_hosts: int = Field(default=15, ge=1, le=100)
    dns_max_hosts: int = Field(default=80, ge=1, le=500)
    hunter_max_emails: int = Field(default=25, ge=1, le=50)
    people_phone_enrich_max: int = Field(default=5, ge=0, le=25)
    http_timeout: float = Field(default=30.0, ge=5.0)
    ollama_timeout: float = Field(default=180.0, ge=10.0)
    user_agent: str = "OSINT_Hub/0.1 (+authorized-recon)"

    @property
    def has_github(self) -> bool:
        return bool(self.github_token)

    @property
    def has_shodan(self) -> bool:
        return bool(self.shodan_api_key)

    @property
    def has_claude(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def has_ollama_key(self) -> bool:
        return bool(self.ollama_api_key)

    @property
    def has_censys(self) -> bool:
        return bool(self.censys_api_token or (self.censys_api_id and self.censys_api_secret))

    @property
    def has_hunter(self) -> bool:
        return bool(self.hunter_api_key)

    @property
    def has_tomba(self) -> bool:
        return bool(self.tomba_api_key and self.tomba_secret)

    @property
    def has_securitytrails(self) -> bool:
        return bool(self.securitytrails_api_key)

    @property
    def has_greynoise(self) -> bool:
        return bool(self.greynoise_api_key)

    @property
    def has_urlscan(self) -> bool:
        return bool(self.urlscan_api_key)

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_pdcp(self) -> bool:
        return bool(self.pdcp_api_key)

    @property
    def has_leakix(self) -> bool:
        return bool(self.leakix_api_key)

    @property
    def has_hibp(self) -> bool:
        return bool(self.hibp_api_key)

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self.abuseipdb_api_key)

    @property
    def has_ipinfo(self) -> bool:
        return bool(self.ipinfo_token)

    def ollama_headers(self) -> dict[str, str]:
        if not self.ollama_api_key:
            return {}
        return {"Authorization": f"Bearer {self.ollama_api_key}"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return int(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        return float(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc


def load_settings() -> Settings:
    """Load `.env` from the package repo root only (never parent directories)."""
    _load_env_file()

    return Settings(
        shodan_api_key=_empty_to_none(os.getenv("SHODAN_API_KEY")),
        github_token=_empty_to_none(os.getenv("GITHUB_TOKEN")),
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.2"),
        ollama_api_key=_empty_to_none(os.getenv("OLLAMA_API_KEY") or os.getenv("OLLAMA_API")),
        anthropic_api_key=_empty_to_none(os.getenv("ANTHROPIC_API_KEY")),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"),
        anthropic_max_tokens=_env_int("ANTHROPIC_MAX_TOKENS", 16384),
        censys_api_id=_empty_to_none(os.getenv("CENSYS_API_ID")),
        censys_api_secret=_empty_to_none(os.getenv("CENSYS_API_SECRET")),
        censys_api_token=_empty_to_none(os.getenv("CENSYS_API_TOKEN")),
        censys_organization_id=_empty_to_none(os.getenv("CENSYS_ORGANIZATION_ID")),
        hunter_api_key=_empty_to_none(os.getenv("HUNTER_API_KEY")),
        tomba_api_key=_empty_to_none(os.getenv("TOMBA_API_KEY")),
        tomba_secret=_empty_to_none(os.getenv("TOMBA_SECRET")),
        securitytrails_api_key=_empty_to_none(os.getenv("SECURITYTRAILS_API_KEY")),
        greynoise_api_key=_empty_to_none(os.getenv("GREYNOISE_API_KEY")),
        urlscan_api_key=_empty_to_none(os.getenv("URLSCAN_API_KEY")),
        virustotal_api_key=_empty_to_none(os.getenv("VIRUSTOTAL_API_KEY")),
        pdcp_api_key=_empty_to_none(os.getenv("PDCP_API_KEY")),
        leakix_api_key=_empty_to_none(os.getenv("LEAKIX_API_KEY")),
        hibp_api_key=_empty_to_none(os.getenv("HIBP_API_KEY")),
        abuseipdb_api_key=_empty_to_none(os.getenv("ABUSEIPDB_API_KEY")),
        ipinfo_token=_empty_to_none(os.getenv("IPINFO_TOKEN")),
        github_max_results=_env_int("GITHUB_MAX_RESULTS", 30),
        shodan_max_hosts=_env_int("SHODAN_MAX_HOSTS", 15),
        dns_max_hosts=_env_int("DNS_MAX_HOSTS", 80),
        hunter_max_emails=_env_int("HUNTER_MAX_EMAILS", 25),
        people_phone_enrich_max=_env_int("PEOPLE_PHONE_ENRICH_MAX", 5),
        http_timeout=_env_float("HTTP_TIMEOUT", 30),
        ollama_timeout=_env_float("OLLAMA_TIMEOUT", 180),
    )


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_runs_dir() -> Path:
    return repo_root() / "runs"
