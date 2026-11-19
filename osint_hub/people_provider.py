"""Provider boundary for people/profile OSINT engines."""

from __future__ import annotations

from typing import Protocol

from osint_hub.config import Settings
from osint_hub.models import CollectorResult, ScanDepth


class PeopleProvider(Protocol):
    name: str

    def available(self) -> bool: ...

    async def collect(
        self,
        *,
        emails: list[str],
        usernames: list[str],
        settings: Settings,
        scan_depth: ScanDepth = "standard",
        allow_loud: bool = False,
    ) -> CollectorResult: ...
