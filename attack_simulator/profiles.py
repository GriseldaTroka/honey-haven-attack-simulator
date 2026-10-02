from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from .models import AttackerProfile


@dataclass(slots=True)
class ProfileLibrary:
    browser_like: AttackerProfile
    scanner_like: AttackerProfile

    def by_name(self, name: str) -> AttackerProfile:
        normalized = name.strip().lower()
        if normalized == "browser_like":
            return self.browser_like
        if normalized == "scanner_like":
            return self.scanner_like
        raise KeyError(f"Unknown attacker profile: {name}")


def build_profile(profile_name: str, overrides: Dict[str, object] | None = None) -> AttackerProfile:
    overrides = overrides or {}
    normalized = profile_name.strip().lower()

    if normalized == "browser_like":
        return AttackerProfile(
            name="browser_like",
            persistent_session=bool(overrides.get("persistent_session", True)),
            user_agent=str(overrides.get("user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")),
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                **{str(key): str(value) for key, value in dict(overrides.get("headers", {})).items()},
            },
            source_ip=str(overrides.get("source_ip", "198.51.100.10")),
            fingerprint_headers={str(key): str(value) for key, value in dict(overrides.get("fingerprint_headers", {})).items()},
        )

    if normalized == "scanner_like":
        return AttackerProfile(
            name="scanner_like",
            persistent_session=bool(overrides.get("persistent_session", False)),
            user_agent=str(overrides.get("user_agent", "Mozilla/5.0 (compatible; AttackSimulator/1.0; +https://example.invalid)")),
            headers={
                "Accept": str(overrides.get("accept", "*/*")),
                **{str(key): str(value) for key, value in dict(overrides.get("headers", {})).items()},
            },
            source_ip=str(overrides.get("source_ip", "198.51.100.200")),
            fingerprint_headers={str(key): str(value) for key, value in dict(overrides.get("fingerprint_headers", {})).items()},
        )

    raise ValueError(f"Unsupported profile type: {profile_name}")
