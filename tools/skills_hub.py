#!/usr/bin/env python3
"""
Skills Hub — Source adapters and hub state management for the Hermes Skills Hub.

This is a library module (not an agent tool). It provides:
  - GitHubAuth: Shared GitHub API authentication (PAT, gh CLI, GitHub App)
  - SkillSource ABC: Interface for all skill registry adapters
  - OptionalSkillSource: Official optional skills shipped with the repo (not activated by default)
  - GitHubSource: Fetch skills from any GitHub repo via the Contents API
  - HubLockFile: Track provenance of installed hub skills
  - Hub state directory management (quarantine, audit log, taps, index cache)

Used by hermes_cli/skills_hub.py for CLI commands and the /skills slash command.
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from hermes_constants import get_hermes_home
from hermes_cli._subprocess_compat import windows_hide_flags
from agent.skill_utils import is_excluded_skill_path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import quote, unquote, urlencode, urljoin, urlparse, urlsplit, urlunparse

import httpx
import yaml

from tools.skills_guard import (
    ScanResult, content_hash, TRUSTED_REPOS,
)
from tools.url_safety import is_safe_url
from tools.website_policy import check_website_access

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Resolved per-call (not frozen at import) so the profile override is honored;
# import-time constants leaked across profiles in single-process multi-profile
# runtimes. Legacy names (SKILLS_DIR, ...) are re-exposed via __getattr__ below
# so external `from tools.skills_hub import SKILLS_DIR` callers still work.

INDEX_CACHE_TTL = 3600  # 1 hour


# _override lets a test-injected real module attribute (patch.object/monkeypatch
# on SKILLS_DIR etc.) win over dynamic resolution; None means resolve live.
def _override(name: str):
    return globals().get(name)


def _hermes_home() -> Path:
    return get_hermes_home()


def _skills_dir() -> Path:
    forced = _override("SKILLS_DIR")
    return Path(forced) if forced is not None else _hermes_home() / "skills"


def _hub_dir() -> Path:
    forced = _override("HUB_DIR")
    return Path(forced) if forced is not None else _skills_dir() / ".hub"


def _lock_file() -> Path:
    forced = _override("LOCK_FILE")
    return Path(forced) if forced is not None else _hub_dir() / "lock.json"


def _quarantine_dir() -> Path:
    forced = _override("QUARANTINE_DIR")
    return Path(forced) if forced is not None else _hub_dir() / "quarantine"


def _audit_log() -> Path:
    forced = _override("AUDIT_LOG")
    return Path(forced) if forced is not None else _hub_dir() / "audit.log"


def _taps_file() -> Path:
    forced = _override("TAPS_FILE")
    return Path(forced) if forced is not None else _hub_dir() / "taps.json"


def _index_cache_dir() -> Path:
    forced = _override("INDEX_CACHE_DIR")
    return Path(forced) if forced is not None else _hub_dir() / "index-cache"


_DYNAMIC_PATH_RESOLVERS = {
    "HERMES_HOME": _hermes_home,
    "SKILLS_DIR": _skills_dir,
    "HUB_DIR": _hub_dir,
    "LOCK_FILE": _lock_file,
    "QUARANTINE_DIR": _quarantine_dir,
    "AUDIT_LOG": _audit_log,
    "TAPS_FILE": _taps_file,
    "INDEX_CACHE_DIR": _index_cache_dir,
}


def __getattr__(name: str):
    """Resolve legacy path constants dynamically (PEP 562) so they reflect the
    active profile override; a test's patch.object-set real attribute shadows it."""
    resolver = _DYNAMIC_PATH_RESOLVERS.get(name)
    if resolver is not None:
        return resolver()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_MAX_SKILL_FETCH_REDIRECTS = 5
_MAX_SKILL_RESPONSE_BYTES = 5 * 1024 * 1024
_MAX_SKILL_ARCHIVE_BYTES = 50 * 1024 * 1024
_MAX_SKILL_ARCHIVE_ENTRIES = 5_000
_MAX_SKILL_ENTRY_BYTES = 20 * 1024 * 1024
_MAX_SKILL_EXTRACTED_BYTES = 100 * 1024 * 1024
_REMOTE_SCAN_IGNORE_FILENAMES = frozenset({".skillignore", ".clawhubignore"})


class _SkillsHubResponseTooLarge(RuntimeError):
    """Raised before a Skills Hub response can be buffered beyond its limit."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SkillMeta:
    """Minimal metadata returned by search results."""
    name: str
    description: str
    source: str           # "official", "github", "clawhub", "lobehub"
    identifier: str       # source-specific ID (e.g. "openai/skills/skill-creator")
    trust_level: str      # "builtin" | "trusted" | "community"
    repo: Optional[str] = None
    path: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillBundle:
    """A downloaded skill ready for quarantine/scanning/installation."""
    name: str
    files: Dict[str, Union[str, bytes]]   # relative_path -> file content
    source: str
    identifier: str
    trust_level: str
    metadata: Dict[str, Any] = field(default_factory=dict)


_ALLOWED_SUPPORT_DIRS = frozenset({"references", "templates", "scripts", "assets", "examples"})
_LOCAL_LINK_RE = re.compile(
    r"(?:\]\(|`|(?:^|[\s\"']))((?:references|templates|scripts|assets|examples)/[^\s)`\"'<>]+)",
    re.MULTILINE,
)
_SUSPICIOUS_LOCAL_REF_RE = re.compile(
    r"(?:references|templates|scripts|assets|examples)/(?:[^\s)`\"'<>]*/)?\.\.(?:/|$)"
)


def _referenced_support_paths(skill_md: str) -> Optional[set[str]]:
    """Extract safe referenced paths; return None on a traversal attempt."""
    normalized = skill_md.replace("\\", "/")
    if _SUSPICIOUS_LOCAL_REF_RE.search(normalized):
        return None
    paths: set[str] = set()
    for match in _LOCAL_LINK_RE.finditer(normalized):
        raw = unquote(urlsplit(match.group(1).rstrip(".,;:")).path)
        try:
            safe = _validate_bundle_rel_path(raw)
        except ValueError:
            return None
        if safe.split("/", 1)[0] in _ALLOWED_SUPPORT_DIRS:
            paths.add(safe)
    return paths


def source_url_for_bundle(bundle: SkillBundle) -> str:
    """Best available human-facing immutable-source provenance URL."""
    explicit = bundle.metadata.get("source_url") or bundle.metadata.get("url")
    if explicit:
        return str(explicit)
    if bundle.source == "github":
        parts = bundle.identifier.split("/", 2)
        if len(parts) >= 2:
            suffix = f"/tree/main/{parts[2]}" if len(parts) == 3 else ""
            return f"https://github.com/{parts[0]}/{parts[1]}{suffix}"
    return bundle.identifier


def _normalize_bundle_path(path_value: str, *, field_name: str, allow_nested: bool) -> str:
    """Normalize and validate bundle-controlled paths before touching disk."""
    if not isinstance(path_value, str):
        raise ValueError(f"Unsafe {field_name}: expected a string")

    raw = path_value.strip()
    if not raw:
        raise ValueError(f"Unsafe {field_name}: empty path")

    normalized = raw.replace("\\", "/")
    path = PurePosixPath(normalized)
    parts = [part for part in path.parts if part not in {"", "."}]

    if normalized.startswith("/") or path.is_absolute():
        raise ValueError(f"Unsafe {field_name}: {path_value}")
    if not parts or any(part == ".." for part in parts):
        raise ValueError(f"Unsafe {field_name}: {path_value}")
    # Reject a colon in any component. On Windows a colon marks either a drive
    # (``C:`` / ``C:foo``) or an NTFS Alternate Data Stream: a bundle member
    # named ``file.py:payload`` writes hidden, scanner-invisible bytes into the
    # visible ``file.py`` (rglob-based review never enumerates the stream).
    # ``/`` is the only legal separator once normalized, so no portable bundle
    # path needs a colon in a component.
    if any(":" in part for part in parts):
        raise ValueError(f"Unsafe {field_name}: {path_value}")
    if not allow_nested and len(parts) != 1:
        raise ValueError(f"Unsafe {field_name}: {path_value}")

    return "/".join(parts)


def _validate_skill_name(name: str) -> str:
    return _normalize_bundle_path(name, field_name="skill name", allow_nested=False)


def _validate_install_parent_path(category: str) -> str:
    return _normalize_bundle_path(category, field_name="install parent path", allow_nested=True)


def _normalize_lock_install_path(install_path: str, skill_name: str) -> str:
    """Validate a skill install path before it touches the lock file or disk.

    Lock-file ``install_path`` entries are the source-of-truth for where
    ``uninstall_skill`` will call ``shutil.rmtree``. A poisoned or buggy
    entry — empty string, ``"."``, an absolute path, ``../..`` traversal,
    or anything whose final component doesn't match the skill name — would
    let ``rmtree`` wipe either the entire ``skills/`` tree or content
    outside it.

    Enforce that ``install_path`` ends with ``<skill_name>``. Nested
    official optional skills may legitimately install below paths such as
    ``mlops/training/<skill_name>``; traversal, absolute paths, empty paths,
    and mismatched final components are still rejected.
    """
    safe_skill_name = _validate_skill_name(skill_name)
    normalized = _normalize_bundle_path(
        install_path,
        field_name="install path",
        allow_nested=True,
    )
    parts = normalized.split("/")
    if not parts or parts[-1] != safe_skill_name:
        raise ValueError(f"Unsafe install path: {install_path}")
    return normalized


def _is_path_redirect(path: Path) -> bool:
    """True when ``path`` is a symlink or (on Windows) a directory junction.

    Either form lets an attacker who can write into the ``skills/`` tree
    redirect a subsequent ``rmtree`` to content outside it. ``is_junction``
    only exists on Python 3.12+ Windows; gate with ``hasattr``.
    """
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _resolve_lock_install_path(install_path: str, skill_name: str) -> Path:
    """Resolve a lock-file install path without allowing escapes from ``SKILLS_DIR``.

    Two layers of defence on top of the existing ``is_relative_to`` check
    that's been on main:

    1. Walk the path component-by-component and refuse if any intermediate
       component is a symlink/junction (a path resolution that follows a
       symlink to outside skills/ would otherwise be hidden by Path.resolve).
    2. After resolve(), reject not just escape-out but also ``resolved == SKILLS_DIR``
       — an empty/``"."``/``""`` install_path resolves to the skills root itself,
       and ``rmtree(SKILLS_DIR)`` would wipe every installed skill.
    """
    normalized = _normalize_lock_install_path(install_path, skill_name)
    skills_dir = _skills_dir()
    skills_root = skills_dir.resolve()

    target = skills_dir
    for part in normalized.split("/"):
        target = target / part
        if _is_path_redirect(target):
            raise ValueError(f"Unsafe install path: {install_path}")

    target = target.resolve()
    if target == skills_root or not target.is_relative_to(skills_root):
        raise ValueError(f"Unsafe install path: {install_path}")
    return target


def _ssrf_safe_http_get(
    url: str,
    *,
    timeout: int = 20,
    headers: Optional[Dict[str, str]] = None,
    allow_private_urls: Optional[bool] = None,
    max_response_bytes: Optional[int] = None,
    verify: Union[bool, str] = True,
    trust_env: bool = True,
) -> httpx.Response:
    """Fetch one URL with connect-time SSRF validation and no automatic redirects."""
    from tools.url_safety import create_ssrf_safe_client

    with create_ssrf_safe_client(
        timeout=timeout,
        follow_redirects=False,
        allow_private_urls=allow_private_urls,
        verify=verify,
        trust_env=trust_env,
    ) as client:
        with client.stream("GET", url, headers=headers) as response:
            if max_response_bytes is not None:
                raw_length = response.headers.get("content-length")
                try:
                    content_length = int(raw_length) if raw_length is not None else None
                except (TypeError, ValueError):
                    content_length = None
                if content_length is not None and content_length > max_response_bytes:
                    raise _SkillsHubResponseTooLarge(
                        f"response exceeds {max_response_bytes} bytes"
                    )

            chunks: List[bytes] = []
            received = 0
            for chunk in response.iter_bytes():
                received += len(chunk)
                if max_response_bytes is not None and received > max_response_bytes:
                    raise _SkillsHubResponseTooLarge(
                        f"response exceeds {max_response_bytes} bytes"
                    )
                chunks.append(chunk)

            # iter_bytes() returns decoded content. Rebuild a detached response
            # without stale encoding/length headers so callers can safely use
            # .content, .text, and .json() after the streaming context closes.
            response_headers = httpx.Headers(response.headers)
            response_headers.pop("content-encoding", None)
            response_headers.pop("content-length", None)
            return httpx.Response(
                status_code=response.status_code,
                headers=response_headers,
                content=b"".join(chunks),
                request=response.request,
            )


def _url_origin(url: str) -> Optional[Tuple[str, str, int]]:
    """Return a normalized HTTP origin, or ``None`` for malformed URLs."""
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        if scheme not in {"http", "https"} or not host:
            return None
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, host, port
    except ValueError:
        return None


def _canonical_origin(url: str) -> Optional[str]:
    """Return a stable scheme://host:port representation for provenance."""
    origin = _url_origin(url)
    if origin is None:
        return None
    scheme, host, port = origin
    display_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{display_host}:{port}"


def _canonical_endpoint(url: str) -> Optional[str]:
    """Return canonical origin plus path for registry provenance pinning."""
    origin = _canonical_origin(url)
    if origin is None:
        return None
    try:
        path = urlparse(url).path or "/"
    except ValueError:
        return None
    if path != "/":
        path = path.rstrip("/")
    return f"{origin}{path}"


def _redact_url_for_log(url: str) -> str:
    """Remove query/fragment values, which may contain signed download tokens."""
    try:
        parsed = urlsplit(url)
        suffix = "?<redacted>" if parsed.query else ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{suffix}"
    except (TypeError, ValueError):
        return "<invalid-url>"


def _guarded_http_get(
    url: str,
    *,
    timeout: int = 20,
    headers: Optional[Dict[str, str]] = None,
    allow_private_urls: Optional[bool] = None,
    allowed_origin: Optional[Tuple[str, str, int]] = None,
    allow_cross_origin_redirects: bool = False,
    max_response_bytes: Optional[int] = None,
    verify: Union[bool, str] = True,
    trust_env: bool = True,
) -> Optional[httpx.Response]:
    """Fetch a URL with SSRF and redirect-target validation."""
    from tools.url_safety import SSRFConnectionBlocked

    current_url = url

    for _ in range(_MAX_SKILL_FETCH_REDIRECTS + 1):
        current_origin = _url_origin(current_url)
        outside_allowed_origin = (
            allowed_origin is not None and current_origin != allowed_origin
        )
        if outside_allowed_origin and not allow_cross_origin_redirects:
            logger.warning(
                "Blocked cross-origin Skills Hub redirect: %s",
                _redact_url_for_log(current_url),
            )
            return None

        # A private-network exception belongs only to the explicitly configured
        # registry origin. It must never be inherited by a redirect target.
        current_allow_private = False if outside_allowed_origin else allow_private_urls
        safe_url = (
            is_safe_url(current_url)
            if current_allow_private is None
            else is_safe_url(current_url, allow_private_urls=current_allow_private)
        )
        if not safe_url:
            logger.warning(
                "Blocked unsafe Skills Hub URL: %s",
                _redact_url_for_log(current_url),
            )
            return None

        blocked = check_website_access(current_url)
        if blocked:
            logger.info(
                "Blocked Skills Hub fetch for %s by rule %s",
                blocked["host"],
                blocked["rule"],
            )
            return None

        try:
            fetch_kwargs: Dict[str, Any] = {"timeout": timeout}
            # A configured registry may redirect a package download to an
            # object-store presigned URL. Follow it only after the normal URL
            # safety checks, and never forward the registry bearer token to a
            # different origin.
            if headers is not None and not outside_allowed_origin:
                fetch_kwargs["headers"] = headers
            if current_allow_private is not None:
                fetch_kwargs["allow_private_urls"] = current_allow_private
            if max_response_bytes is not None:
                fetch_kwargs["max_response_bytes"] = max_response_bytes
            if verify is not True:
                fetch_kwargs["verify"] = verify
            if trust_env is not True:
                fetch_kwargs["trust_env"] = trust_env
            resp = _ssrf_safe_http_get(current_url, **fetch_kwargs)
        except (SSRFConnectionBlocked, httpx.HTTPError, _SkillsHubResponseTooLarge) as exc:
            logger.debug(
                "Skills Hub fetch failed for %s: %s",
                _redact_url_for_log(current_url),
                exc,
            )
            return None

        if resp.status_code in _REDIRECT_STATUS_CODES:
            location = getattr(resp, "headers", {}).get("location")
            if not location:
                return None
            next_url = urljoin(current_url, location)
            next_origin = _url_origin(next_url)
            if (
                current_origin is not None
                and current_origin[0] == "https"
                and (next_origin is None or next_origin[0] != "https")
            ):
                logger.warning(
                    "Blocked HTTPS downgrade in Skills Hub redirect: %s",
                    _redact_url_for_log(next_url),
                )
                return None
            current_url = next_url
            continue

        return resp

    logger.warning(
        "Skills Hub fetch exceeded redirect limit for %s",
        _redact_url_for_log(url),
    )
    return None


def _validate_bundle_rel_path(rel_path: str) -> str:
    return _normalize_bundle_path(rel_path, field_name="bundle file path", allow_nested=True)


# ---------------------------------------------------------------------------
# GitHub Authentication
# ---------------------------------------------------------------------------

class GitHubAuth:
    """
    GitHub API authentication. Tries methods in priority order:
      1. GITHUB_TOKEN / GH_TOKEN env var (PAT — the default)
      2. `gh auth token` subprocess (if gh CLI is installed)
      3. GitHub App JWT + installation token (if app credentials configured)
      4. Unauthenticated (60 req/hr, public repos only)
    """

    def __init__(self):
        self._cached_token: Optional[str] = None
        self._cached_method: Optional[str] = None
        self._app_token_expiry: float = 0

    def get_headers(self) -> Dict[str, str]:
        """Return authorization headers for GitHub API requests."""
        token = self._resolve_token()
        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        return headers

    def is_authenticated(self) -> bool:
        return self._resolve_token() is not None

    def auth_method(self) -> str:
        """Return which auth method is active: 'pat', 'gh-cli', 'github-app', or 'anonymous'."""
        self._resolve_token()
        return self._cached_method or "anonymous"

    def _resolve_token(self) -> Optional[str]:
        # Return cached token if still valid
        if self._cached_token:
            if self._cached_method != "github-app" or time.time() < self._app_token_expiry:
                return self._cached_token

        # 1. Environment variable (profile-scoped under a multiplexed gateway)
        from agent.secret_scope import get_secret
        token = get_secret("GITHUB_TOKEN") or get_secret("GH_TOKEN")
        if token:
            self._cached_token = token
            self._cached_method = "pat"
            return token

        # 2. gh CLI
        token = self._try_gh_cli()
        if token:
            self._cached_token = token
            self._cached_method = "gh-cli"
            return token

        # 3. GitHub App
        token = self._try_github_app()
        if token:
            self._cached_token = token
            self._cached_method = "github-app"
            self._app_token_expiry = time.time() + 3500  # ~58 min (tokens last 1 hour)
            return token

        self._cached_method = "anonymous"
        return None

    def _try_gh_cli(self) -> Optional[str]:
        """Try to get a token from the gh CLI."""
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
                stdin=subprocess.DEVNULL,
                creationflags=windows_hide_flags(),
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.debug("gh CLI token lookup failed: %s", e)
        return None

    def _try_github_app(self) -> Optional[str]:
        """Try GitHub App JWT authentication if credentials are configured."""
        from agent.secret_scope import get_secret
        app_id = get_secret("GITHUB_APP_ID")
        key_path = get_secret("GITHUB_APP_PRIVATE_KEY_PATH")
        installation_id = get_secret("GITHUB_APP_INSTALLATION_ID")

        if not all([app_id, key_path, installation_id]):
            return None

        try:
            import jwt  # PyJWT
        except ImportError:
            logger.debug("PyJWT not installed, skipping GitHub App auth")
            return None

        try:
            key_file = Path(key_path)
            if not key_file.exists():
                return None
            private_key = key_file.read_text(encoding="utf-8")

            now = int(time.time())
            payload = {
                "iat": now - 60,
                "exp": now + (10 * 60),
                "iss": app_id,
            }
            encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

            resp = httpx.post(
                f"https://api.github.com/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {encoded_jwt}",
                    "Accept": "application/vnd.github.v3+json",
                },
                timeout=10,
            )
            if resp.status_code == 201:
                return resp.json().get("token")
        except Exception as e:
            logger.debug("GitHub App auth failed: %s", e)

        return None


# ---------------------------------------------------------------------------
# Source adapter interface
# ---------------------------------------------------------------------------

class SkillSource(ABC):
    """Abstract base for all skill registry adapters."""

    @abstractmethod
    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        """Search for skills matching a query string."""
        ...

    @abstractmethod
    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        """Download a skill bundle by identifier."""
        ...

    @abstractmethod
    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        """Fetch metadata for a skill without downloading all files."""
        ...

    @abstractmethod
    def source_id(self) -> str:
        """Unique identifier for this source (e.g. 'github', 'clawhub')."""
        ...

    def trust_level_for(self, identifier: str) -> str:
        """Determine trust level for a skill from this source."""
        return "community"


# ---------------------------------------------------------------------------
# GitHub source adapter
# ---------------------------------------------------------------------------

# Map a GitHub tap repo (owner/repo) to the human-facing provider label used
# in the docs-site catalog (website/scripts/extract-skills.py::GITHUB_TAP_LABELS).
# The runtime index collapses every GitHub tap into source="github"; stamping
# this provider label onto each skill's ``extra`` keeps the per-tap identity
# (NVIDIA / OpenAI / Anthropic / HuggingFace / gstack / ...) searchable and
# filterable at the CLI without disturbing the source="github" dedup / floor /
# index-skip logic that keys off the bare source id.
GITHUB_TAP_PROVIDERS = {
    "openai/skills": "OpenAI",
    "anthropics/skills": "Anthropic",
    "huggingface/skills": "HuggingFace",
    "nvidia/skills": "NVIDIA",
    "voltagent/awesome-agent-skills": "VoltAgent",
    "garrytan/gstack": "gstack",
    "minimax-ai/cli": "MiniMax",
}


def github_provider_for(repo: str) -> Optional[str]:
    """Return the provider label for a GitHub tap repo, or None.

    ``repo`` is ``owner/repo``; matched case-insensitively so ``NVIDIA/skills``
    and ``nvidia/skills`` both resolve to ``"NVIDIA"``.
    """
    if not repo:
        return None
    return GITHUB_TAP_PROVIDERS.get(repo.strip().lower())


# Lowercased set of accepted ``--source`` provider filters. These are not real
# source ids — they narrow the merged results to GitHub-tap skills carrying the
# matching ``extra.provider`` label (see ``_filter_results_by_provider``).
_PROVIDER_FILTER_VALUES = frozenset(v.lower() for v in GITHUB_TAP_PROVIDERS.values())


def _filter_results_by_provider(
    results: List["SkillMeta"], provider: str
) -> List["SkillMeta"]:
    """Keep only results whose ``extra.provider`` matches ``provider``.

    An explicit provider filter (e.g. ``--source nvidia``) means "show me that
    provider's skills" — so it narrows to exactly those, without injecting the
    official catalog the unfiltered browse/search would lead with.
    """
    want = provider.strip().lower()
    return [
        r for r in results
        if str((r.extra or {}).get("provider", "")).lower() == want
    ]


class GitHubSource(SkillSource):
    """Fetch skills from GitHub repos via the Contents API."""

    DEFAULT_TAPS = [
        # NOTE: openai/skills moved its content into skills/.curated/ (and
        # skills/.system/ for system-level skills). _list_skills_in_repo
        # skips directories starting with "." or "_", so we point both
        # entries at the inner paths directly.
        {"repo": "openai/skills", "path": "skills/.curated/"},
        {"repo": "openai/skills", "path": "skills/.system/"},
        {"repo": "anthropics/skills", "path": "skills/"},
        {"repo": "huggingface/skills", "path": "skills/"},
        # NVIDIA/skills: NVIDIA-verified skills for CUDA-X, AIQ, cuOpt,
        # cuPyNumeric, DeepStream, NeMo, NemoClaw, etc. Each skill ships
        # alongside a signed `skill.oms.sig`, an OMS-signed `skill-card.md`
        # (governance card), and an `evals/` directory — synced daily from
        # the NVIDIA product repos. Treated as `trusted` (see
        # `tools/skills_guard.py::TRUSTED_REPOS`). Sample layout:
        # https://github.com/NVIDIA/skills/tree/main/skills
        {"repo": "NVIDIA/skills", "path": "skills/"},
        {"repo": "garrytan/gstack", "path": ""},
    ]

    def __init__(self, auth: GitHubAuth, extra_taps: Optional[List[Dict]] = None):
        self.auth = auth
        self.taps = list(self.DEFAULT_TAPS)
        if extra_taps:
            self.taps.extend(extra_taps)
        # Per-instance cache: repo -> (default_branch, tree_entries)
        # Survives within a single search/install flow, avoiding redundant API calls.
        self._tree_cache: Dict[str, Tuple[str, List[dict]]] = {}
        self._tree_revisions: Dict[str, str] = {}
        # Per-repo cache of the optional skills.sh.json grouping sidecar,
        # mapping skill_name -> human-readable grouping title. ``None`` means
        # "fetched, no sidecar"; a missing key means "not fetched yet".
        self._skillsh_groupings: Dict[str, Optional[Dict[str, str]]] = {}
        # Set when GitHub returns 403 with rate limit exhausted
        self._rate_limited: bool = False

    def source_id(self) -> str:
        return "github"

    @property
    def is_rate_limited(self) -> bool:
        """Whether GitHub API rate limit was hit during operations."""
        return self._rate_limited

    def trust_level_for(self, identifier: str) -> str:
        # identifier format: "owner/repo/path/to/skill"
        parts = identifier.split("/", 2)
        if len(parts) >= 2:
            repo = f"{parts[0]}/{parts[1]}"
            if repo in TRUSTED_REPOS:
                return "trusted"
        return "community"

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        """Search all taps for skills matching the query."""
        results: List[SkillMeta] = []
        query_lower = query.lower()

        for tap in self.taps:
            try:
                skills = self._list_skills_in_repo(tap["repo"], tap.get("path", ""))
                for skill in skills:
                    searchable = f"{skill.name} {skill.description} {' '.join(skill.tags)}".lower()
                    if query_lower in searchable:
                        results.append(skill)
            except Exception as e:
                logger.debug("Failed to search %s: %s", tap['repo'], e)
                continue

        # Deduplicate by identifier, preferring higher trust levels.
        # identifier is unique per skill; name is not (two configured taps can
        # publish skills with the same name but different identifiers).
        _trust_rank = {"builtin": 2, "trusted": 1, "community": 0}
        seen = {}
        for r in results:
            if r.identifier not in seen:
                seen[r.identifier] = r
            elif _trust_rank.get(r.trust_level, 0) > _trust_rank.get(seen[r.identifier].trust_level, 0):
                seen[r.identifier] = r
        results = list(seen.values())

        return results[:limit]

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        """
        Download a skill from GitHub.
        identifier format: "owner/repo/path/to/skill-dir"
        """
        parts = identifier.split("/", 2)
        if len(parts) < 3:
            return None

        repo = f"{parts[0]}/{parts[1]}"
        skill_path = parts[2]

        skill_md = self._fetch_file_content(repo, f"{skill_path.rstrip('/')}/SKILL.md")
        if skill_md is None:
            return None
        referenced = _referenced_support_paths(skill_md)
        if referenced is None:
            return None

        files: Dict[str, Union[str, bytes]] = {"SKILL.md": skill_md}
        tree = self._get_repo_tree(repo)
        if tree is not None:
            branch, entries = tree
            prefix = f"{skill_path.rstrip('/')}/"
            entries_by_path = {item.get("path", ""): item for item in entries}
            for rel_path in sorted(referenced):
                item_path = f"{prefix}{rel_path}"
                item = entries_by_path.get(item_path)
                if item is None:
                    logger.warning("Referenced skill support file is missing: %s", item_path)
                    return None
                if item.get("type") != "blob" or item.get("mode") == "120000":
                    logger.warning("Rejected non-regular file in skill bundle: %s", item_path)
                    return None
                content = self._fetch_file_bytes(repo, item_path)
                if content is None:
                    return None
                files[rel_path] = content
            revision = self._tree_revisions.get(repo) or branch
        else:
            for rel_path in referenced:
                content = self._fetch_file_bytes(repo, f"{skill_path.rstrip('/')}/{rel_path}")
                if content is None:
                    return None
                files[rel_path] = content
            revision = ""

        skill_name = skill_path.rstrip("/").split("/")[-1]
        trust = self.trust_level_for(identifier)

        return SkillBundle(
            name=skill_name,
            files=files,
            source="github",
            identifier=identifier,
            trust_level=trust,
            metadata={
                "source_url": (
                    f"https://github.com/{repo}/tree/{revision}/{skill_path}"
                    if revision else f"https://github.com/{repo}/{skill_path}"
                ),
                "source_revision": revision,
            },
        )

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        """Fetch just the SKILL.md metadata for preview."""
        parts = identifier.split("/", 2)
        if len(parts) < 3:
            return None

        repo = f"{parts[0]}/{parts[1]}"
        skill_path = parts[2].rstrip("/")
        skill_md_path = f"{skill_path}/SKILL.md"

        content = self._fetch_file_content(repo, skill_md_path)
        if not content:
            return None

        fm = self._parse_frontmatter_quick(content)
        skill_name = fm.get("name", skill_path.split("/")[-1])
        description = fm.get("description", "")

        tags = []
        metadata = fm.get("metadata", {})
        if isinstance(metadata, dict):
            hermes_meta = metadata.get("hermes", {})
            if isinstance(hermes_meta, dict):
                tags = hermes_meta.get("tags", [])
        if not tags:
            raw_tags = fm.get("tags", [])
            tags = raw_tags if isinstance(raw_tags, list) else []

        provider = github_provider_for(repo)
        extra: Dict[str, Any] = {}
        if provider:
            extra["provider"] = provider

        return SkillMeta(
            name=skill_name,
            description=str(description),
            source="github",
            identifier=identifier,
            trust_level=self.trust_level_for(identifier),
            repo=repo,
            path=skill_path,
            tags=[str(t) for t in tags],
            extra=extra,
        )

    # -- Internal helpers --

    def _list_skills_in_repo(self, repo: str, path: str) -> List[SkillMeta]:
        """List skill directories in a GitHub repo path, using cached index."""
        cache_key = f"{repo}_{path}".replace("/", "_").replace(" ", "_")
        cached = self._read_cache(cache_key)
        if cached is not None:
            return [SkillMeta(**s) for s in cached]

        url = f"https://api.github.com/repos/{repo}/contents/{path.rstrip('/')}"
        resp = self._github_get(url)
        if resp is None or resp.status_code != 200:
            return []

        entries = resp.json()
        if not isinstance(entries, list):
            return []

        skills: List[SkillMeta] = []
        groupings = self._get_skillsh_groupings(repo)
        for entry in entries:
            if entry.get("type") != "dir":
                continue

            dir_name = entry["name"]
            if dir_name.startswith((".", "_")):
                continue

            prefix = path.rstrip("/")
            skill_identifier = f"{repo}/{prefix}/{dir_name}" if prefix else f"{repo}/{dir_name}"
            meta = self.inspect(skill_identifier)
            if meta:
                if groupings:
                    category = groupings.get(meta.name) or groupings.get(dir_name)
                    if category:
                        meta.extra["category"] = category
                skills.append(meta)

        # Cache the results
        self._write_cache(cache_key, [self._meta_to_dict(s) for s in skills])
        return skills

    # -- Repo tree cache (avoids redundant API calls) --

    def _get_repo_tree(self, repo: str) -> Optional[Tuple[str, List[dict]]]:
        """Get cached or fresh repo tree.

        Returns ``(default_branch, tree_entries)`` or ``None``.
        A single install can call ``_download_directory_via_tree`` and
        ``_find_skill_in_repo_tree`` multiple times for the same repo — this
        cache eliminates the redundant ``GET /repos/{repo}`` +
        ``GET /repos/{repo}/git/trees/{branch}`` round-trips (previously up to
        6 duplicated pairs per install, consuming ~12 of the 60/hr
        unauthenticated rate limit for nothing).
        """
        if repo in self._tree_cache:
            return self._tree_cache[repo]

        headers = self.auth.get_headers()

        # Resolve default branch
        try:
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}",
                headers=headers, timeout=15, follow_redirects=True,
            )
            if resp.status_code != 200:
                self._check_rate_limit_response(resp)
                return None
            default_branch = resp.json().get("default_branch", "main")
        except (httpx.HTTPError, ValueError):
            return None

        # Fetch recursive tree
        try:
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}/git/trees/{default_branch}",
                params={"recursive": "1"},
                headers=headers, timeout=30, follow_redirects=True,
            )
            if resp.status_code != 200:
                self._check_rate_limit_response(resp)
                return None
            tree_data = resp.json()
            if tree_data.get("truncated"):
                logger.debug("Git tree truncated for %s, cannot cache", repo)
                return None
        except (httpx.HTTPError, ValueError):
            return None

        entries = tree_data.get("tree", [])
        revision = tree_data.get("sha")
        if isinstance(revision, str) and revision:
            self._tree_revisions[repo] = revision
        self._tree_cache[repo] = (default_branch, entries)
        return (default_branch, entries)

    def _check_rate_limit_response(self, resp: "httpx.Response") -> None:
        """Flag the instance as rate-limited when GitHub returns 403 + exhausted quota."""
        if resp.status_code in (403, 429):
            remaining = resp.headers.get("X-RateLimit-Remaining", "")
            if remaining == "0" or resp.status_code == 429:
                self._rate_limited = True
                logger.warning(
                    "GitHub API rate limit exhausted (unauthenticated: 60 req/hr). "
                    "Set GITHUB_TOKEN or install the gh CLI to raise the limit to 5,000/hr."
                )

    def _github_get(
        self,
        url: str,
        *,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: float = 15.0,
        max_retries: int = 3,
    ) -> Optional["httpx.Response"]:
        """GET against the GitHub API with retry/backoff on transient failures.

        Returns the final ``httpx.Response`` (caller inspects status) or
        ``None`` when every attempt raised a transport error.

        Retries on:
          - 403/429 with ``X-RateLimit-Remaining: 0`` — waits until the
            reset time (capped) when the header is present, else exponential
            backoff. This is the all-GitHub-tap-collapse case: a single
            shared rate limit zeroes github + well-known
            at once during the index build.
          - 5xx and connection/timeout errors — exponential backoff.

        On terminal rate-limit exhaustion the instance is flagged via
        ``_check_rate_limit_response`` so the build can fail loud instead of
        silently shipping an index with the GitHub sources dropped to zero.
        """
        hdrs = headers if headers is not None else self.auth.get_headers()
        backoff = 1.0
        last_resp: Optional["httpx.Response"] = None
        for attempt in range(max_retries):
            try:
                resp = httpx.get(
                    url, params=params, headers=hdrs,
                    timeout=timeout, follow_redirects=True,
                )
            except httpx.HTTPError as e:
                logger.debug("GitHub GET %s failed (attempt %d/%d): %s",
                             url, attempt + 1, max_retries, e)
                if attempt < max_retries - 1:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 30.0)
                    continue
                return None

            last_resp = resp
            if resp.status_code == 200:
                return resp

            # Rate-limited: honor the reset header when present, else back off.
            if resp.status_code in (403, 429):
                remaining = resp.headers.get("X-RateLimit-Remaining", "")
                is_rl = remaining == "0" or resp.status_code == 429
                if is_rl and attempt < max_retries - 1:
                    wait = backoff
                    reset = resp.headers.get("X-RateLimit-Reset", "")
                    retry_after = resp.headers.get("Retry-After", "")
                    if retry_after.isdigit():
                        wait = min(float(retry_after), 60.0)
                    elif reset.isdigit():
                        delta = float(reset) - time.time()
                        if 0 < delta <= 60.0:
                            wait = delta
                    logger.debug(
                        "GitHub rate limited on %s, waiting %.1fs (attempt %d/%d)",
                        url, wait, attempt + 1, max_retries,
                    )
                    time.sleep(wait)
                    backoff = min(backoff * 2, 30.0)
                    continue
                # Out of retries (or not a rate-limit 403) — flag and return.
                self._check_rate_limit_response(resp)
                return resp

            # 5xx — retry; 4xx (other than rate limit) — return immediately.
            if 500 <= resp.status_code < 600 and attempt < max_retries - 1:
                time.sleep(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            return resp

        return last_resp


    def _download_directory(self, repo: str, path: str) -> Dict[str, str]:
        """Recursively download all text files from a GitHub directory.

        Uses the Git Trees API first (single call for the entire tree) to
        avoid per-directory rate limiting that causes silent subdirectory
        loss.  Falls back to the recursive Contents API when the tree
        endpoint is unavailable or the response is truncated.
        """
        files = self._download_directory_via_tree(repo, path)
        if files is not None:
            return files
        logger.debug("Tree API unavailable for %s/%s, falling back to Contents API", repo, path)
        return self._download_directory_recursive(repo, path)

    def _download_directory_via_tree(self, repo: str, path: str) -> Optional[Dict[str, str]]:
        """Download an entire directory using the Git Trees API (single request).

        Returns:
            dict of files if the path exists and has content,
            empty dict ``{}`` if the tree is cached but the path doesn't exist
            (prevents unnecessary Contents API fallback),
            ``None`` if the tree couldn't be fetched (triggers Contents API fallback).
        """
        path = path.rstrip("/")

        cached = self._get_repo_tree(repo)
        if cached is None:
            return None
        _default_branch, tree_entries = cached

        # Check if ANY entry lives under the target path
        prefix = f"{path}/"
        has_entries = any(
            item.get("path", "").startswith(prefix) for item in tree_entries
        )
        if not has_entries:
            # Path definitively doesn't exist in the repo — return empty
            # instead of None to skip the Contents API fallback.
            return {}

        # Filter to blobs under our target path and fetch content
        files: Dict[str, str] = {}
        for item in tree_entries:
            if item.get("type") != "blob":
                continue
            item_path = item.get("path", "")
            if not item_path.startswith(prefix):
                continue
            rel_path = item_path[len(prefix):]
            content = self._fetch_file_content(repo, item_path)
            if content is not None:
                files[rel_path] = content
            else:
                logger.debug("Skipped file (fetch failed): %s/%s", repo, item_path)

        return files if files else None

    def _download_directory_recursive(self, repo: str, path: str) -> Dict[str, str]:
        """Recursively download via Contents API (fallback)."""
        url = f"https://api.github.com/repos/{repo}/contents/{path.rstrip('/')}"
        # Route through _github_get so directory listing gets the same
        # 429/403-rate-limit retry + backoff as file fetches (#3033).
        resp = self._github_get(url)
        if resp is None:
            return {}
        if resp.status_code != 200:
            logger.debug("Contents API returned %d for %s/%s", resp.status_code, repo, path)
            return {}

        entries = resp.json()
        if not isinstance(entries, list):
            return {}

        files: Dict[str, str] = {}
        for entry in entries:
            name = entry.get("name", "")
            entry_type = entry.get("type", "")

            if entry_type == "file":
                content = self._fetch_file_content(repo, entry.get("path", ""))
                if content is not None:
                    rel_path = name
                    files[rel_path] = content
            elif entry_type == "dir":
                sub_files = self._download_directory_recursive(repo, entry.get("path", ""))
                if not sub_files:
                    logger.debug("Empty or failed subdirectory: %s/%s", repo, entry.get("path", ""))
                for sub_name, sub_content in sub_files.items():
                    files[f"{name}/{sub_name}"] = sub_content

        return files

    def _find_skill_in_repo_tree(self, repo: str, skill_name: str) -> Optional[str]:
        """Use the GitHub Trees API to find a skill directory anywhere in the repo.

        Returns the full identifier (``repo/path/to/skill``) or ``None``.
        This is a single API call regardless of repo depth, so it efficiently
        handles deeply nested directory structures like
        ``cli-tool/components/skills/development/<skill>/SKILL.md``.
        """
        cached = self._get_repo_tree(repo)
        if cached is None:
            return None
        _default_branch, tree_entries = cached

        # Look for SKILL.md files inside directories named <skill_name>
        skill_md_suffix = f"/{skill_name}/SKILL.md"
        for entry in tree_entries:
            if entry.get("type") != "blob":
                continue
            path = entry.get("path", "")
            if path.endswith(skill_md_suffix) or path == f"{skill_name}/SKILL.md":
                # Strip /SKILL.md to get the skill directory path
                skill_dir = path[: -len("/SKILL.md")]
                return f"{repo}/{skill_dir}"

        return None

    def _fetch_file_content(self, repo: str, path: str) -> Optional[str]:
        """Fetch a single text file from GitHub."""
        content = self._fetch_file_bytes(repo, path)
        if content is None:
            return None
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def _fetch_file_bytes(self, repo: str, path: str) -> Optional[bytes]:
        """Fetch exact file bytes from GitHub without text decoding."""
        url = f"https://api.github.com/repos/{repo}/contents/{path}"
        resp = self._github_get(
            url,
            headers={**self.auth.get_headers(), "Accept": "application/vnd.github.v3.raw"},
        )
        if resp is not None and resp.status_code == 200:
            return resp.content
        return None

    def _get_skillsh_groupings(self, repo: str) -> Optional[Dict[str, str]]:
        """Fetch and parse the repo-root ``skills.sh.json`` grouping sidecar.

        ``skills.sh.json`` is a published cross-ecosystem standard
        (``$schema: https://skills.sh/schemas/skills.sh.schema.json``) that
        lets a tap declare human-readable category groupings for its skills:

            {"groupings": [{"title": "Inference AI", "skills": ["dynamo-..."]}]}

        We flatten it into ``{skill_name: grouping_title}`` so the Skills Hub
        UI can show a real category pill instead of a tag-derived guess. Any
        tap that ships this file gets categorization for free — this is not
        NVIDIA-specific.

        Returns the map (possibly empty) on success, or ``None`` when the repo
        has no sidecar / it couldn't be parsed. Cached per-repo on the instance.
        """
        if repo in self._skillsh_groupings:
            return self._skillsh_groupings[repo]

        content = self._fetch_file_content(repo, "skills.sh.json")
        groupings = self._parse_skillsh_groupings(content) if content else None
        self._skillsh_groupings[repo] = groupings
        return groupings

    @staticmethod
    def _parse_skillsh_groupings(content: str) -> Optional[Dict[str, str]]:
        """Flatten a ``skills.sh.json`` document into ``{skill_name: title}``.

        Returns ``None`` when the content isn't a usable grouping document.
        """
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(data, dict):
            return None
        groupings = data.get("groupings")
        if not isinstance(groupings, list):
            return None

        mapping: Dict[str, str] = {}
        for group in groupings:
            if not isinstance(group, dict):
                continue
            title = group.get("title")
            members = group.get("skills")
            if not isinstance(title, str) or not isinstance(members, list):
                continue
            for member in members:
                if isinstance(member, str) and member:
                    # First grouping wins if a skill is listed twice.
                    mapping.setdefault(member, title)
        return mapping

    def _read_cache(self, key: str) -> Optional[list]:
        """Read cached index if not expired."""
        cache_file = _index_cache_dir() / f"{key}.json"
        if not cache_file.exists():
            return None
        try:
            stat = cache_file.stat()
            if time.time() - stat.st_mtime > INDEX_CACHE_TTL:
                return None
            return json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(self, key: str, data: list) -> None:
        """Write index data to cache."""
        index_cache_dir = _index_cache_dir()
        index_cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = index_cache_dir / f"{key}.json"
        try:
            cache_file.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError as e:
            logger.debug("Could not write cache: %s", e)

    @staticmethod
    def _meta_to_dict(meta: SkillMeta) -> dict:
        return {
            "name": meta.name,
            "description": meta.description,
            "source": meta.source,
            "identifier": meta.identifier,
            "trust_level": meta.trust_level,
            "repo": meta.repo,
            "path": meta.path,
            "tags": meta.tags,
            "extra": meta.extra,
        }

    @staticmethod
    def _parse_frontmatter_quick(content: str) -> dict:
        """Parse YAML frontmatter from SKILL.md content."""
        content = content.lstrip("\ufeff")  # tolerate UTF-8 BOM (Windows editors)
        if not content.startswith("---"):
            return {}
        match = re.search(r'\n---\s*\n', content[3:])
        if not match:
            return {}
        yaml_text = content[3:match.start() + 3]
        try:
            parsed = yaml.safe_load(yaml_text)
            return parsed if isinstance(parsed, dict) else {}
        except yaml.YAMLError:
            return {}


# ---------------------------------------------------------------------------
# Well-known Agent Skills endpoint source adapter
# ---------------------------------------------------------------------------

class WellKnownSkillSource(SkillSource):
    """Read skills from a domain exposing /.well-known/skills/index.json."""

    BASE_PATH = "/.well-known/skills"

    def source_id(self) -> str:
        return "well-known"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        index_url = self._query_to_index_url(query)
        if not index_url:
            return []

        parsed = self._parse_index(index_url)
        if not parsed:
            return []

        results: List[SkillMeta] = []
        for entry in parsed["skills"][:limit]:
            name = entry.get("name")
            if not isinstance(name, str) or not name:
                continue
            description = entry.get("description", "")
            files = entry.get("files", ["SKILL.md"])
            results.append(SkillMeta(
                name=name,
                description=str(description),
                source="well-known",
                identifier=self._wrap_identifier(parsed["base_url"], name),
                trust_level="community",
                path=name,
                extra={
                    "index_url": parsed["index_url"],
                    "base_url": parsed["base_url"],
                    "files": files if isinstance(files, list) else ["SKILL.md"],
                },
            ))
        return results

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        parsed = self._parse_identifier(identifier)
        if not parsed:
            return None

        entry = self._index_entry(parsed["index_url"], parsed["skill_name"])
        if not entry:
            return None

        skill_md = self._fetch_text(f"{parsed['skill_url']}/SKILL.md")
        if skill_md is None:
            return None

        fm = GitHubSource._parse_frontmatter_quick(skill_md)
        description = str(fm.get("description") or entry.get("description") or "")
        name = str(fm.get("name") or parsed["skill_name"])
        return SkillMeta(
            name=name,
            description=description,
            source="well-known",
            identifier=self._wrap_identifier(parsed["base_url"], parsed["skill_name"]),
            trust_level="community",
            path=parsed["skill_name"],
            extra={
                "index_url": parsed["index_url"],
                "base_url": parsed["base_url"],
                "files": entry.get("files", ["SKILL.md"]),
                "endpoint": parsed["skill_url"],
            },
        )

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        parsed = self._parse_identifier(identifier)
        if not parsed:
            return None

        try:
            skill_name = _validate_skill_name(parsed["skill_name"])
        except ValueError:
            logger.warning("Well-known skill identifier contained unsafe skill name: %s", identifier)
            return None

        entry = self._index_entry(parsed["index_url"], parsed["skill_name"])
        if not entry:
            return None

        files = entry.get("files", ["SKILL.md"])
        if not isinstance(files, list) or not files:
            files = ["SKILL.md"]

        downloaded: Dict[str, str] = {}
        for rel_path in files:
            if not isinstance(rel_path, str) or not rel_path:
                continue
            try:
                safe_rel_path = _validate_bundle_rel_path(rel_path)
            except ValueError:
                logger.warning(
                    "Well-known skill %s advertised unsafe file path: %r",
                    identifier,
                    rel_path,
                )
                return None
            text = self._fetch_text(f"{parsed['skill_url']}/{safe_rel_path}")
            if text is None:
                return None
            downloaded[safe_rel_path] = text

        if "SKILL.md" not in downloaded:
            return None

        return SkillBundle(
            name=skill_name,
            files=downloaded,
            source="well-known",
            identifier=self._wrap_identifier(parsed["base_url"], skill_name),
            trust_level="community",
            metadata={
                "index_url": parsed["index_url"],
                "base_url": parsed["base_url"],
                "endpoint": parsed["skill_url"],
                "files": files,
            },
        )

    def _query_to_index_url(self, query: str) -> Optional[str]:
        query = query.strip()
        if not query.startswith(("http://", "https://")):
            return None
        if query.endswith("/index.json"):
            return query
        if f"{self.BASE_PATH}/" in query:
            base_url = query.split(f"{self.BASE_PATH}/", 1)[0] + self.BASE_PATH
            return f"{base_url}/index.json"
        return query.rstrip("/") + f"{self.BASE_PATH}/index.json"

    def _parse_identifier(self, identifier: str) -> Optional[dict]:
        raw = identifier[len("well-known:"):] if identifier.startswith("well-known:") else identifier
        if not raw.startswith(("http://", "https://")):
            return None

        parsed_url = urlparse(raw)
        clean_url = urlunparse(parsed_url._replace(fragment=""))
        fragment = parsed_url.fragment

        if clean_url.endswith("/index.json"):
            if not fragment:
                return None
            base_url = clean_url[:-len("/index.json")]
            skill_name = fragment
            skill_url = f"{base_url}/{skill_name}"
            return {
                "index_url": clean_url,
                "base_url": base_url,
                "skill_name": skill_name,
                "skill_url": skill_url,
            }

        if clean_url.endswith("/SKILL.md"):
            skill_url = clean_url[:-len("/SKILL.md")]
        else:
            skill_url = clean_url.rstrip("/")

        if f"{self.BASE_PATH}/" not in skill_url:
            return None

        base_url, skill_name = skill_url.rsplit("/", 1)
        return {
            "index_url": f"{base_url}/index.json",
            "base_url": base_url,
            "skill_name": skill_name,
            "skill_url": skill_url,
        }

    def _parse_index(self, index_url: str) -> Optional[dict]:
        cache_key = f"well_known_index_{hashlib.md5(index_url.encode()).hexdigest()}"
        cached = _read_index_cache(cache_key)
        if isinstance(cached, dict) and isinstance(cached.get("skills"), list):
            return cached

        resp = _guarded_http_get(index_url, timeout=20)
        if resp is None or resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except json.JSONDecodeError:
            return None

        skills = data.get("skills", []) if isinstance(data, dict) else []
        if not isinstance(skills, list):
            return None

        parsed = {
            "index_url": index_url,
            "base_url": index_url[:-len("/index.json")],
            "skills": skills,
        }
        _write_index_cache(cache_key, parsed)
        return parsed

    def _index_entry(self, index_url: str, skill_name: str) -> Optional[dict]:
        parsed = self._parse_index(index_url)
        if not parsed:
            return None
        for entry in parsed["skills"]:
            if isinstance(entry, dict) and entry.get("name") == skill_name:
                return entry
        return None

    @staticmethod
    def _fetch_text(url: str) -> Optional[str]:
        resp = _guarded_http_get(url, timeout=20)
        if resp is not None and resp.status_code == 200:
            return resp.text
        return None

    @staticmethod
    def _wrap_identifier(base_url: str, skill_name: str) -> str:
        return f"well-known:{base_url.rstrip('/')}/{skill_name}"


# ---------------------------------------------------------------------------
# Configured enterprise Agent Skills endpoint
# ---------------------------------------------------------------------------

_ENTERPRISE_SOURCE_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
_ENTERPRISE_TOKEN_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ENTERPRISE_SOURCE_PROTOCOLS = frozenset({"well-known", "clawhub"})


class _EnterpriseAuthMissing(RuntimeError):
    """Raised when a configured enterprise credential cannot be resolved."""


def _is_explicit_loopback_host(hostname: Optional[str]) -> bool:
    """Allow insecure HTTP only for explicit local integration-test hosts."""
    host = (hostname or "").lower().rstrip(".")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _enterprise_auth_context(
    config: dict,
) -> Tuple[Optional[Dict[str, str]], str]:
    """Resolve bearer headers plus a non-secret cache partition identity."""
    token_env = str(config.get("token_env") or "").strip()
    if not token_env:
        return None, "anonymous"
    try:
        from hermes_cli.config import get_env_value

        token = (get_env_value(token_env) or "").strip()
    except Exception as exc:
        raise _EnterpriseAuthMissing("auth_missing") from exc
    if not token:
        raise _EnterpriseAuthMissing("auth_missing")
    partition = hashlib.sha256(
        f"{token_env}\0{token}".encode("utf-8")
    ).hexdigest()
    return {"Authorization": f"Bearer {token}"}, partition


def _fail_closed_hub_config(reason: str) -> dict:
    logger.error("Skills Hub configuration rejected; using private local-only mode: %s", reason)
    return {
        "mode": "private",
        "sources": [],
        "configuration_error": "invalid_config",
    }


def normalize_enterprise_source_config(raw: Any) -> dict:
    """Validate and normalize one ``skills.hub.sources`` entry.

    Enterprise hubs receive a stable source id so multiple internal registries
    can coexist and installed-skill updates remain pinned to their original
    registry. ``well-known`` remains the backward-compatible default protocol.
    """
    if not isinstance(raw, dict):
        raise ValueError("Enterprise Skill Hub source must be an object")

    source_id = str(raw.get("id") or "").strip().lower()
    if not _ENTERPRISE_SOURCE_ID_RE.fullmatch(source_id):
        raise ValueError(
            "Source id must start with a letter and contain only lowercase "
            "letters, numbers, and hyphens (maximum 48 characters)"
        )

    label = str(raw.get("label") or raw.get("name") or "").strip()
    if not label:
        raise ValueError("Source name is required")
    if len(label) > 80:
        raise ValueError("Source name must be 80 characters or fewer")

    protocol = str(raw.get("protocol") or "well-known").strip().lower()
    if protocol not in _ENTERPRISE_SOURCE_PROTOCOLS:
        raise ValueError(
            "Source protocol must be 'well-known' or 'clawhub'"
        )

    raw_url = str(
        (
            raw.get("base_url")
            if protocol == "clawhub"
            else raw.get("index_url")
        )
        or raw.get("url")
        or raw.get("index_url")
        or raw.get("base_url")
        or ""
    ).strip()
    try:
        parsed = urlparse(raw_url)
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Source URL is invalid") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Source URL must use http:// or https://")
    if parsed.username or parsed.password:
        raise ValueError("Credentials are not allowed in the source URL")
    if parsed.query or parsed.fragment:
        raise ValueError("Source URL cannot contain a query string or fragment")

    path = parsed.path.rstrip("/")
    if protocol == "clawhub":
        api_path = path if path.endswith("/api/v1") else f"{path}/api/v1"
        base_url = urlunparse(
            parsed._replace(path=api_path, query="", fragment="")
        )
        index_url = ""
    else:
        if path.endswith("/index.json"):
            index_path = path
        elif path.endswith(WellKnownSkillSource.BASE_PATH):
            index_path = f"{path}/index.json"
        else:
            index_path = f"{path}{WellKnownSkillSource.BASE_PATH}/index.json"
        index_url = urlunparse(
            parsed._replace(path=index_path, query="", fragment="")
        )
        base_url = ""

    token_env = str(raw.get("token_env") or "").strip()
    if token_env and not _ENTERPRISE_TOKEN_ENV_RE.fullmatch(token_env):
        raise ValueError("Token environment variable name is invalid")
    if (
        token_env
        and parsed.scheme.lower() != "https"
        and not _is_explicit_loopback_host(parsed.hostname)
    ):
        raise ValueError(
            "Enterprise sources with a bearer token must use HTTPS "
            "(HTTP is allowed only for explicit loopback test hosts)"
        )

    ca_bundle = str(raw.get("ca_bundle") or "").strip()

    return {
        "id": source_id,
        "label": label,
        "protocol": protocol,
        "index_url": index_url,
        "base_url": base_url,
        "token_env": token_env,
        "allow_private_network": bool(raw.get("allow_private_network", True)),
        "ca_bundle": ca_bundle,
    }


def load_skills_hub_config() -> dict:
    """Return the validated, profile-scoped Skills Hub source policy."""
    try:
        from hermes_cli import managed_scope
        from hermes_cli.config import fast_safe_load, get_config_path, load_config

        # load_config() intentionally falls back to defaults/last-known-good on
        # parse errors. That is unsafe for a network-egress policy: a broken
        # private-mode file must never silently become the public default.
        config_paths = [get_config_path()]
        managed_dir = managed_scope.get_managed_dir()
        if managed_dir is not None:
            config_paths.append(managed_dir / "config.yaml")
        for config_path in config_paths:
            try:
                with open(config_path, encoding="utf-8") as config_file:
                    raw_config = fast_safe_load(config_file)
            except FileNotFoundError:
                continue
            if raw_config is not None and not isinstance(raw_config, dict):
                return _fail_closed_hub_config(
                    f"{config_path.name} root is not an object"
                )
        config = load_config()
    except Exception as exc:
        return _fail_closed_hub_config(type(exc).__name__)

    if not isinstance(config, dict):
        return _fail_closed_hub_config("loaded config is not an object")
    skills_cfg = config.get("skills", {})
    if not isinstance(skills_cfg, dict):
        return _fail_closed_hub_config("skills config is not an object")
    hub_cfg = skills_cfg.get("hub", {})
    if not isinstance(hub_cfg, dict):
        return _fail_closed_hub_config("skills.hub is not an object")

    mode = str(hub_cfg.get("mode", "public")).strip().lower()
    if mode not in {"public", "hybrid", "private"}:
        return _fail_closed_hub_config("skills.hub.mode is invalid")

    raw_sources = hub_cfg.get("sources", [])
    if not isinstance(raw_sources, list):
        return _fail_closed_hub_config("skills.hub.sources is not a list")
    sources = []
    seen = set()
    for raw in raw_sources:
        try:
            source = normalize_enterprise_source_config(raw)
        except ValueError as exc:
            return _fail_closed_hub_config(str(exc))
        if source["id"] in seen:
            return _fail_closed_hub_config(
                f"duplicate enterprise Skill Hub source id: {source['id']}"
            )
        seen.add(source["id"])
        sources.append(source)

    return {"mode": mode, "sources": sources}


class EnterpriseSkillSource(SkillSource):
    """A persistent, profile-scoped well-known source for an enterprise hub."""

    def __init__(self, config: dict):
        self.config = normalize_enterprise_source_config(config)
        if self.config["protocol"] != "well-known":
            raise ValueError("EnterpriseSkillSource requires the well-known protocol")
        self.display_name = self.config["label"]
        self.source_kind = "enterprise"
        self.configured = True
        self.removable = True
        self.status = "unknown"
        self.last_error: Optional[str] = None
        self.last_synced_at: Optional[str] = None
        self._index: Optional[dict] = None
        self._index_partition: Optional[str] = None
        self._origin = _url_origin(self.config["index_url"])
        self._base_url = self.config["index_url"][:-len("/index.json")]

    def source_id(self) -> str:
        return f"enterprise:{self.config['id']}"

    def trust_level_for(self, identifier: str) -> str:
        # An internal network location is not itself a code-signing boundary.
        return "community"

    @property
    def is_available(self) -> bool:
        return self._load_index() is not None

    @property
    def index_url(self) -> str:
        return self.config["index_url"]

    def probe(self) -> dict:
        index = self._load_index(force_refresh=True)
        return {
            "ok": index is not None,
            "status": self.status,
            "last_error": self.last_error,
            "last_synced_at": self.last_synced_at,
            "skill_count": len(index.get("skills", [])) if index else 0,
        }

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        index = self._load_index()
        if not index:
            return []

        needle = query.strip().lower()
        results: List[SkillMeta] = []
        for entry in index["skills"]:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            if not isinstance(name, str):
                continue
            try:
                safe_name = _validate_skill_name(name)
            except ValueError:
                continue
            description = str(entry.get("description") or "")
            tags = [str(tag) for tag in (entry.get("tags") or []) if isinstance(tag, str)]
            if needle:
                haystack = " ".join([safe_name, description, *tags]).lower()
                if needle not in haystack:
                    continue
            results.append(self._to_meta(entry, safe_name))
            if len(results) >= limit:
                break
        return results

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        skill_name = self._identifier_skill_name(identifier)
        if not skill_name:
            return None
        entry = self._entry(skill_name)
        if not entry:
            return None
        skill_md = self._fetch_text(f"{self._base_url}/{skill_name}/SKILL.md")
        if skill_md is None:
            return None
        fm = GitHubSource._parse_frontmatter_quick(skill_md)
        meta = self._to_meta(entry, skill_name)
        meta.name = str(fm.get("name") or meta.name)
        meta.description = str(fm.get("description") or meta.description)
        meta.extra["endpoint"] = f"{self._base_url}/{skill_name}"
        return meta

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        skill_name = self._identifier_skill_name(identifier)
        if not skill_name:
            return None
        entry = self._entry(skill_name)
        if not entry:
            return None

        files = entry.get("files", ["SKILL.md"])
        if not isinstance(files, list) or not files:
            files = ["SKILL.md"]

        downloaded: Dict[str, str] = {}
        for rel_path in files:
            if not isinstance(rel_path, str) or not rel_path:
                continue
            try:
                safe_rel_path = _validate_bundle_rel_path(rel_path)
            except ValueError:
                logger.warning(
                    "Enterprise skill %s advertised unsafe file path: %r",
                    identifier,
                    rel_path,
                )
                return None
            text = self._fetch_text(
                f"{self._base_url}/{skill_name}/{safe_rel_path}"
            )
            if text is None:
                return None
            downloaded[safe_rel_path] = text

        if "SKILL.md" not in downloaded:
            return None

        return SkillBundle(
            name=skill_name,
            files=downloaded,
            source=self.source_id(),
            identifier=self._identifier(skill_name),
            trust_level="community",
            metadata={
                "index_url": self.config["index_url"],
                "endpoint": f"{self._base_url}/{skill_name}",
                "files": files,
                "source_label": self.display_name,
                "source_protocol": "well-known",
                "source_origin": _canonical_origin(self.config["index_url"]),
                "source_endpoint": _canonical_endpoint(self.config["index_url"]),
            },
        )

    def _identifier_skill_name(self, identifier: str) -> Optional[str]:
        prefix = f"{self.source_id()}/"
        if not isinstance(identifier, str) or not identifier.startswith(prefix):
            return None
        try:
            return _validate_skill_name(identifier[len(prefix):])
        except ValueError:
            return None

    def _identifier(self, skill_name: str) -> str:
        return f"{self.source_id()}/{skill_name}"

    def _to_meta(self, entry: dict, skill_name: str) -> SkillMeta:
        return SkillMeta(
            name=skill_name,
            description=str(entry.get("description") or ""),
            source=self.source_id(),
            identifier=self._identifier(skill_name),
            trust_level="community",
            path=skill_name,
            tags=[
                str(tag)
                for tag in (entry.get("tags") or [])
                if isinstance(tag, str)
            ],
            extra={
                "index_url": self.config["index_url"],
                "files": entry.get("files", ["SKILL.md"]),
                "source_label": self.display_name,
            },
        )

    def _entry(self, skill_name: str) -> Optional[dict]:
        index = self._load_index()
        if not index:
            return None
        for entry in index["skills"]:
            if isinstance(entry, dict) and entry.get("name") == skill_name:
                return entry
        return None

    def _headers(self) -> Optional[Dict[str, str]]:
        headers, _partition = _enterprise_auth_context(self.config)
        return headers

    def _credential_partition(self) -> str:
        _headers, partition = _enterprise_auth_context(self.config)
        return partition

    def _fetch_text(self, url: str) -> Optional[str]:
        response = self._request(url)
        if response is None or response.status_code != 200:
            return None
        return response.text

    def _request(self, url: str) -> Optional[httpx.Response]:
        try:
            headers = self._headers()
        except _EnterpriseAuthMissing:
            self.status = "unreachable"
            self.last_error = "auth_missing"
            return None
        verify: Union[bool, str] = self.config.get("ca_bundle") or True
        response = _guarded_http_get(
            url,
            timeout=20,
            headers=headers,
            allow_private_urls=self.config["allow_private_network"],
            allowed_origin=self._origin,
            max_response_bytes=_MAX_SKILL_RESPONSE_BYTES,
            verify=verify,
            # Enterprise mode must not accidentally route through a public
            # proxy inherited from the desktop process.
            trust_env=False,
        )
        if response is not None and response.status_code in {401, 403}:
            self.status = "unreachable"
            self.last_error = f"http_{response.status_code}"
        return response

    def _cache_file(self, credential_partition: Optional[str] = None) -> Path:
        partition = credential_partition or self._credential_partition()
        digest = hashlib.sha256(
            f"{self.config['index_url']}\0{partition}".encode("utf-8")
        ).hexdigest()
        return _index_cache_dir() / f"enterprise_{self.config['id']}_{digest}.json"

    def _read_cache(
        self,
        *,
        fresh_only: bool,
        credential_partition: Optional[str] = None,
    ) -> Optional[dict]:
        cache_file = self._cache_file(credential_partition)
        try:
            age = time.time() - cache_file.stat().st_mtime
            if fresh_only and age > INDEX_CACHE_TTL:
                return None
            data = json.loads(cache_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("skills"), list):
                return None
            self.last_synced_at = datetime.fromtimestamp(
                cache_file.stat().st_mtime,
                timezone.utc,
            ).isoformat()
            return data
        except (OSError, json.JSONDecodeError):
            return None

    def _write_cache(
        self,
        data: dict,
        credential_partition: Optional[str] = None,
    ) -> None:
        cache_file = self._cache_file(credential_partition)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            cache_file.write_text(
                json.dumps(data, ensure_ascii=False),
                encoding="utf-8",
            )
            ignore_file = _hub_dir() / ".ignore"
            if not ignore_file.exists():
                ignore_file.write_text(
                    "# Exclude hub internals from search tools\n*\n",
                    encoding="utf-8",
                )
            self.last_synced_at = datetime.now(timezone.utc).isoformat()
        except OSError as exc:
            logger.debug("Could not cache enterprise Skill Hub index: %s", exc)

    def _load_index(self, *, force_refresh: bool = False) -> Optional[dict]:
        try:
            credential_partition = self._credential_partition()
        except _EnterpriseAuthMissing:
            self.status = "unreachable"
            self.last_error = "auth_missing"
            self._index = None
            self._index_partition = None
            return None

        if (
            self._index is not None
            and self._index_partition == credential_partition
            and not force_refresh
        ):
            return self._index

        if not force_refresh:
            cached = self._read_cache(
                fresh_only=True,
                credential_partition=credential_partition,
            )
            if cached is not None:
                self.status = "cached"
                self.last_error = None
                self._index = cached
                self._index_partition = credential_partition
                return cached

        response = self._request(self.config["index_url"])
        if response is not None and response.status_code == 200:
            try:
                data = response.json()
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict) and isinstance(data.get("skills"), list):
                normalized = {"skills": data["skills"]}
                self._write_cache(normalized, credential_partition)
                self.status = "online"
                self.last_error = None
                self._index = normalized
                self._index_partition = credential_partition
                return normalized
            self.last_error = "invalid_index"
        else:
            if response is not None:
                self.last_error = f"http_{response.status_code}"
            elif self.last_error != "auth_missing":
                self.last_error = "unreachable"

        if self.last_error == "auth_missing" or (
            response is not None and response.status_code in {401, 403}
        ):
            self.status = "unreachable"
            self._index = None
            self._index_partition = None
            return None

        stale = self._read_cache(
            fresh_only=False,
            credential_partition=credential_partition,
        )
        if stale is not None:
            self.status = "cached"
            self._index = stale
            self._index_partition = credential_partition
            return stale

        self.status = "unreachable"
        self._index = None
        self._index_partition = None
        return None


# ---------------------------------------------------------------------------
# Configured ClawHub-compatible enterprise source
# ---------------------------------------------------------------------------

class EnterpriseClawHubSource(SkillSource):
    """A profile-scoped ClawHub-compatible registry.

    Unlike the public ``ClawHubSource``, this adapter carries a configured
    origin and optional bearer token, and uses the compatibility contract's
    ``/search`` and ``/download`` routes. The stable ``enterprise:<id>`` source
    identity keeps update provenance pinned to the configured registry.
    """

    _SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")

    def __init__(self, config: dict):
        self.config = normalize_enterprise_source_config(config)
        if self.config["protocol"] != "clawhub":
            raise ValueError(
                "EnterpriseClawHubSource requires the clawhub protocol"
            )
        self.display_name = self.config["label"]
        self.source_kind = "enterprise"
        self.configured = True
        self.removable = True
        self.status = "unknown"
        self.last_error: Optional[str] = None
        self.last_synced_at: Optional[str] = None
        self._base_url = self.config["base_url"]
        self._origin = _url_origin(self._base_url)

    def source_id(self) -> str:
        return f"enterprise:{self.config['id']}"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    @property
    def is_available(self) -> bool:
        return bool(self.probe()["ok"])

    @property
    def base_url(self) -> str:
        return self._base_url

    def probe(self) -> dict:
        results = self._search("", limit=100, force_refresh=True)
        return {
            "ok": self.status in {"online", "cached"},
            "status": self.status,
            "last_error": self.last_error,
            "last_synced_at": self.last_synced_at,
            # The compatibility API does not guarantee a total count. This is
            # the visible result count returned by the bounded probe.
            "skill_count": len(results),
        }

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        return self._search(query.strip(), limit=max(1, limit))

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        slug = self._identifier_slug(identifier)
        if not slug:
            return None
        data = self._skill_detail(slug)
        if not data:
            return None
        return self._detail_to_meta(data, slug)

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        slug = self._identifier_slug(identifier)
        if not slug:
            return None

        detail = self._skill_detail(slug)
        if detail is None:
            return None
        version = self._latest_version(slug, detail)
        if not version:
            logger.warning(
                "Enterprise SkillHub fetch failed for %s: no published version",
                slug,
            )
            return None

        files = self._download_zip(slug, version)
        if "SKILL.md" not in files:
            logger.warning(
                "Enterprise SkillHub fetch failed for %s@%s: bundle missing SKILL.md",
                slug,
                version,
            )
            return None

        return SkillBundle(
            name=slug,
            files=files,
            source=self.source_id(),
            identifier=self._identifier(slug),
            trust_level="community",
            metadata={
                "base_url": self._base_url,
                "version": version,
                "source_label": self.display_name,
                "source_url": f"{self._base_url}/skills/{quote(slug, safe='')}",
                "source_protocol": "clawhub",
                "source_origin": _canonical_origin(self._base_url),
                "source_endpoint": _canonical_endpoint(self._base_url),
            },
        )

    def _search(
        self,
        query: str,
        *,
        limit: int,
        force_refresh: bool = False,
    ) -> List[SkillMeta]:
        try:
            credential_partition = self._credential_partition()
        except _EnterpriseAuthMissing:
            self.status = "unreachable"
            self.last_error = "auth_missing"
            return []

        if not force_refresh:
            cached = self._read_search_cache(
                query,
                limit,
                credential_partition=credential_partition,
                fresh_only=True,
            )
            if cached is not None:
                self.status = "cached"
                self.last_error = None
                return cached

        url = f"{self._base_url}/search?{urlencode({'q': query, 'page': 0, 'limit': limit})}"
        response = self._request(url)
        if response is not None and response.status_code == 200:
            try:
                payload = response.json()
            except json.JSONDecodeError:
                payload = None
            raw_results = payload.get("results") if isinstance(payload, dict) else None
            if isinstance(raw_results, list):
                results = [
                    meta
                    for item in raw_results[:limit]
                    if isinstance(item, dict)
                    for meta in [self._search_item_to_meta(item)]
                    if meta is not None
                ]
                self._write_search_cache(
                    query,
                    limit,
                    results,
                    credential_partition=credential_partition,
                )
                self.status = "online"
                self.last_error = None
                return results
            self.last_error = "invalid_search_response"
        else:
            if response is not None:
                self.last_error = f"http_{response.status_code}"
            elif self.last_error != "auth_missing":
                self.last_error = "unreachable"

        if self.last_error == "auth_missing" or (
            response is not None and response.status_code in {401, 403}
        ):
            self.status = "unreachable"
            return []

        stale = self._read_search_cache(
            query,
            limit,
            credential_partition=credential_partition,
            fresh_only=False,
        )
        if stale is not None:
            self.status = "cached"
            return stale
        self.status = "unreachable"
        return []

    def _search_item_to_meta(self, item: dict) -> Optional[SkillMeta]:
        slug = str(item.get("slug") or "").strip()
        if not self._SLUG_RE.fullmatch(slug):
            return None
        extra: Dict[str, Any] = {}
        version = item.get("version")
        if isinstance(version, str) and version:
            extra["version"] = version
        author = item.get("author")
        if isinstance(author, dict) and author.get("handle"):
            extra["owner"] = str(author["handle"])
        return SkillMeta(
            name=str(item.get("displayName") or item.get("name") or slug),
            description=str(item.get("summary") or item.get("description") or ""),
            source=self.source_id(),
            identifier=self._identifier(slug),
            trust_level="community",
            tags=[str(tag) for tag in (item.get("tags") or []) if isinstance(tag, str)],
            extra=extra,
        )

    def _detail_to_meta(self, data: dict, slug: str) -> SkillMeta:
        tags = data.get("tags")
        normalized_tags = (
            [str(tag) for tag in tags if isinstance(tag, str)]
            if isinstance(tags, list)
            else [str(tag) for tag in tags if str(tag) != "latest"]
            if isinstance(tags, dict)
            else []
        )
        extra: Dict[str, Any] = {"base_url": self._base_url}
        latest = data.get("latestVersion")
        if isinstance(latest, dict) and latest.get("version"):
            extra["version"] = str(latest["version"])
        return SkillMeta(
            name=str(data.get("displayName") or data.get("name") or slug),
            description=str(data.get("summary") or data.get("description") or ""),
            source=self.source_id(),
            identifier=self._identifier(slug),
            trust_level="community",
            tags=normalized_tags,
            extra=extra,
        )

    def _skill_detail(self, slug: str) -> Optional[dict]:
        payload = self._request_json(
            f"{self._base_url}/skills/{quote(slug, safe='')}"
        )
        if not isinstance(payload, dict):
            return None
        nested = payload.get("skill")
        if not isinstance(nested, dict):
            return payload
        merged = dict(nested)
        for field_name in ("latestVersion", "owner", "moderation"):
            if field_name in payload and field_name not in merged:
                merged[field_name] = payload[field_name]
        return merged

    def _latest_version(self, slug: str, detail: dict) -> Optional[str]:
        latest = detail.get("latestVersion")
        if isinstance(latest, dict):
            version = latest.get("version")
            if isinstance(version, str) and version:
                return version

        payload = self._request_json(
            f"{self._base_url}/resolve?{urlencode({'slug': slug})}"
        )
        if not isinstance(payload, dict):
            return None
        for key in ("match", "latestVersion"):
            candidate = payload.get(key)
            if isinstance(candidate, dict):
                version = candidate.get("version")
                if isinstance(version, str) and version:
                    return version
        return None

    def _download_zip(self, slug: str, version: str) -> Dict[str, Union[str, bytes]]:
        import io
        import stat
        import zipfile

        response = self._request(
            f"{self._base_url}/download?{urlencode({'slug': slug, 'version': version})}",
            allow_cross_origin_redirects=True,
            max_response_bytes=_MAX_SKILL_ARCHIVE_BYTES,
        )
        if response is None or response.status_code != 200:
            return {}
        content = response.content
        if len(content) > _MAX_SKILL_ARCHIVE_BYTES:
            logger.warning("Enterprise SkillHub archive exceeds compressed size limit")
            return {}

        files: Dict[str, Union[str, bytes]] = {}
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                entries = [entry for entry in archive.infolist() if not entry.is_dir()]
                if len(entries) > _MAX_SKILL_ARCHIVE_ENTRIES:
                    return {}
                total_size = 0
                seen_paths: set[str] = set()
                for entry in entries:
                    total_size += entry.file_size
                    if (
                        entry.file_size > _MAX_SKILL_ENTRY_BYTES
                        or total_size > _MAX_SKILL_EXTRACTED_BYTES
                    ):
                        return {}
                    if stat.S_IFMT(entry.external_attr >> 16) == stat.S_IFLNK:
                        return {}
                    try:
                        path = _validate_bundle_rel_path(entry.filename)
                    except ValueError:
                        return {}
                    path_key = path.casefold()
                    if path_key in seen_paths:
                        return {}
                    seen_paths.add(path_key)
                    raw = archive.read(entry)
                    try:
                        files[path] = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        files[path] = raw
        except (OSError, zipfile.BadZipFile, RuntimeError):
            return {}
        return files

    def _identifier_slug(self, identifier: str) -> Optional[str]:
        prefix = f"{self.source_id()}/"
        if not isinstance(identifier, str) or not identifier.startswith(prefix):
            return None
        slug = identifier[len(prefix):]
        return slug if self._SLUG_RE.fullmatch(slug) else None

    def _identifier(self, slug: str) -> str:
        return f"{self.source_id()}/{slug}"

    def _headers(self) -> Optional[Dict[str, str]]:
        headers, _partition = _enterprise_auth_context(self.config)
        return headers

    def _credential_partition(self) -> str:
        _headers, partition = _enterprise_auth_context(self.config)
        return partition

    def _request(
        self,
        url: str,
        *,
        allow_cross_origin_redirects: bool = False,
        max_response_bytes: int = _MAX_SKILL_RESPONSE_BYTES,
    ) -> Optional[httpx.Response]:
        try:
            headers = self._headers()
        except _EnterpriseAuthMissing:
            self.status = "unreachable"
            self.last_error = "auth_missing"
            return None
        verify: Union[bool, str] = self.config.get("ca_bundle") or True
        response = _guarded_http_get(
            url,
            timeout=30,
            headers=headers,
            allow_private_urls=self.config["allow_private_network"],
            allowed_origin=self._origin,
            allow_cross_origin_redirects=allow_cross_origin_redirects,
            max_response_bytes=max_response_bytes,
            verify=verify,
            trust_env=False,
        )
        if response is not None and response.status_code in {401, 403}:
            self.status = "unreachable"
            self.last_error = f"http_{response.status_code}"
        return response

    def _request_json(self, url: str) -> Optional[Any]:
        response = self._request(url)
        if response is None or response.status_code != 200:
            return None
        try:
            return response.json()
        except json.JSONDecodeError:
            return None

    def _search_cache_file(
        self,
        query: str,
        limit: int,
        credential_partition: str,
    ) -> Path:
        digest = hashlib.sha256(
            f"{self._base_url}\0{credential_partition}\0{query}\0{limit}".encode(
                "utf-8"
            )
        ).hexdigest()
        return _index_cache_dir() / (
            f"enterprise_clawhub_{self.config['id']}_{digest}.json"
        )

    def _read_search_cache(
        self,
        query: str,
        limit: int,
        *,
        credential_partition: str,
        fresh_only: bool,
    ) -> Optional[List[SkillMeta]]:
        cache_file = self._search_cache_file(query, limit, credential_partition)
        try:
            age = time.time() - cache_file.stat().st_mtime
            if fresh_only and age > INDEX_CACHE_TTL:
                return None
            payload = json.loads(cache_file.read_text(encoding="utf-8"))
            if not isinstance(payload, list):
                return None
            results = [SkillMeta(**item) for item in payload if isinstance(item, dict)]
            self.last_synced_at = datetime.fromtimestamp(
                cache_file.stat().st_mtime,
                timezone.utc,
            ).isoformat()
            return results
        except (OSError, TypeError, json.JSONDecodeError):
            return None

    def _write_search_cache(
        self,
        query: str,
        limit: int,
        results: List[SkillMeta],
        *,
        credential_partition: str,
    ) -> None:
        cache_file = self._search_cache_file(query, limit, credential_partition)
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = [
            {
                "name": item.name,
                "description": item.description,
                "source": item.source,
                "identifier": item.identifier,
                "trust_level": item.trust_level,
                "repo": item.repo,
                "path": item.path,
                "tags": item.tags,
                "extra": item.extra,
            }
            for item in results
        ]
        try:
            cache_file.write_text(
                json.dumps(payload, ensure_ascii=False),
                encoding="utf-8",
            )
            self.last_synced_at = datetime.now(timezone.utc).isoformat()
        except OSError as exc:
            logger.debug("Could not cache enterprise ClawHub search: %s", exc)


def create_enterprise_source(config: dict) -> SkillSource:
    """Create the configured enterprise adapter selected by its protocol."""
    normalized = normalize_enterprise_source_config(config)
    if normalized["protocol"] == "clawhub":
        return EnterpriseClawHubSource(normalized)
    return EnterpriseSkillSource(normalized)


# ---------------------------------------------------------------------------
# Direct URL source adapter
# ---------------------------------------------------------------------------

class UrlSource(SkillSource):
    """Fetch SKILL.md plus explicitly referenced, allowlisted support files.

    The identifier IS the URL (e.g. ``https://example.com/path/SKILL.md``).
    Bare URLs cannot safely enumerate a repository, so only exact references
    below references/templates/scripts/assets are fetched. Other repository
    files are never copied.

    The skill name is read from the ``name:`` field in the SKILL.md YAML
    frontmatter (with a URL-slug fallback). Trust level is always
    ``community`` and the same security scan runs as for every other source.
    """

    def source_id(self) -> str:
        return "url"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    # Search is meaningless for a direct URL — skip (return empty).
    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        return []

    def _matches(self, identifier: str) -> bool:
        """Return True iff this source should handle ``identifier``.

        We claim bare HTTP(S) URLs that end in ``.md`` (typically
        ``.../SKILL.md``). Wrapped identifiers (``github:``,
        ``well-known:``, etc.) and ``/.well-known/skills/`` URLs are
        left for their respective adapters.
        """
        if not isinstance(identifier, str):
            return False
        ident = identifier.strip()
        if not ident.lower().startswith(("http://", "https://")):
            return False
        # Don't steal well-known URLs.
        if "/.well-known/skills/" in ident or ident.rstrip("/").endswith("/index.json"):
            return False
        # Only claim URLs that look like a markdown file.
        try:
            path = urlparse(ident).path
        except ValueError:
            return False
        return path.lower().endswith(".md")

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        if not self._matches(identifier):
            return None
        url = identifier.strip()
        text = self._fetch_text(url)
        if text is None:
            return None
        fm = GitHubSource._parse_frontmatter_quick(text)
        name = self._resolve_skill_name(fm, url)
        description = str(fm.get("description") or "")
        tags: List[str] = []
        metadata = fm.get("metadata", {})
        if isinstance(metadata, dict):
            hermes_meta = metadata.get("hermes", {})
            if isinstance(hermes_meta, dict):
                raw_tags = hermes_meta.get("tags", [])
                if isinstance(raw_tags, list):
                    tags = [str(t) for t in raw_tags]
        return SkillMeta(
            name=name or "",
            description=description,
            source="url",
            identifier=url,
            trust_level="community",
            path=name or "",
            tags=tags,
            extra={"url": url, "awaiting_name": name is None},
        )

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        if not self._matches(identifier):
            return None
        url = identifier.strip()
        text = self._fetch_text(url)
        if text is None:
            return None

        fm = GitHubSource._parse_frontmatter_quick(text)
        name = self._resolve_skill_name(fm, url)
        referenced = _referenced_support_paths(text)
        if referenced is None:
            return None
        files: Dict[str, Union[str, bytes]] = {"SKILL.md": text}
        base_url = url.rsplit("/", 1)[0] + "/"
        for rel_path in sorted(referenced):
            support_url = urljoin(base_url, rel_path)
            if urlparse(support_url).netloc != urlparse(url).netloc:
                return None
            content = self._fetch_bytes(support_url)
            if content is None:
                return None
            files[rel_path] = content

        # When auto-resolution fails, return a bundle with an empty name and
        # ``awaiting_name=True`` in metadata. The install flow (``do_install``)
        # either prompts the user on a TTY or refuses with an actionable error
        # on non-interactive surfaces. Keep the expensive HTTP fetch's result
        # so the caller doesn't have to re-download after picking a name.
        skill_name = ""
        if name is not None:
            try:
                skill_name = _validate_skill_name(name)
            except ValueError:
                logger.warning("URL skill %s produced unsafe skill name: %r", url, name)
                return None

        return SkillBundle(
            name=skill_name,
            files=files,
            source="url",
            identifier=url,
            trust_level="community",
            metadata={"url": url, "source_url": url, "awaiting_name": not skill_name},
        )

    @staticmethod
    def _fetch_text(url: str) -> Optional[str]:
        resp = _guarded_http_get(url, timeout=20)
        if resp is not None and resp.status_code == 200:
            return resp.text
        return None

    @staticmethod
    def _fetch_bytes(url: str) -> Optional[bytes]:
        resp = _guarded_http_get(url, timeout=20)
        if resp is not None and resp.status_code == 200:
            return resp.content
        return None

    # Skill names must look like identifiers: lowercase letters/digits with
    # optional hyphens/underscores. Blocks dangerous (``../evil``) AND useless
    # (``SKILL``, ``README``, empty) candidates before they hit the disk.
    _VALID_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

    @classmethod
    def _is_valid_skill_name(cls, name: Optional[str]) -> bool:
        if not isinstance(name, str):
            return False
        candidate = name.strip().lower()
        if not candidate or candidate in {"skill", "readme", "index", "unnamed-skill"}:
            return False
        return bool(cls._VALID_NAME_RE.match(candidate))

    @classmethod
    def _resolve_skill_name(cls, fm: dict, url: str) -> Optional[str]:
        """Pick a skill name from frontmatter or URL.

        Returns ``None`` when neither source produces a valid identifier;
        callers (CLI ``do_install``) then prompt the user or refuse. Preferring
        a clean failure over a useless auto-name like ``SKILL`` or ``unnamed-skill``.
        """
        # 1. Frontmatter ``name:`` is authoritative when present and valid.
        fm_name = fm.get("name") if isinstance(fm, dict) else None
        if isinstance(fm_name, str) and cls._is_valid_skill_name(fm_name):
            return fm_name.strip()

        # 2. URL-slug heuristic: ``.../<name>/SKILL.md`` → ``<name>``;
        #    ``.../<name>.md`` → ``<name>``. Validate each candidate.
        try:
            path = urlparse(url).path
        except ValueError:
            return None
        parts = [p for p in path.split("/") if p]
        if parts and parts[-1].lower() == "skill.md" and len(parts) >= 2:
            candidate = parts[-2]
            if cls._is_valid_skill_name(candidate):
                return candidate
        if parts:
            candidate = re.sub(r"\.md$", "", parts[-1], flags=re.IGNORECASE)
            if cls._is_valid_skill_name(candidate):
                return candidate

        # Nothing usable — let the caller handle it.
        return None


# ---------------------------------------------------------------------------
# skills.sh source adapter
# ---------------------------------------------------------------------------

class SkillsShSource(SkillSource):
    """Discover skills via skills.sh and fetch content from the underlying GitHub repo."""

    BASE_URL = "https://skills.sh"
    SEARCH_URL = f"{BASE_URL}/api/search"
    # Sitemap index — the real catalog source. The homepage scrape only
    # exposes a curated featured strip (~200 entries); the sitemap covers
    # the full ~20k+ catalog. https://www.skills.sh/sitemap.xml points at
    # sitemap-skills-1.xml + sitemap-skills-2.xml, each up to 10k URLs.
    SITEMAP_INDEX_URL = "https://www.skills.sh/sitemap.xml"
    _SITEMAP_LOC_RE = re.compile(r"<loc>([^<]+)</loc>", re.IGNORECASE)
    _SITEMAP_SKILL_RE = re.compile(
        r"^https?://(?:www\.)?skills\.sh/(?P<owner>[^/]+)/(?P<repo>[^/]+)/(?P<skill>[^/]+)/?$",
        re.IGNORECASE,
    )
    _SKILL_LINK_RE = re.compile(r'href=["\']/(?P<id>(?!agents/|_next/|api/)[^"\'/]+/[^"\'/]+/[^"\'/]+)["\']')
    _INSTALL_CMD_RE = re.compile(
        r'npx\s+skills\s+add\s+(?P<repo>https?://github\.com/[^\s<]+|[^\s<]+)'
        r'(?:\s+--skill\s+(?P<skill>[^\s<]+))?',
        re.IGNORECASE,
    )
    _PAGE_H1_RE = re.compile(r'<h1[^>]*>(?P<title>.*?)</h1>', re.IGNORECASE | re.DOTALL)
    _PROSE_H1_RE = re.compile(
        r'<div[^>]*class=["\'][^"\']*prose[^"\']*["\'][^>]*>.*?<h1[^>]*>(?P<title>.*?)</h1>',
        re.IGNORECASE | re.DOTALL,
    )
    _PROSE_P_RE = re.compile(
        r'<div[^>]*class=["\'][^"\']*prose[^"\']*["\'][^>]*>.*?<p[^>]*>(?P<body>.*?)</p>',
        re.IGNORECASE | re.DOTALL,
    )
    _WEEKLY_INSTALLS_RE = re.compile(r'Weekly Installs.*?children\\":\\"(?P<count>[0-9.,Kk]+)\\"', re.DOTALL)

    def __init__(self, auth: GitHubAuth):
        self.auth = auth
        self.github = GitHubSource(auth=auth)

    def source_id(self) -> str:
        return "skills-sh"

    def trust_level_for(self, identifier: str) -> str:
        return self.github.trust_level_for(self._normalize_identifier(identifier))

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        if not query.strip():
            # Empty query = bulk catalog dump (what build_skills_index.py
            # calls with). The homepage scrape only sees ~200 featured
            # entries; the sitemap walks the full ~20k+ catalog.
            return self._sitemap_catalog(limit)

        cache_key = f"skills_sh_search_{hashlib.md5(f'{query}|{limit}'.encode()).hexdigest()}"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return [SkillMeta(**item) for item in cached][:limit]

        try:
            resp = httpx.get(
                self.SEARCH_URL,
                params={"q": query, "limit": limit},
                timeout=20,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return []

        items = data.get("skills", []) if isinstance(data, dict) else []
        if not isinstance(items, list):
            return []

        results: List[SkillMeta] = []
        for item in items[:limit]:
            meta = self._meta_from_search_item(item)
            if meta:
                results.append(meta)

        _write_index_cache(cache_key, [_skill_meta_to_dict(item) for item in results])
        return results

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        canonical = self._normalize_identifier(identifier)
        detail = self._fetch_detail_page(canonical)
        for candidate in self._candidate_identifiers(canonical):
            bundle = self.github.fetch(candidate)
            if bundle:
                bundle.source = "skills.sh"
                bundle.identifier = self._wrap_identifier(canonical)
                bundle.metadata.update(self._detail_to_metadata(canonical, detail))
                return bundle

        resolved = self._discover_identifier(canonical, detail=detail)
        if resolved:
            bundle = self.github.fetch(resolved)
            if bundle:
                bundle.source = "skills.sh"
                bundle.identifier = self._wrap_identifier(canonical)
                bundle.metadata.update(self._detail_to_metadata(canonical, detail))
                return bundle
        return None

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        canonical = self._normalize_identifier(identifier)
        detail = self._fetch_detail_page(canonical)
        meta = self._resolve_github_meta(canonical, detail=detail)
        if meta:
            return self._finalize_inspect_meta(meta, canonical, detail)
        return None

    def _sitemap_catalog(self, limit: int) -> List[SkillMeta]:
        """Walk the skills.sh sitemap to enumerate the full catalog.

        Cached for the standard index TTL so we don't refetch ~2 MB of
        sitemap XML per build. Falls back to ``_featured_skills`` if the
        sitemap is unreachable or empty (network failure, hostname
        change, etc.).
        """
        cache_key = "skills_sh_sitemap_v1"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            metas = [SkillMeta(**item) for item in cached]
            return metas[:limit] if limit > 0 else metas

        # skills.sh serves the per-skill sitemaps brotli-compressed, and
        # httpx's optional brotlicffi backend has a streaming-decode bug
        # that fails on these specific payloads. Excluding "br" from
        # Accept-Encoding makes the server fall back to gzip (or
        # identity), which works on every httpx install.
        sitemap_headers = {"Accept-Encoding": "gzip"}

        # Step 1: fetch the sitemap index → list of skill-sitemap URLs.
        skill_sitemap_urls: List[str] = []
        try:
            resp = httpx.get(
                self.SITEMAP_INDEX_URL,
                timeout=20,
                follow_redirects=True,
                headers=sitemap_headers,
            )
            if resp.status_code != 200:
                return self._featured_skills(limit)
            for match in self._SITEMAP_LOC_RE.finditer(resp.text):
                loc = match.group(1).strip()
                # Sitemap index entries that point at the per-skill maps.
                if "sitemap-skills" in loc:
                    skill_sitemap_urls.append(loc)
        except httpx.HTTPError:
            return self._featured_skills(limit)

        if not skill_sitemap_urls:
            return self._featured_skills(limit)

        # Step 2: fetch each skill sitemap and collect canonical "owner/repo/skill" IDs.
        seen: set[str] = set()
        results: List[SkillMeta] = []
        for sitemap_url in skill_sitemap_urls:
            try:
                resp = httpx.get(
                    sitemap_url,
                    timeout=30,
                    follow_redirects=True,
                    headers=sitemap_headers,
                )
                if resp.status_code != 200:
                    continue
            except httpx.HTTPError:
                continue
            for loc_match in self._SITEMAP_LOC_RE.finditer(resp.text):
                url = loc_match.group(1).strip()
                m = self._SITEMAP_SKILL_RE.match(url)
                if not m:
                    continue
                owner = m.group("owner")
                repo_name = m.group("repo")
                skill_name = m.group("skill")
                canonical = f"{owner}/{repo_name}/{skill_name}"
                if canonical in seen:
                    continue
                seen.add(canonical)
                repo = f"{owner}/{repo_name}"
                results.append(SkillMeta(
                    name=skill_name,
                    description=f"Indexed by skills.sh from {repo}",
                    source="skills.sh",
                    identifier=self._wrap_identifier(canonical),
                    trust_level=self.github.trust_level_for(canonical),
                    repo=repo,
                    path=skill_name,
                    extra={
                        "detail_url": f"{self.BASE_URL}/{canonical}",
                        "repo_url": f"https://github.com/{repo}",
                    },
                ))

        if not results:
            return self._featured_skills(limit)

        _write_index_cache(cache_key, [_skill_meta_to_dict(item) for item in results])
        return results[:limit] if limit > 0 else results

    def _featured_skills(self, limit: int) -> List[SkillMeta]:
        cache_key = "skills_sh_featured"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return [SkillMeta(**item) for item in cached][:limit]

        try:
            resp = httpx.get(self.BASE_URL, timeout=20)
            if resp.status_code != 200:
                return []
        except httpx.HTTPError:
            return []

        seen: set[str] = set()
        results: List[SkillMeta] = []
        for match in self._SKILL_LINK_RE.finditer(resp.text):
            canonical = match.group("id")
            if canonical in seen:
                continue
            seen.add(canonical)
            parts = canonical.split("/", 2)
            if len(parts) < 3:
                continue
            repo = f"{parts[0]}/{parts[1]}"
            skill_path = parts[2]
            results.append(SkillMeta(
                name=skill_path.split("/")[-1],
                description=f"Featured on skills.sh from {repo}",
                source="skills.sh",
                identifier=self._wrap_identifier(canonical),
                trust_level=self.github.trust_level_for(canonical),
                repo=repo,
                path=skill_path,
            ))
            if len(results) >= limit:
                break

        _write_index_cache(cache_key, [_skill_meta_to_dict(item) for item in results])
        return results

    def _meta_from_search_item(self, item: dict) -> Optional[SkillMeta]:
        if not isinstance(item, dict):
            return None

        canonical = item.get("id")
        repo = item.get("source")
        skill_path = item.get("skillId")
        if not isinstance(canonical, str) or canonical.count("/") < 2:
            if not (isinstance(repo, str) and isinstance(skill_path, str)):
                return None
            canonical = f"{repo}/{skill_path}"

        parts = canonical.split("/", 2)
        if len(parts) < 3:
            return None

        repo = f"{parts[0]}/{parts[1]}"
        skill_path = parts[2]
        installs = item.get("installs")
        installs_label = f" · {int(installs):,} installs" if isinstance(installs, int) else ""

        return SkillMeta(
            name=str(item.get("name") or skill_path.split("/")[-1]),
            description=f"Indexed by skills.sh from {repo}{installs_label}",
            source="skills.sh",
            identifier=self._wrap_identifier(canonical),
            trust_level=self.github.trust_level_for(canonical),
            repo=repo,
            path=skill_path,
            extra={
                "installs": installs,
                "detail_url": f"{self.BASE_URL}/{canonical}",
                "repo_url": f"https://github.com/{repo}",
            },
        )

    def _fetch_detail_page(self, identifier: str) -> Optional[dict]:
        cache_key = f"skills_sh_detail_{hashlib.md5(identifier.encode()).hexdigest()}"
        cached = _read_index_cache(cache_key)
        if isinstance(cached, dict):
            return cached

        try:
            resp = httpx.get(f"{self.BASE_URL}/{identifier}", timeout=20)
            if resp.status_code != 200:
                return None
        except httpx.HTTPError:
            return None

        detail = self._parse_detail_page(identifier, resp.text)
        if detail:
            _write_index_cache(cache_key, detail)
        return detail

    def _parse_detail_page(self, identifier: str, html: str) -> Optional[dict]:
        parts = identifier.split("/", 2)
        if len(parts) < 3:
            return None

        default_repo = f"{parts[0]}/{parts[1]}"
        skill_token = parts[2]
        repo = default_repo
        install_skill = skill_token

        install_command = None
        install_match = self._INSTALL_CMD_RE.search(html)
        if install_match:
            install_command = install_match.group(0).strip()
            repo_value = (install_match.group("repo") or "").strip()
            install_skill = (install_match.group("skill") or install_skill).strip()
            repo = self._extract_repo_slug(repo_value) or repo

        page_title = self._extract_first_match(self._PAGE_H1_RE, html)
        body_title = self._extract_first_match(self._PROSE_H1_RE, html)
        body_summary = self._extract_first_match(self._PROSE_P_RE, html)
        weekly_installs = self._extract_weekly_installs(html)
        security_audits = self._extract_security_audits(html, identifier)

        return {
            "repo": repo,
            "install_skill": install_skill,
            "page_title": page_title,
            "body_title": body_title,
            "body_summary": body_summary,
            "weekly_installs": weekly_installs,
            "install_command": install_command,
            "repo_url": f"https://github.com/{repo}",
            "detail_url": f"{self.BASE_URL}/{identifier}",
            "security_audits": security_audits,
        }

    def _discover_identifier(self, identifier: str, detail: Optional[dict] = None) -> Optional[str]:
        parts = identifier.split("/", 2)
        if len(parts) < 3:
            return None

        default_repo = f"{parts[0]}/{parts[1]}"
        repo = detail.get("repo", default_repo) if isinstance(detail, dict) else default_repo
        skill_token=parts[2].split("/")[-1]
        tokens=[skill_token]
        if isinstance(detail, dict):
            tokens.extend([
                detail.get("install_skill", ""),
                detail.get("page_title", ""),
                detail.get("body_title", ""),
            ])

        # Standard skill paths
        base_paths = ["skills/", ".agents/skills/", ".claude/skills/"]

        for base_path in base_paths:
            try:
                skills = self.github._list_skills_in_repo(repo, base_path)
            except Exception:
                continue
            for meta in skills:
                if self._matches_skill_tokens(meta, tokens):
                    return meta.identifier

        # Prefer a single recursive tree lookup before brute-forcing every
        # top-level directory. This avoids large request bursts on categorized
        # repos like borghei/claude-skills.
        tree_result = self.github._find_skill_in_repo_tree(repo, skill_token)
        if tree_result:
            return tree_result

        # Fallback: scan repo root for directories that might contain skills
        try:
            root_url = f"https://api.github.com/repos/{repo}/contents/"
            resp = httpx.get(root_url, headers=self.github.auth.get_headers(),
                             timeout=15, follow_redirects=True)
            if resp.status_code == 200:
                entries = resp.json()
                if isinstance(entries, list):
                    for entry in entries:
                        if entry.get("type") != "dir":
                            continue
                        dir_name = entry["name"]
                        if dir_name.startswith((".", "_")):
                            continue
                        if dir_name in {"skills", ".agents", ".claude"}:
                            continue  # already tried
                        # Try direct: repo/dir/skill_token
                        direct_id = f"{repo}/{dir_name}/{skill_token}"
                        meta = self.github.inspect(direct_id)
                        if meta:
                            return meta.identifier
                        # Try listing skills in this directory
                        try:
                            skills = self.github._list_skills_in_repo(repo, dir_name + "/")
                        except Exception:
                            continue
                        for meta in skills:
                            if self._matches_skill_tokens(meta, tokens):
                                return meta.identifier
        except Exception:
            pass

        return None

    def _resolve_github_meta(self, identifier: str, detail: Optional[dict] = None) -> Optional[SkillMeta]:
        for candidate in self._candidate_identifiers(identifier):
            meta = self.github.inspect(candidate)
            if meta:
                return meta

        resolved = self._discover_identifier(identifier, detail=detail)
        if resolved:
            return self.github.inspect(resolved)
        return None

    def _finalize_inspect_meta(self, meta: SkillMeta, canonical: str, detail: Optional[dict]) -> SkillMeta:
        meta.source = "skills.sh"
        meta.identifier = self._wrap_identifier(canonical)
        meta.trust_level = self.trust_level_for(canonical)
        merged_extra = dict(meta.extra)
        merged_extra.update(self._detail_to_metadata(canonical, detail))
        meta.extra = merged_extra

        if isinstance(detail, dict):
            body_summary = detail.get("body_summary")
            weekly_installs = detail.get("weekly_installs")
            if body_summary:
                meta.description = body_summary
            elif meta.description and weekly_installs:
                meta.description = f"{meta.description} · {weekly_installs} weekly installs on skills.sh"
        return meta

    @classmethod
    def _matches_skill_tokens(cls, meta: SkillMeta, skill_tokens: List[str]) -> bool:
        candidates = set()
        candidates.update(cls._token_variants(meta.name))
        candidates.update(cls._token_variants(meta.path))
        candidates.update(cls._token_variants(meta.identifier.split("/", 2)[-1] if meta.identifier else None))

        for token in skill_tokens:
            variants = cls._token_variants(token)
            if variants & candidates:
                return True
        return False

    @staticmethod
    def _token_variants(value: Optional[str]) -> set[str]:
        if not value:
            return set()

        plain = SkillsShSource._strip_html(str(value)).strip().strip("/").lower()
        if not plain:
            return set()

        base = plain.split("/")[-1]
        sanitized = re.sub(r'[^a-z0-9/_-]+', '-', plain).strip('-')
        sanitized_base = sanitized.split("/")[-1] if sanitized else ""
        slash_tail = plain.split("/")[-1]
        slash_tail_clean = slash_tail.lstrip('@')
        slash_tail_clean = slash_tail_clean.split('/')[-1]

        variants = {
            plain,
            plain.replace("_", "-"),
            plain.replace("/", "-"),
            base,
            base.replace("_", "-"),
            base.replace("/", "-"),
            sanitized,
            sanitized.replace("/", "-") if sanitized else "",
            sanitized_base,
            slash_tail_clean,
            slash_tail_clean.replace("_", "-"),
        }
        return {v for v in variants if v}

    @staticmethod
    def _extract_repo_slug(repo_value: str) -> Optional[str]:
        repo_value = repo_value.strip()
        if repo_value.startswith("https://github.com/"):
            repo_value = repo_value[len("https://github.com/"):]
        repo_value = repo_value.strip("/")
        parts = repo_value.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        return None

    @staticmethod
    def _extract_first_match(pattern: re.Pattern, text: str) -> Optional[str]:
        match = pattern.search(text)
        if not match:
            return None
        value = next((group for group in match.groups() if group), None)
        if value is None:
            return None
        return SkillsShSource._strip_html(value).strip() or None

    def _detail_to_metadata(self, canonical: str, detail: Optional[dict]) -> Dict[str, Any]:
        parts = canonical.split("/", 2)
        repo = f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else ""
        metadata = {
            "detail_url": f"{self.BASE_URL}/{canonical}",
        }
        if repo:
            metadata["repo_url"] = f"https://github.com/{repo}"
        if isinstance(detail, dict):
            for key in ("weekly_installs", "install_command", "repo_url", "detail_url", "security_audits"):
                value = detail.get(key)
                if value:
                    metadata[key] = value
        return metadata

    @staticmethod
    def _extract_weekly_installs(html: str) -> Optional[str]:
        match = SkillsShSource._WEEKLY_INSTALLS_RE.search(html)
        if not match:
            return None
        return match.group("count")

    @staticmethod
    def _extract_security_audits(html: str, identifier: str) -> Dict[str, str]:
        audits: Dict[str, str] = {}
        for audit in ("agent-trust-hub", "socket", "snyk"):
            idx = html.find(f"/security/{audit}")
            if idx == -1:
                continue
            window = html[idx:idx + 500]
            match = re.search(r'(Pass|Warn|Fail)', window, re.IGNORECASE)
            if match:
                audits[audit] = match.group(1).title()
        return audits

    @staticmethod
    def _strip_html(value: str) -> str:
        return re.sub(r'<[^>]+>', '', value)

    @staticmethod
    def _normalize_identifier(identifier: str) -> str:
        prefix_aliases = (
            "skills-sh/",
            "skills.sh/",
            "skils-sh/",
            "skils.sh/",
        )
        for prefix in prefix_aliases:
            if identifier.startswith(prefix):
                return identifier[len(prefix):]
        return identifier

    @staticmethod
    def _candidate_identifiers(identifier: str) -> List[str]:
        parts = identifier.split("/", 2)
        if len(parts) < 3:
            return [identifier]

        repo = f"{parts[0]}/{parts[1]}"
        skill_path = parts[2].lstrip("/")
        candidates = [
            f"{repo}/{skill_path}",
            f"{repo}/skills/{skill_path}",
            f"{repo}/.agents/skills/{skill_path}",
            f"{repo}/.claude/skills/{skill_path}",
        ]

        seen = set()
        deduped: List[str] = []
        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                deduped.append(candidate)
        return deduped

    @staticmethod
    def _wrap_identifier(identifier: str) -> str:
        return f"skills-sh/{identifier}"


# ---------------------------------------------------------------------------
# ClawHub source adapter
# ---------------------------------------------------------------------------

class ClawHubSource(SkillSource):
    """
    Fetch skills from ClawHub (clawhub.ai) via their HTTP API.
    All skills are treated as community trust — ClawHavoc incident showed
    their vetting is insufficient (341 malicious skills found Feb 2026).
    """

    BASE_URL = "https://clawhub.ai/api/v1"

    # Wall-clock budget for a full catalog walk. ClawHub has 50k+ skills and
    # the walk is sequential (~250 requests, each under per-request
    # timeout=30 so nothing errors), so an unbounded walk can block for
    # minutes. Bound it so a slow/large catalog cannot hang the caller.
    CATALOG_WALK_BUDGET_SECONDS = 12

    def source_id(self) -> str:
        return "clawhub"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    @staticmethod
    def _normalize_tags(tags: Any) -> List[str]:
        if isinstance(tags, list):
            return [str(t) for t in tags]
        if isinstance(tags, dict):
            return [str(k) for k in tags if str(k) != "latest"]
        return []

    @staticmethod
    def _coerce_skill_payload(data: Any) -> Optional[Dict[str, Any]]:
        if not isinstance(data, dict):
            return None
        nested = data.get("skill")
        if isinstance(nested, dict):
            merged = dict(nested)
            latest_version = data.get("latestVersion")
            if latest_version is not None and "latestVersion" not in merged:
                merged["latestVersion"] = latest_version
            # Carry over top-level fields that the listing API nests alongside
            # the skill object — owner is needed for building valid detail URLs.
            if "owner" in data and "owner" not in merged:
                merged["owner"] = data["owner"]
            return merged
        return data

    @staticmethod
    def _query_terms(query: str) -> List[str]:
        return [term for term in re.split(r"[^a-z0-9]+", query.lower()) if term]

    @classmethod
    def _search_score(cls, query: str, meta: SkillMeta) -> int:
        query_norm = query.strip().lower()
        if not query_norm:
            return 1

        identifier = (meta.identifier or "").lower()
        name = (meta.name or "").lower()
        description = (meta.description or "").lower()
        normalized_identifier = " ".join(cls._query_terms(identifier))
        normalized_name = " ".join(cls._query_terms(name))
        query_terms = cls._query_terms(query_norm)
        identifier_terms = cls._query_terms(identifier)
        name_terms = cls._query_terms(name)
        score = 0

        if query_norm == identifier:
            score += 140
        if query_norm == name:
            score += 130
        if normalized_identifier == query_norm:
            score += 125
        if normalized_name == query_norm:
            score += 120
        if normalized_identifier.startswith(query_norm):
            score += 95
        if normalized_name.startswith(query_norm):
            score += 90
        if query_terms and identifier_terms[: len(query_terms)] == query_terms:
            score += 70
        if query_terms and name_terms[: len(query_terms)] == query_terms:
            score += 65
        if query_norm in identifier:
            score += 40
        if query_norm in name:
            score += 35
        if query_norm in description:
            score += 10

        for term in query_terms:
            if term in identifier_terms:
                score += 15
            if term in name_terms:
                score += 12
            if term in description:
                score += 3

        return score

    @staticmethod
    def _dedupe_results(results: List[SkillMeta]) -> List[SkillMeta]:
        seen: set[str] = set()
        deduped: List[SkillMeta] = []
        for result in results:
            key = (result.identifier or result.name).lower()
            if key in seen:
                continue
            seen.add(key)
            deduped.append(result)
        return deduped

    def _exact_slug_meta(self, query: str) -> Optional[SkillMeta]:
        query = query.strip()
        parsed = self._parse_identifier(query)
        query_terms = self._query_terms(query)
        candidates: List[str] = []

        if parsed:
            candidates.append(parsed[0])
        elif "/" not in query and self._SLUG_RE.fullmatch(query):
            candidates.append(query)

        if query_terms:
            base_slug = "-".join(query_terms)
            if len(query_terms) >= 2:
                candidates.extend([
                    f"{base_slug}-agent",
                    f"{base_slug}-skill",
                    f"{base_slug}-tool",
                    f"{base_slug}-assistant",
                    f"{base_slug}-playbook",
                    base_slug,
                ])
            else:
                candidates.append(base_slug)

        seen: set[str] = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            meta = self.inspect(candidate)
            if meta:
                return meta

        return None

    def _finalize_search_results(self, query: str, results: List[SkillMeta], limit: int) -> List[SkillMeta]:
        query_norm = query.strip()
        if not query_norm:
            return self._dedupe_results(results)[:limit]

        filtered = [meta for meta in results if self._search_score(query_norm, meta) > 0]
        filtered.sort(
            key=lambda meta: (
                -self._search_score(query_norm, meta),
                meta.name.lower(),
                meta.identifier.lower(),
            )
        )
        filtered = self._dedupe_results(filtered)

        exact = self._exact_slug_meta(query_norm)
        if exact:
            filtered = [meta for meta in filtered if self._search_score(query_norm, meta) >= 20]
            filtered = self._dedupe_results([exact] + filtered)

        if filtered:
            return filtered[:limit]

        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", query_norm):
            return []

        return self._dedupe_results(results)[:limit]

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        query = query.strip()

        if query:
            query_terms = self._query_terms(query)
            if len(query_terms) >= 2:
                direct = self._exact_slug_meta(query)
                if direct:
                    return [direct]

            results = self._search_catalog(query, limit=limit)
            if results:
                return results
        else:
            # Empty query: route through the paginating catalog walker. When
            # the full catalog is already disk-cached this returns it whole and
            # the caller paginates client-side. On a cold cache, bound the walk
            # to `limit` so a browse command renders its first page without
            # walking the entire 50k+ catalog (max_items=0 → unbounded, used
            # only by the offline index builder via search("", limit=0)).
            catalog = self._load_catalog_index(max_items=limit if limit > 0 else 0)
            if catalog:
                return self._dedupe_results(catalog)[:limit] if limit > 0 else self._dedupe_results(catalog)

        # Non-empty query catalog miss, or catalog walker failure: fall back to
        # the lightweight listing API for a best-effort response.
        cache_key = f"clawhub_search_listing_v1_{hashlib.md5(query.encode()).hexdigest()}_{limit}"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return self._finalize_search_results(
                query,
                [SkillMeta(**s) for s in cached],
                limit,
            )

        try:
            resp = httpx.get(
                f"{self.BASE_URL}/skills",
                params={"search": query, "limit": limit},
                timeout=15,
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return []

        skills_data = data.get("items", data) if isinstance(data, dict) else data
        if not isinstance(skills_data, list):
            return []

        results = []
        for item in skills_data[:limit]:
            slug = item.get("slug")
            if not slug:
                continue
            display_name = item.get("displayName") or item.get("name") or slug
            summary = item.get("summary") or item.get("description") or ""
            tags = self._normalize_tags(item.get("tags", []))
            extra: Dict[str, Any] = {}
            owner = item.get("owner")
            if isinstance(owner, dict):
                handle = owner.get("handle")
                if isinstance(handle, str) and handle:
                    extra["owner"] = handle
            elif isinstance(owner, str) and owner:
                extra["owner"] = owner
            results.append(SkillMeta(
                name=display_name,
                description=summary,
                source="clawhub",
                identifier=slug,
                trust_level="community",
                tags=tags,
                extra=extra,
            ))

        final_results = self._finalize_search_results(query, results, limit)
        _write_index_cache(cache_key, [_skill_meta_to_dict(s) for s in final_results])
        return final_results

    _SLUG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*$")

    @classmethod
    def _parse_identifier(cls, identifier: str) -> Optional[Tuple[str, Optional[str]]]:
        """Return ``(slug, expected_owner)`` for a ClawHub identifier.

        Accepts a bare slug, ``clawhub/<slug>``, ``@owner/slug``, and the
        clawhub.ai URL path ``owner/skills/slug``. GitHub-style
        ``owner/repo/skill`` and ``owner/repo/skills/skill`` identifiers
        are not ClawHub's — claiming them by last path segment installs
        a same-named skill from a different author.
        """
        raw = (identifier or "").strip()
        if not raw:
            return None
        had_at = raw.startswith("@")
        ident = raw[1:] if had_at else raw
        if ident.startswith("clawhub/"):
            ident = ident[len("clawhub/"):]
        parts = [part for part in ident.split("/") if part]
        if len(parts) == 1:
            slug = parts[0]
            return (slug, None) if cls._SLUG_RE.fullmatch(slug) else None
        if len(parts) == 2 and had_at:
            owner, slug = parts
            if cls._SLUG_RE.fullmatch(owner) and cls._SLUG_RE.fullmatch(slug):
                return slug, owner
            return None
        if len(parts) == 3 and parts[1].lower() == "skills":
            owner, _, slug = parts
            if cls._SLUG_RE.fullmatch(owner) and cls._SLUG_RE.fullmatch(slug):
                return slug, owner
            return None
        return None

    @staticmethod
    def _owner_from_payload(data: Optional[Dict[str, Any]]) -> Optional[str]:
        if not isinstance(data, dict):
            return None
        owner = data.get("owner")
        if isinstance(owner, dict):
            handle = owner.get("handle")
            if isinstance(handle, str) and handle.strip():
                return handle.strip()
        if isinstance(owner, str) and owner.strip():
            return owner.strip()
        return None

    @classmethod
    def _owner_matches(cls, expected_owner: Optional[str], data: Optional[Dict[str, Any]]) -> bool:
        if not expected_owner:
            return True
        actual = cls._owner_from_payload(data)
        if not actual:
            return True
        return actual.lower() == expected_owner.lower()

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        parsed = self._parse_identifier(identifier)
        if parsed is None:
            return None
        slug, expected_owner = parsed

        skill_data = self._coerce_skill_payload(self._get_json(f"{self.BASE_URL}/skills/{slug}"))
        if not isinstance(skill_data, dict):
            return None
        if not self._owner_matches(expected_owner, skill_data):
            return None

        latest_version = self._resolve_latest_version(slug, skill_data)
        if not latest_version:
            logger.warning("ClawHub fetch failed for %s: could not resolve latest version", slug)
            return None

        # Primary method: download the skill as a ZIP bundle from /download
        files = self._download_zip(slug, latest_version)

        # Fallback: try the version metadata endpoint for inline/raw content
        if "SKILL.md" not in files:
            version_data = self._get_json(f"{self.BASE_URL}/skills/{slug}/versions/{latest_version}")
            if isinstance(version_data, dict):
                # Files may be nested under version_data["version"]["files"]
                files = self._extract_files(version_data) or files
                if "SKILL.md" not in files:
                    nested = version_data.get("version", {})
                    if isinstance(nested, dict):
                        files = self._extract_files(nested) or files

        if "SKILL.md" not in files:
            logger.warning(
                "ClawHub fetch for %s resolved version %s but could not retrieve file content",
                slug,
                latest_version,
            )
            return None

        return SkillBundle(
            name=slug,
            files=files,
            source="clawhub",
            identifier=slug,
            trust_level="community",
        )

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        parsed = self._parse_identifier(identifier)
        if parsed is None:
            return None
        slug, expected_owner = parsed
        data = self._coerce_skill_payload(self._get_json(f"{self.BASE_URL}/skills/{slug}"))
        if not isinstance(data, dict):
            return None
        if not self._owner_matches(expected_owner, data):
            return None

        tags = self._normalize_tags(data.get("tags", []))
        extra: Dict[str, Any] = {}
        # The detail API returns owner info — capture it so callers can build
        # valid ClawHub URLs (https://clawhub.ai/{owner}/skills/{slug}).
        owner = self._owner_from_payload(data)
        if owner:
            extra["owner"] = owner

        return SkillMeta(
            name=data.get("displayName") or data.get("name") or data.get("slug") or slug,
            description=data.get("summary") or data.get("description") or "",
            source="clawhub",
            identifier=data.get("slug") or slug,
            trust_level="community",
            tags=tags,
            extra=extra,
        )

    def _search_catalog(self, query: str, limit: int = 10) -> List[SkillMeta]:
        cache_key = f"clawhub_search_catalog_v1_{hashlib.md5(f'{query}|{limit}'.encode()).hexdigest()}"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return [SkillMeta(**s) for s in cached][:limit]

        catalog = self._load_catalog_index()
        if not catalog:
            return []

        results = self._finalize_search_results(query, catalog, limit)
        _write_index_cache(cache_key, [_skill_meta_to_dict(s) for s in results])
        return results

    def _load_catalog_index(self, max_items: int = 0) -> List[SkillMeta]:
        """Walk the ClawHub catalog via cursor pagination.

        ``max_items`` bounds the walk: once at least that many distinct skills
        have been gathered the walk stops early. This is what browse's
        cold-start fallback wants — it only renders one page, so walking the
        entire 50k+ catalog just to slice off the first N is pure waste.
        ``max_items=0`` (the default, used by the offline index builder) means
        walk to exhaustion.

        Caching: only a *complete* catalog (cursor exhausted or page cap) is
        written to the shared ``clawhub_catalog_v1`` cache. A walk truncated by
        ``max_items`` OR the wall-clock budget is partial, so caching it would
        poison the full-catalog cache with an incomplete slice.
        """
        cache_key = "clawhub_catalog_v1"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return [SkillMeta(**s) for s in cached]

        cursor: Optional[str] = None
        results: List[SkillMeta] = []
        seen: set[str] = set()
        # ClawHub has 50k+ skills as of May 2026 (live E2E walked 49,698 with
        # an active cursor still pending); 750 pages * 200/page = 150k ceiling
        # leaves room for catalog growth. Walk-to-exhaustion typically
        # terminates well before this on `nextCursor` going None — the cap is
        # a safety rail against an infinite-cursor loop.
        max_pages = 750
        # Wall-clock budget is for interactive browse (max_items > 0) only.
        # The offline index builder passes max_items=0 and must walk the full
        # catalog — a 12s cap there ships ~3k skills and trips the deploy
        # health floor (20k).
        deadline = (
            time.monotonic() + self.CATALOG_WALK_BUDGET_SECONDS
            if max_items > 0
            else None
        )
        hit_deadline = False
        hit_max_items = False

        for _ in range(max_pages):
            if deadline is not None and time.monotonic() > deadline:
                hit_deadline = True
                break
            params: Dict[str, Any] = {"limit": 200}
            if cursor:
                params["cursor"] = cursor

            try:
                resp = httpx.get(f"{self.BASE_URL}/skills", params=params, timeout=30)
                if resp.status_code != 200:
                    break
                data = resp.json()
            except (httpx.HTTPError, json.JSONDecodeError):
                break

            items = data.get("items", []) if isinstance(data, dict) else []
            if not isinstance(items, list) or not items:
                break

            for item in items:
                slug = item.get("slug")
                if not isinstance(slug, str) or not slug or slug in seen:
                    continue
                seen.add(slug)
                display_name = item.get("displayName") or item.get("name") or slug
                summary = item.get("summary") or item.get("description") or ""
                tags = self._normalize_tags(item.get("tags", []))
                extra: Dict[str, Any] = {}
                owner = self._owner_from_payload(item)
                if owner:
                    extra["owner"] = owner
                results.append(SkillMeta(
                    name=display_name,
                    description=summary,
                    source="clawhub",
                    identifier=slug,
                    trust_level="community",
                    tags=tags,
                    extra=extra,
                ))

            cursor = data.get("nextCursor") if isinstance(data, dict) else None
            if not isinstance(cursor, str) or not cursor:
                break

            # Browse's cold-start fallback only renders one page, so stop as
            # soon as we have enough to satisfy the caller's bound. The index
            # builder passes max_items=0 (unbounded) and walks to exhaustion.
            if max_items > 0 and len(results) >= max_items:
                hit_max_items = True
                break

        # Only cache a walk that reached a natural stop (cursor exhausted or
        # page cap). A walk truncated by the wall-clock budget OR by max_items
        # is partial, so writing it would poison the shared full-catalog cache
        # with incomplete data.
        if not hit_deadline and not hit_max_items:
            _write_index_cache(cache_key, [_skill_meta_to_dict(s) for s in results])
        return results

    def _get_json(self, url: str, timeout: int = 20) -> Optional[Any]:
        try:
            resp = httpx.get(url, timeout=timeout)
            if resp.status_code != 200:
                return None
            return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

    def _resolve_latest_version(self, slug: str, skill_data: Dict[str, Any]) -> Optional[str]:
        latest = skill_data.get("latestVersion")
        if isinstance(latest, dict):
            version = latest.get("version")
            if isinstance(version, str) and version:
                return version

        tags = skill_data.get("tags")
        if isinstance(tags, dict):
            latest_tag = tags.get("latest")
            if isinstance(latest_tag, str) and latest_tag:
                return latest_tag

        versions_data = self._get_json(f"{self.BASE_URL}/skills/{slug}/versions")
        if isinstance(versions_data, list) and versions_data:
            first = versions_data[0]
            if isinstance(first, dict):
                version = first.get("version")
                if isinstance(version, str) and version:
                    return version
        return None

    def _fetch_owner_handle(self, slug: str) -> Optional[str]:
        """Fetch the owner handle for a single ClawHub skill via the detail API.

        Returns the owner handle string, or None if unavailable.
        The detail endpoint at ``/api/v1/skills/{slug}`` returns an ``owner``
        object with a ``handle`` field — the listing API does not include this.

        Retry semantics (bounded):
        - Up to 3 attempts total (initial + 2 retries).
        - On HTTP 429: respects ``Retry-After`` header (seconds) when present,
          otherwise exponential backoff (2s → 4s).
        - On HTTP 5xx: exponential backoff (transient server errors).
        - On HTTP 4xx (non-429): no retry — the resource doesn't exist.
        """
        url = f"{self.BASE_URL}/skills/{slug}"
        max_attempts = 3
        backoff_base = 2.0  # seconds

        for attempt in range(max_attempts):
            try:
                resp = httpx.get(url, timeout=20)
            except (httpx.HTTPError, OSError):
                # Network/transport error — treat as transient, retry with backoff.
                if attempt < max_attempts - 1:
                    delay = backoff_base * (2 ** attempt)
                    logger.debug(
                        "_fetch_owner_handle(%s): transport error on attempt %d/%d, "
                        "retrying in %.1fs",
                        slug, attempt + 1, max_attempts, delay,
                    )
                    time.sleep(delay)
                    continue
                return None

            if resp.status_code == 200:
                try:
                    raw = resp.json()
                except (json.JSONDecodeError, ValueError):
                    return None
                data = self._coerce_skill_payload(raw)
                if not isinstance(data, dict):
                    return None
                return self._owner_from_payload(data)

            if resp.status_code == 429:
                # Rate-limited — honour Retry-After if present, else backoff.
                if attempt < max_attempts - 1:
                    retry_after_raw = resp.headers.get("Retry-After")
                    try:
                        delay = float(retry_after_raw) if retry_after_raw else backoff_base * (2 ** attempt)
                    except (TypeError, ValueError):
                        delay = backoff_base * (2 ** attempt)
                    logger.debug(
                        "_fetch_owner_handle(%s): HTTP 429 on attempt %d/%d, "
                        "retrying in %.1fs",
                        slug, attempt + 1, max_attempts, delay,
                    )
                    time.sleep(delay)
                    continue
                return None

            if 500 <= resp.status_code < 600:
                # Transient server error — retry with backoff.
                if attempt < max_attempts - 1:
                    delay = backoff_base * (2 ** attempt)
                    logger.debug(
                        "_fetch_owner_handle(%s): HTTP %d on attempt %d/%d, "
                        "retrying in %.1fs",
                        slug, resp.status_code, attempt + 1, max_attempts, delay,
                    )
                    time.sleep(delay)
                    continue
                return None

            # 4xx (non-429) — resource doesn't exist / bad request. No retry.
            return None

        return None

    def enrich_owners(self, skills: List[SkillMeta], max_workers: int = 30) -> int:
        """Batch-fetch owner handles for ClawHub skills missing ``extra["owner"]``.

        Mutates each SkillMeta in-place, setting ``extra["owner"]`` when the
        detail API returns a handle. Returns the number of skills enriched.

        This is intended for the offline index builder, which walks the full
        50k+ catalog. The listing API does not include owner info, so we
        fetch each skill's detail page concurrently. With ``max_workers=30``
        the full catalog takes ~5–10 minutes — acceptable for a twice-daily
        batch job.

        Safety rails:
        - Aborts early if 50 consecutive requests all fail (systemic outage).
        - Respects HTTP 429 rate-limit responses with exponential backoff.
        - Logs progress every 1000 skills so the batch job is observable.
        """
        needs_enrichment = [
            s for s in skills
            if s.source == "clawhub" and not (s.extra or {}).get("owner")
        ]
        if not needs_enrichment:
            return 0

        enriched = 0
        consecutive_failures = 0
        max_consecutive_failures = 50
        processed = 0
        import threading
        lock = threading.Lock()

        def _fetch(meta: SkillMeta) -> Optional[str]:
            return self._fetch_owner_handle(meta.identifier)

        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_fetch, s): s for s in needs_enrichment}
            for future in as_completed(futures):
                meta = futures[future]
                processed += 1
                try:
                    handle = future.result()
                    if handle:
                        with lock:
                            if not meta.extra:
                                meta.extra = {}
                            meta.extra["owner"] = handle
                            enriched += 1
                            consecutive_failures = 0
                    else:
                        with lock:
                            consecutive_failures += 1
                except Exception:
                    with lock:
                        consecutive_failures += 1

                if processed % 1000 == 0:
                    logger.info(
                        "ClawHub owner enrichment: %d/%d processed, %d enriched",
                        processed, len(needs_enrichment), enriched,
                    )

                with lock:
                    if consecutive_failures >= max_consecutive_failures:
                        logger.warning(
                            "ClawHub owner enrichment: %d consecutive failures — "
                            "aborting early (%d/%d processed, %d enriched). "
                            "The ClawHub API may be down or rate-limited.",
                            max_consecutive_failures, processed,
                            len(needs_enrichment), enriched,
                        )
                        # Cancel pending futures
                        for f in futures:
                            f.cancel()
                        break

        return enriched

    def _extract_files(self, version_data: Dict[str, Any]) -> Dict[str, str]:
        files: Dict[str, str] = {}
        file_list = version_data.get("files")

        if isinstance(file_list, dict):
            return {k: v for k, v in file_list.items() if isinstance(v, str)}

        if not isinstance(file_list, list):
            return files

        for file_meta in file_list:
            if not isinstance(file_meta, dict):
                continue

            fname = file_meta.get("path") or file_meta.get("name")
            if not fname or not isinstance(fname, str):
                continue

            inline_content = file_meta.get("content")
            if isinstance(inline_content, str):
                files[fname] = inline_content
                continue

            raw_url = file_meta.get("rawUrl") or file_meta.get("downloadUrl") or file_meta.get("url")
            if isinstance(raw_url, str) and raw_url.startswith("http"):
                content = self._fetch_text(raw_url)
                if content is not None:
                    files[fname] = content

        return files

    def _download_zip(self, slug: str, version: str) -> Dict[str, str]:
        """Download skill as a ZIP bundle from the /download endpoint and extract text files."""
        import io
        import zipfile

        files: Dict[str, str] = {}
        max_retries = 3
        for attempt in range(max_retries):
            try:
                resp = httpx.get(
                    f"{self.BASE_URL}/download",
                    params={"slug": slug, "version": version},
                    timeout=30,
                    follow_redirects=True,
                )
                if resp.status_code == 429:
                    try:
                        retry_after = int(resp.headers.get("retry-after", "5"))
                    except (ValueError, TypeError):
                        retry_after = 5
                    retry_after = min(retry_after, 15)  # Cap wait time
                    logger.debug(
                        "ClawHub download rate-limited for %s, retrying in %ds (attempt %d/%d)",
                        slug, retry_after, attempt + 1, max_retries,
                    )
                    time.sleep(retry_after)
                    continue
                if resp.status_code != 200:
                    logger.debug("ClawHub ZIP download for %s v%s returned %s", slug, version, resp.status_code)
                    return files

                with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        try:
                            name = _validate_bundle_rel_path(info.filename)
                        except ValueError:
                            logger.debug("Skipping unsafe ZIP member path: %s", info.filename)
                            continue
                        # Only extract text-sized files (skip large binaries)
                        if info.file_size > 500_000:
                            logger.debug("Skipping large file in ZIP: %s (%d bytes)", name, info.file_size)
                            continue
                        try:
                            raw = zf.read(info.filename)
                            files[name] = raw.decode("utf-8")
                        except (UnicodeDecodeError, KeyError):
                            logger.debug("Skipping non-text file in ZIP: %s", name)
                            continue

                return files

            except zipfile.BadZipFile:
                logger.warning("ClawHub returned invalid ZIP for %s v%s", slug, version)
                return files
            except httpx.HTTPError as exc:
                logger.debug("ClawHub ZIP download failed for %s v%s: %s", slug, version, exc)
                return files

        logger.debug("ClawHub ZIP download exhausted retries for %s v%s", slug, version)
        return files

    def _fetch_text(self, url: str) -> Optional[str]:
        resp = _guarded_http_get(url, timeout=20)
        if resp is not None and resp.status_code == 200:
            return resp.text
        return None


# ---------------------------------------------------------------------------
# LobeHub source adapter
# ---------------------------------------------------------------------------

class LobeHubSource(SkillSource):
    """
    Fetch skills from LobeHub's agent marketplace (14,500+ agents).
    LobeHub agents are system prompt templates — we convert them to SKILL.md on fetch.
    Data lives in GitHub: lobehub/lobe-chat-agents.
    """

    INDEX_URL = "https://chat-agents.lobehub.com/index.json"

    def source_id(self) -> str:
        return "lobehub"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        index = self._fetch_index()
        if not index:
            return []

        query_lower = query.lower()
        results: List[SkillMeta] = []

        agents = index.get("agents", index) if isinstance(index, dict) else index
        if not isinstance(agents, list):
            return []

        for agent in agents:
            meta = agent.get("meta", agent)
            title = meta.get("title", agent.get("identifier", ""))
            desc = meta.get("description", "")
            tags = meta.get("tags", [])

            searchable = f"{title} {desc} {' '.join(tags) if isinstance(tags, list) else ''}".lower()
            if query_lower in searchable:
                identifier = agent.get("identifier", title.lower().replace(" ", "-"))
                results.append(SkillMeta(
                    name=identifier,
                    description=desc[:200],
                    source="lobehub",
                    identifier=f"lobehub/{identifier}",
                    trust_level="community",
                    tags=tags if isinstance(tags, list) else [],
                ))

            if len(results) >= limit:
                break

        return results

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        # Strip "lobehub/" prefix if present
        agent_id = identifier.split("/", 1)[-1] if identifier.startswith("lobehub/") else identifier

        agent_data = self._fetch_agent(agent_id)
        if not agent_data:
            return None

        skill_md = self._convert_to_skill_md(agent_data)
        return SkillBundle(
            name=agent_id,
            files={"SKILL.md": skill_md},
            source="lobehub",
            identifier=f"lobehub/{agent_id}",
            trust_level="community",
        )

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        agent_id = identifier.split("/", 1)[-1] if identifier.startswith("lobehub/") else identifier
        index = self._fetch_index()
        if not index:
            return None

        agents = index.get("agents", index) if isinstance(index, dict) else index
        if not isinstance(agents, list):
            return None

        for agent in agents:
            if agent.get("identifier") == agent_id:
                meta = agent.get("meta", agent)
                return SkillMeta(
                    name=agent_id,
                    description=meta.get("description", ""),
                    source="lobehub",
                    identifier=f"lobehub/{agent_id}",
                    trust_level="community",
                    tags=meta.get("tags", []) if isinstance(meta.get("tags"), list) else [],
                )
        return None

    def _fetch_index(self) -> Optional[Any]:
        """Fetch the LobeHub agent index (cached for 1 hour)."""
        cache_key = "lobehub_index"
        cached = _read_index_cache(cache_key)
        if cached is not None:
            return cached

        try:
            resp = httpx.get(self.INDEX_URL, timeout=30)
            if resp.status_code != 200:
                return None
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return None

        _write_index_cache(cache_key, data)
        return data

    def _fetch_agent(self, agent_id: str) -> Optional[dict]:
        """Fetch a single agent's JSON file."""
        url = f"https://chat-agents.lobehub.com/{agent_id}.json"
        try:
            resp = httpx.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.debug("LobeHub agent fetch failed: %s", e)
        return None

    @staticmethod
    def _convert_to_skill_md(agent_data: dict) -> str:
        """Convert a LobeHub agent JSON into SKILL.md format."""
        meta = agent_data.get("meta", agent_data)
        identifier = agent_data.get("identifier", "lobehub-agent")
        title = meta.get("title", identifier)
        description = meta.get("description", "")
        tags = meta.get("tags", [])
        system_role = agent_data.get("config", {}).get("systemRole", "")

        tag_list = tags if isinstance(tags, list) else []
        fm_lines = [
            "---",
            f"name: {identifier}",
            f"description: {description[:500]}",
            "metadata:",
            "  hermes:",
            f"    tags: [{', '.join(str(t) for t in tag_list)}]",
            "  lobehub:",
            "    source: lobehub",
            "---",
        ]

        body_lines = [
            f"# {title}",
            "",
            description,
            "",
            "## Instructions",
            "",
            system_role if system_role else "(No system role defined)",
        ]

        return "\n".join(fm_lines) + "\n\n" + "\n".join(body_lines) + "\n"


# ---------------------------------------------------------------------------
# browse.sh source adapter
# ---------------------------------------------------------------------------


class BrowseShSource(SkillSource):
    """Discover and install site-specific browser automation skills from browse.sh.

    browse.sh (https://browse.sh) is Browserbase's catalog of 200+ SKILL.md files
    that describe how to automate specific websites (Airbnb, Amazon, arXiv, etc.).
    The catalog lives at ``/api/skills`` and each skill's actual SKILL.md content
    is fetched via ``/api/skills/{slug}`` which returns a ``skillMdUrl`` field
    pointing at a CDN-hosted blob — the catalog's ``sourceUrl`` field is a GitHub
    HTML URL whose underlying repository is not always public, so it cannot be
    relied on for content fetch.
    """

    CATALOG_URL = "https://browse.sh/api/skills"
    SKILL_DETAIL_URL = "https://browse.sh/api/skills/{slug}"
    _CACHE_KEY = "browse_sh_catalog"

    def source_id(self) -> str:
        return "browse-sh"

    def trust_level_for(self, identifier: str) -> str:
        return "community"

    def _fetch_catalog(self) -> List[Dict]:
        cached = _read_index_cache(self._CACHE_KEY)
        if cached is not None:
            return cached
        try:
            resp = httpx.get(self.CATALOG_URL, timeout=20)
            if resp.status_code != 200:
                return []
            data = resp.json()
        except (httpx.HTTPError, json.JSONDecodeError):
            return []
        skills = data.get("skills", []) if isinstance(data, dict) else []
        if isinstance(skills, list):
            _write_index_cache(self._CACHE_KEY, skills)
        return skills if isinstance(skills, list) else []

    def _item_to_meta(self, item: Dict) -> Optional[SkillMeta]:
        slug = item.get("slug", "")
        name = item.get("name", "")
        title = item.get("title", name)
        description = item.get("description", title)
        if not slug or not name:
            return None
        if len(description) > 1024:
            description = description[:1021] + "..."
        return SkillMeta(
            name=name,
            description=description,
            source="browse-sh",
            identifier=f"browse-sh/{slug}",
            trust_level="community",
            tags=item.get("tags", []),
            extra={
                "slug": slug,
                "hostname": item.get("hostname", ""),
                "category": item.get("category", ""),
                "source_url": item.get("sourceUrl", ""),
                "recommended_method": item.get("recommendedMethod", ""),
                "proxies": item.get("proxies", False),
                "install_count": item.get("installCount", 0),
            },
        )

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        catalog = self._fetch_catalog()
        query_lower = query.lower()
        results = []
        for item in catalog:
            text = " ".join([
                item.get("name", ""),
                item.get("title", ""),
                item.get("description", ""),
                item.get("hostname", ""),
                item.get("category", ""),
                " ".join(item.get("tags", [])),
            ]).lower()
            if not query_lower or query_lower in text:
                meta = self._item_to_meta(item)
                if meta:
                    results.append(meta)
            if len(results) >= limit:
                break
        return results

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        slug = self._slug_from_identifier(identifier)
        if not slug:
            return None
        catalog = self._fetch_catalog()
        for item in catalog:
            if item.get("slug") == slug:
                return self._item_to_meta(item)
        return None

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        slug = self._slug_from_identifier(identifier)
        if not slug:
            return None
        catalog = self._fetch_catalog()
        item = next((i for i in catalog if i.get("slug") == slug), None)
        if not item:
            return None

        # Resolve the actual SKILL.md content URL via the per-skill detail
        # endpoint, which returns a ``skillMdUrl`` (CDN blob). The catalog's
        # ``sourceUrl`` is a GitHub HTML link whose underlying repo is not
        # reliably public, so we don't use it for content.
        md_url = self._resolve_skill_md_url(slug, item)
        if not md_url:
            return None
        try:
            resp = httpx.get(md_url, timeout=20, follow_redirects=True)
            if resp.status_code != 200:
                return None
            content = resp.text
        except httpx.HTTPError:
            return None

        meta = self._item_to_meta(item)
        name = meta.name if meta else slug.split("/")[-1]
        return SkillBundle(
            name=name,
            files={"SKILL.md": content},
            source="browse-sh",
            identifier=identifier,
            trust_level="community",
            metadata={
                "slug": slug,
                "hostname": item.get("hostname", ""),
                "source_url": item.get("sourceUrl", ""),
                "skill_md_url": md_url,
            },
        )

    def _resolve_skill_md_url(self, slug: str, item: Dict) -> Optional[str]:
        """Resolve the SKILL.md content URL for a slug.

        Primary path: hit ``/api/skills/{slug}`` and read ``skillMdUrl``.
        Fallback: if the catalog item already has a ``raw.githubusercontent.com``
        ``sourceUrl`` (some entries may), use it directly.
        """
        try:
            detail = httpx.get(
                self.SKILL_DETAIL_URL.format(slug=slug),
                timeout=20,
                follow_redirects=True,
            )
            if detail.status_code == 200:
                data = detail.json()
                if isinstance(data, dict):
                    md_url = data.get("skillMdUrl")
                    if isinstance(md_url, str) and md_url.startswith("http"):
                        return md_url
        except (httpx.HTTPError, json.JSONDecodeError):
            pass

        source_url = item.get("sourceUrl", "") if isinstance(item, dict) else ""
        from utils import base_url_host_matches
        if source_url and base_url_host_matches(source_url, "raw.githubusercontent.com"):
            return source_url
        return None

    def _slug_from_identifier(self, identifier: str) -> str:
        """Extract slug from identifier like 'browse-sh/airbnb.com/search-listings-abc'."""
        if identifier.startswith("browse-sh/"):
            return identifier[len("browse-sh/"):]
        return identifier


# ---------------------------------------------------------------------------
# Official optional skills source adapter
# ---------------------------------------------------------------------------

class OptionalSkillSource(SkillSource):
    """
    Fetch skills from the optional-skills/ directory shipped with the repo.

    These skills are official (maintained by Nous Research) but not activated
    by default — they don't appear in the system prompt and aren't copied to
    ~/.hermes/skills/ during setup.  They are discoverable via the Skills Hub
    (search / install / inspect) and labelled "official" with "builtin" trust.
    """

    OFFICIAL_REPO = "NousResearch/hermes-agent"
    OPTIONAL_SKILLS_PREFIX = "optional-skills"

    def __init__(
        self,
        auth: Optional[GitHubAuth] = None,
        *,
        allow_remote_fallback: bool = True,
    ):
        from hermes_constants import get_optional_skills_dir

        self._optional_dir = get_optional_skills_dir(
            Path(__file__).parent.parent / "optional-skills"
        )
        self._auth = auth
        self._allow_remote_fallback = allow_remote_fallback
        # Lazily created GitHubSource for the live-repo fallback — only
        # instantiated when a skill is missing from the local checkout.
        self._github: Optional[GitHubSource] = None
        # rel_path ("category/skill") -> True, from the live repo tree.
        # None = not fetched yet this process.
        self._remote_dirs: Optional[Dict[str, bool]] = None

    def source_id(self) -> str:
        return "official"

    def trust_level_for(self, identifier: str) -> str:
        return "builtin"

    # -- search -----------------------------------------------------------

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        results: List[SkillMeta] = []
        query_lower = query.lower()

        local_rels: set = set()
        for meta in self._scan_all():
            rel = meta.identifier.split("/", 1)[-1] if meta.identifier else ""
            local_rels.add(rel)
            searchable = f"{meta.name} {meta.description} {' '.join(meta.tags)}".lower()
            if query_lower in searchable:
                results.append(meta)
            if len(results) >= limit:
                break

        # Also surface skills that landed on live main after this install was
        # cut (missing from the local optional-skills/ checkout).
        if self._allow_remote_fallback and len(results) < limit:
            for rel_dir in sorted(self._list_remote_skill_dirs()):
                if rel_dir in local_rels:
                    continue
                name = rel_dir.rsplit("/", 1)[-1]
                if query_lower and query_lower not in rel_dir.lower():
                    continue
                results.append(SkillMeta(
                    name=name,
                    description="Official optional skill (from live repo; run install to fetch)",
                    source="official",
                    identifier=f"official/{rel_dir}",
                    trust_level="builtin",
                    repo=self.OFFICIAL_REPO,
                    path=f"{self.OPTIONAL_SKILLS_PREFIX}/{rel_dir}",
                    tags=[],
                ))
                if len(results) >= limit:
                    break

        return results

    # -- fetch ------------------------------------------------------------

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        # identifier format: "official/category/skill" or "official/skill"
        rel = identifier.split("/", 1)[-1] if identifier.startswith("official/") else identifier
        skill_dir = self._optional_dir / rel

        # Guard against path traversal (e.g. "official/../../etc")
        try:
            resolved = skill_dir.resolve()
            optional_root = self._optional_dir.resolve()
            if not resolved.is_relative_to(optional_root):
                return None
        except (OSError, ValueError):
            return None

        if not resolved.is_dir():
            # Try searching by skill name only (last segment)
            skill_name = rel.rsplit("/", 1)[-1]
            skill_dir = self._find_skill_dir(skill_name)
            if not skill_dir:
                # Not in the local checkout — the skill may have landed on
                # main after this install was cut. Fall back to the live repo.
                if not self._allow_remote_fallback:
                    return None
                return self._fetch_from_live_repo(rel)
        else:
            skill_dir = resolved

        files: Dict[str, Union[str, bytes]] = {}
        for f in skill_dir.rglob("*"):
            if (
                f.is_file()
                and not f.name.startswith(".")
                and "__pycache__" not in f.parts
                and f.suffix != ".pyc"
            ):
                rel_path = str(f.relative_to(skill_dir))
                try:
                    files[rel_path] = f.read_bytes()
                except OSError:
                    continue

        if not files:
            return None

        # Determine category from directory structure
        name = skill_dir.name

        return SkillBundle(
            name=name,
            files=files,
            source="official",
            identifier=f"official/{skill_dir.resolve().relative_to(self._optional_dir.resolve()).as_posix()}",
            trust_level="builtin",
        )

    # -- inspect ----------------------------------------------------------

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        rel = identifier.split("/", 1)[-1] if identifier.startswith("official/") else identifier
        skill_name = rel.rsplit("/", 1)[-1]

        for meta in self._scan_all():
            if meta.name == skill_name:
                return meta

        # Not in the local checkout — check live main.
        if not self._allow_remote_fallback:
            return None
        remote_dirs = self._list_remote_skill_dirs()
        matches = [d for d in remote_dirs if d.rsplit("/", 1)[-1] == skill_name]
        if len(matches) == 1:
            rel_dir = matches[0]
            return SkillMeta(
                name=skill_name,
                description="Official optional skill (from live repo; run install to fetch)",
                source="official",
                identifier=f"official/{rel_dir}",
                trust_level="builtin",
                repo=self.OFFICIAL_REPO,
                path=f"{self.OPTIONAL_SKILLS_PREFIX}/{rel_dir}",
                tags=[],
            )
        return None

    # -- internal helpers -------------------------------------------------

    def _get_github(self) -> "GitHubSource":
        if self._github is None:
            self._github = GitHubSource(auth=self._auth or GitHubAuth())
        return self._github

    def _fetch_from_live_repo(self, rel: str) -> Optional[SkillBundle]:
        """Fetch an optional skill straight from the live repo on GitHub.

        Local installs lag `main` — a freshly merged optional skill isn't in
        the user's `optional-skills/` checkout until they run
        ``hermes update``. Rather than telling them to update first, resolve
        the skill against the live default branch.

        ``rel`` is the identifier without the ``official/`` prefix — either
        ``category/skill`` (used verbatim) or a bare skill name (located via
        the repo tree).
        """
        if not self._allow_remote_fallback:
            return None
        rel = rel.strip("/")
        if not rel:
            return None
        # Reject traversal before it ever becomes a GitHub path.
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts):
            return None
        rel = "/".join(parts)

        github = self._get_github()
        remote_dirs = self._list_remote_skill_dirs()

        if rel in remote_dirs:
            repo_path = f"{self.OPTIONAL_SKILLS_PREFIX}/{rel}"
        else:
            # Bare name (or stale category) — locate by final path segment.
            name = parts[-1]
            matches = [d for d in remote_dirs if d.rsplit("/", 1)[-1] == name]
            if len(matches) != 1:
                return None
            repo_path = f"{self.OPTIONAL_SKILLS_PREFIX}/{matches[0]}"
            rel = matches[0]

        # Download the FULL skill directory (byte-exact, including root-level
        # install scripts, LICENSE, tests/). GitHubSource.fetch() would only
        # pull SKILL.md + referenced support dirs, silently dropping files the
        # local-checkout path preserves.
        tree = github._get_repo_tree(self.OFFICIAL_REPO)
        if tree is None:
            return None
        _branch, entries = tree
        prefix = f"{repo_path}/"
        files: Dict[str, Union[str, bytes]] = {}
        for item in entries:
            if item.get("type") != "blob" or item.get("mode") == "120000":
                continue
            item_path = item.get("path", "")
            if not item_path.startswith(prefix):
                continue
            rel_file = item_path[len(prefix):]
            base = rel_file.rsplit("/", 1)[-1]
            if base.startswith(".") or base.endswith(".pyc") or "__pycache__" in rel_file.split("/"):
                continue
            content = github._fetch_file_bytes(self.OFFICIAL_REPO, item_path)
            if content is None:
                logger.warning("Live-repo optional skill fetch failed for %s", item_path)
                return None
            files[rel_file] = content

        if "SKILL.md" not in files:
            return None

        logger.info("Optional skill '%s' fetched from live repo (not in local checkout)", rel)
        return SkillBundle(
            name=rel.rsplit("/", 1)[-1],
            files=files,
            source="official",
            identifier=f"official/{rel}",
            trust_level="builtin",
        )

    def _list_remote_skill_dirs(self) -> Dict[str, bool]:
        """Map of ``category/skill`` dirs under optional-skills/ on live main.

        Derived from the repo tree (single API call, cached per-process by
        GitHubSource, plus the shared on-disk index cache). Returns {} when
        the network/API is unavailable — callers degrade to local-only.
        """
        if not self._allow_remote_fallback:
            return {}
        if self._remote_dirs is not None:
            return self._remote_dirs

        cache_key = "official_optional_dirs"
        cached = _read_index_cache(cache_key)
        if isinstance(cached, dict) and cached:
            self._remote_dirs = cached
            return cached

        dirs: Dict[str, bool] = {}
        tree = self._get_github()._get_repo_tree(self.OFFICIAL_REPO)
        if tree is not None:
            _branch, entries = tree
            prefix = f"{self.OPTIONAL_SKILLS_PREFIX}/"
            suffix = "/SKILL.md"
            for item in entries:
                path = item.get("path", "")
                if (
                    item.get("type") == "blob"
                    and path.startswith(prefix)
                    and path.endswith(suffix)
                ):
                    rel_dir = path[len(prefix):-len(suffix)]
                    if rel_dir and not is_excluded_skill_path(
                        PurePosixPath(rel_dir + suffix)
                    ):
                        dirs[rel_dir] = True
            if dirs:
                _write_index_cache(cache_key, dirs)

        self._remote_dirs = dirs
        return dirs

    def _find_skill_dir(self, name: str) -> Optional[Path]:
        """Find a skill directory by name anywhere in optional-skills/."""
        if not self._optional_dir.is_dir():
            return None
        for skill_md in self._optional_dir.rglob("SKILL.md"):
            if is_excluded_skill_path(
                skill_md.relative_to(self._optional_dir), root=self._optional_dir
            ):
                continue
            if skill_md.parent.name == name:
                return skill_md.parent
        return None

    def _scan_all(self) -> List[SkillMeta]:
        """Enumerate all optional skills with metadata."""
        if not self._optional_dir.is_dir():
            return []

        results: List[SkillMeta] = []
        for skill_md in sorted(self._optional_dir.rglob("SKILL.md")):
            if is_excluded_skill_path(
                skill_md.relative_to(self._optional_dir), root=self._optional_dir
            ):
                continue
            parent = skill_md.parent

            try:
                content = skill_md.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue

            fm = self._parse_frontmatter(content)
            name = fm.get("name", parent.name)
            desc = fm.get("description", "")
            tags = []
            meta_block = fm.get("metadata", {})
            if isinstance(meta_block, dict):
                hermes_meta = meta_block.get("hermes", {})
                if isinstance(hermes_meta, dict):
                    tags = hermes_meta.get("tags", [])

            rel_path = parent.relative_to(self._optional_dir).as_posix()

            results.append(SkillMeta(
                name=name,
                description=desc[:200],
                source="official",
                identifier=f"official/{rel_path}",
                trust_level="builtin",
                repo=self.OFFICIAL_REPO,
                # The centralized skills index consumes repo-root-relative paths.
                path=f"optional-skills/{rel_path}",
                tags=tags if isinstance(tags, list) else [],
            ))

        return results

    @staticmethod
    def _parse_frontmatter(content: str) -> dict:
        """Parse YAML frontmatter from SKILL.md content."""
        content = content.lstrip("\ufeff")  # tolerate UTF-8 BOM (Windows editors)
        if not content.startswith("---"):
            return {}
        match = re.search(r'\n---\s*\n', content[3:])
        if not match:
            return {}
        yaml_text = content[3:match.start() + 3]
        try:
            parsed = yaml.safe_load(yaml_text)
            return parsed if isinstance(parsed, dict) else {}
        except yaml.YAMLError:
            return {}


# ---------------------------------------------------------------------------
# Shared cache helpers (used by multiple adapters)
# ---------------------------------------------------------------------------

def _read_index_cache(key: str) -> Optional[Any]:
    """Read cached data if not expired."""
    cache_file = _index_cache_dir() / f"{key}.json"
    if not cache_file.exists():
        return None
    try:
        stat = cache_file.stat()
        if time.time() - stat.st_mtime > INDEX_CACHE_TTL:
            return None
        return json.loads(cache_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_index_cache(key: str, data: Any) -> None:
    """Write data to cache."""
    index_cache_dir = _index_cache_dir()
    index_cache_dir.mkdir(parents=True, exist_ok=True)
    # Ensure .ignore exists so ripgrep (and tools respecting .ignore) skip
    # this directory.  Cache files contain unvetted community content that
    # could include adversarial text (prompt injection via catalog entries).
    ignore_file = _hub_dir() / ".ignore"
    if not ignore_file.exists():
        try:
            ignore_file.write_text("# Exclude hub internals from search tools\n*\n", encoding="utf-8")
        except OSError:
            pass
    cache_file = index_cache_dir / f"{key}.json"
    try:
        cache_file.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
    except OSError as e:
        logger.debug("Could not write cache: %s", e)


def _skill_meta_to_dict(meta: SkillMeta) -> dict:
    """Convert a SkillMeta to a dict for caching."""
    return {
        "name": meta.name,
        "description": meta.description,
        "source": meta.source,
        "identifier": meta.identifier,
        "trust_level": meta.trust_level,
        "repo": meta.repo,
        "path": meta.path,
        "tags": meta.tags,
        "extra": meta.extra,
    }


# ---------------------------------------------------------------------------
# Lock file management
# ---------------------------------------------------------------------------

class HubLockFile:
    """Manages skills/.hub/lock.json — tracks provenance of installed hub skills."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path if path is not None else _lock_file()

    def load(self) -> dict:
        if not self.path.exists():
            return {"version": 1, "installed": {}}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {"version": 1, "installed": {}}

    def save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def record_install(
        self,
        name: str,
        source: str,
        identifier: str,
        trust_level: str,
        scan_verdict: str,
        skill_hash: str,
        install_path: str,
        files: List[str],
        metadata: Optional[Dict[str, Any]] = None,
        scan_provenance: Optional[Dict[str, Any]] = None,
    ) -> None:
        # Validate both the skill name and the install path SHAPE before
        # writing into lock.json. A poisoned lock entry is the precondition
        # for the uninstall_skill rmtree-escape; reject malformed input at
        # write time so the file never carries the bad state.
        safe_name = _validate_skill_name(name)
        safe_install_path = _normalize_lock_install_path(install_path, safe_name)
        data = self.load()
        data["installed"][safe_name] = {
            "source": source,
            "identifier": identifier,
            "trust_level": trust_level,
            "scan_verdict": scan_verdict,
            "content_hash": skill_hash,
            "install_path": safe_install_path,
            "files": files,
            "metadata": metadata or {},
            "scan_provenance": scan_provenance or {},
            "installed_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self.save(data)

    def record_uninstall(self, name: str) -> None:
        data = self.load()
        data["installed"].pop(name, None)
        self.save(data)

    def get_installed(self, name: str) -> Optional[dict]:
        data = self.load()
        return data["installed"].get(name)

    def list_installed(self) -> List[dict]:
        data = self.load()
        result = []
        for name, entry in data["installed"].items():
            result.append({"name": name, **entry})
        return result


# ---------------------------------------------------------------------------
# Taps management
# ---------------------------------------------------------------------------

class TapsManager:
    """Manages the taps.json file — custom GitHub repo sources."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path if path is not None else _taps_file()

    def load(self) -> List[dict]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data.get("taps", [])
        except (json.JSONDecodeError, OSError):
            return []

    def save(self, taps: List[dict]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"taps": taps}, indent=2) + "\n", encoding="utf-8")

    def add(self, repo: str, path: str = "skills/") -> bool:
        """Add a tap. Returns False if already exists."""
        taps = self.load()
        if any(t["repo"] == repo for t in taps):
            return False
        taps.append({"repo": repo, "path": path})
        self.save(taps)
        return True

    def remove(self, repo: str) -> bool:
        """Remove a tap by repo name. Returns False if not found."""
        taps = self.load()
        new_taps = [t for t in taps if t["repo"] != repo]
        if len(new_taps) == len(taps):
            return False
        self.save(new_taps)
        return True

    def list_taps(self) -> List[dict]:
        return self.load()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def append_audit_log(action: str, skill_name: str, source: str,
                     trust_level: str, verdict: str, extra: str = "") -> None:
    """Append a line to the audit log."""
    audit_log = _audit_log()
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [timestamp, action, skill_name, f"{source}:{trust_level}", verdict]
    if extra:
        parts.append(extra)
    line = " ".join(parts) + "\n"
    try:
        with open(audit_log, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError as e:
        logger.debug("Could not write audit log: %s", e)


# ---------------------------------------------------------------------------
# Hub operations (high-level)
# ---------------------------------------------------------------------------

def ensure_hub_dirs() -> None:
    """Create the .hub directory structure if it doesn't exist."""
    hub_dir = _hub_dir()
    lock_file = _lock_file()
    audit_log = _audit_log()
    taps_file = _taps_file()
    hub_dir.mkdir(parents=True, exist_ok=True)
    _quarantine_dir().mkdir(exist_ok=True)
    _index_cache_dir().mkdir(exist_ok=True)
    if not lock_file.exists():
        lock_file.write_text('{"version": 1, "installed": {}}\n', encoding="utf-8")
    if not audit_log.exists():
        audit_log.touch()
    if not taps_file.exists():
        taps_file.write_text('{"taps": []}\n', encoding="utf-8")


def quarantine_bundle(bundle: SkillBundle) -> Path:
    """Write a skill bundle to the quarantine directory for scanning."""
    ensure_hub_dirs()
    skill_name = _validate_skill_name(bundle.name)
    validated_files: List[Tuple[str, Union[str, bytes]]] = []
    for rel_path, file_content in bundle.files.items():
        safe_rel_path = _validate_bundle_rel_path(rel_path)
        if safe_rel_path.casefold() in _REMOTE_SCAN_IGNORE_FILENAMES:
            # Hub content must not control the scanner's visibility. Omitting
            # the control file means every other bundle file is scanned and
            # then installed; the upstream ignore pattern never takes effect.
            continue
        validated_files.append((safe_rel_path, file_content))

    # Keep the bundle manifest/hash symmetric with what is actually quarantined
    # and later moved into the installed skill directory.
    bundle.files = dict(validated_files)

    dest = _quarantine_dir() / skill_name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    for rel_path, file_content in validated_files:
        file_dest = dest.joinpath(*rel_path.split("/"))
        file_dest.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(file_content, bytes):
            file_dest.write_bytes(file_content)
        else:
            file_dest.write_text(file_content, encoding="utf-8")

    return dest


def _category_skill_dirs(directory: Path) -> List[str]:
    """Names of direct children of *directory* that contain skills.

    A child counts when it is a non-hidden directory holding at least one
    active ``SKILL.md`` anywhere below it (recursive, so nested category
    layouts like ``mlops/training/<skill>`` are detected). Vendored,
    cache, and progressive-disclosure support paths are pruned via
    :func:`is_excluded_skill_path` so a lone ``node_modules`` or
    ``references/pkg/SKILL.md`` hit does not misclassify the directory as
    a category. Shared by the install-time category guard here and
    ``hermes_cli.skills_hub._existing_categories``.
    """
    skill_dirs: List[str] = []
    for entry in directory.iterdir():
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        for skill_md in entry.rglob("SKILL.md"):
            if is_excluded_skill_path(
                skill_md.relative_to(directory), root=directory
            ):
                continue
            skill_dirs.append(entry.name)
            break
    return skill_dirs


def install_from_quarantine(
    quarantine_path: Path,
    skill_name: str,
    category: str,
    bundle: SkillBundle,
    scan_result: ScanResult,
    scan_provenance: Optional[Dict[str, Any]] = None,
) -> Path:
    """Move a scanned skill from quarantine into the skills directory."""
    safe_skill_name = _validate_skill_name(skill_name)
    safe_category = _validate_install_parent_path(category) if category else ""
    quarantine_resolved = quarantine_path.resolve()
    quarantine_root = _quarantine_dir().resolve()
    if not quarantine_resolved.is_relative_to(quarantine_root):
        raise ValueError(f"Unsafe quarantine path: {quarantine_path}")

    if safe_category:
        install_rel_path = f"{safe_category}/{safe_skill_name}"
    else:
        install_rel_path = safe_skill_name

    # Resolve via the same lock-path validator the uninstaller uses. Catches
    # symlink-in-skills-tree redirects at install time so the lock entry's
    # path can never refer to a redirected target.
    install_dir = _resolve_lock_install_path(install_rel_path, safe_skill_name)

    # Refuse to nest a skill inside an existing skill directory. Installing
    # with ``--category <name-of-an-existing-skill>`` would create a hybrid
    # skill-plus-category directory; a later update or uninstall of the outer
    # skill would then rmtree the inner one — the sibling case of the
    # category-bucket wipe reported in issue #75983.
    skills_root = _skills_dir().resolve()
    ancestor = install_dir.parent
    while ancestor != skills_root and ancestor.is_relative_to(skills_root):
        if (ancestor / "SKILL.md").is_file():
            raise ValueError(
                f"Refusing to install into '{ancestor.name}': it is an "
                f"existing skill directory, not a category. Choose a "
                f"different category."
            )
        ancestor = ancestor.parent

    if install_dir.exists():
        if not install_dir.is_dir():
            # A stray regular file at the install path. rmtree() on a file
            # raises NotADirectoryError (an uncaught traceback at the CLI);
            # refuse with the same actionable ValueError contract instead.
            raise ValueError(
                f"Refusing to install: '{install_dir.name}' already exists "
                f"and is not a directory. Remove it or choose a different "
                f"skill name."
            )
        # Guard against silent data loss when the install target collides with
        # an existing category bucket (a directory that holds other skills).
        # This was reported as GitHub issue #75983: installing a skill with
        # --name matching an existing category directory caused rmtree to wipe
        # all sibling skills.  A directory that directly contains SKILL.md is
        # an existing skill installation and stays overwritable (hub-installed
        # skills are additionally guarded by the lock-file check in
        # do_install()).  But a directory that contains *other* skill
        # directories is a category bucket and must NOT be silently deleted.
        if not (install_dir / "SKILL.md").exists():
            skill_dirs_in = _category_skill_dirs(install_dir)
            if skill_dirs_in:
                raise ValueError(
                    f"Refusing to overwrite category directory '{install_dir}' "
                    f"which contains {len(skill_dirs_in)} skill(s): "
                    f"{', '.join(sorted(skill_dirs_in))}. "
                    f"Use a different --name or install into a subcategory."
                )
        shutil.rmtree(install_dir)

    # Warn (but don't block) if SKILL.md is very large
    skill_md = quarantine_path / "SKILL.md"
    if skill_md.exists():
        try:
            skill_size = skill_md.stat().st_size
            if skill_size > 100_000:
                logger.warning(
                    "Skill '%s' has a large SKILL.md (%s chars). "
                    "Large skills consume significant context when loaded. "
                    "Consider asking the author to split it into smaller files.",
                    safe_skill_name,
                    f"{skill_size:,}",
                )
        except OSError:
            pass

    # Reject symlinks inside the quarantined skill before moving it.
    # A malicious skill bundle could include a symlink pointing outside the
    # skills tree; its target contents would then be copied into skills/ and
    # leaked to the agent on the next skill_view call.
    for entry in quarantine_path.rglob("*"):
        if not _is_path_redirect(entry):
            continue
        try:
            rel = entry.relative_to(quarantine_resolved)
        except ValueError:
            rel = entry
        raise ValueError(
            f"Installed skill contains symlinks, which is not allowed: {rel}"
        )

    install_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantine_path), str(install_dir))

    # Record in lock file
    lock = HubLockFile()
    lock.record_install(
        name=safe_skill_name,
        source=bundle.source,
        identifier=bundle.identifier,
        trust_level=bundle.trust_level,
        scan_verdict=scan_result.verdict,
        skill_hash=content_hash(install_dir),
        install_path=install_dir.resolve().relative_to(_skills_dir().resolve()).as_posix(),
        files=list(bundle.files.keys()),
        metadata=bundle.metadata,
        scan_provenance=scan_provenance or getattr(scan_result, "scan_provenance", None),
    )

    append_audit_log(
        "INSTALL", safe_skill_name, bundle.source,
        bundle.trust_level, scan_result.verdict,
        content_hash(install_dir),
    )

    try:
        from tools.skill_usage import record_installed

        record_installed(safe_skill_name)
    except Exception:
        logger.debug(
            "Unable to record skill install lifecycle for %s",
            safe_skill_name,
            exc_info=True,
        )

    return install_dir


def uninstall_skill(skill_name: str) -> Tuple[bool, str]:
    """Remove a hub-installed skill. Refuses to remove builtins."""
    lock = HubLockFile()
    entry = lock.get_installed(skill_name)
    if not entry:
        return False, f"'{skill_name}' is not a hub-installed skill (may be a builtin)"

    # Validate the lock entry's install_path against the skill name. This is
    # the destructive boundary — anything that falls through to the rmtree
    # below MUST be inside SKILLS_DIR and MUST NOT be SKILLS_DIR itself
    # (an empty/"."/"/" install_path would otherwise wipe the entire tree).
    # _resolve_lock_install_path enforces a relative path ending in
    # <skill_name>, rejects absolute/traversal paths, and walks the path
    # component-by-component refusing symlink/junction redirects.
    try:
        install_path = _resolve_lock_install_path(
            entry.get("install_path", ""), skill_name
        )
    except ValueError as exc:
        return False, f"Refusing to uninstall '{skill_name}': {exc}"

    if install_path.exists():
        shutil.rmtree(install_path)

    lock.record_uninstall(skill_name)
    append_audit_log("UNINSTALL", skill_name, entry["source"], entry["trust_level"], "n/a", "user_request")

    return True, f"Uninstalled '{skill_name}' from {entry['install_path']}"


def bundle_content_hash(bundle: SkillBundle) -> str:
    """Compute a deterministic hash for an in-memory skill bundle.

    MUST stay symmetric with ``tools.skills_guard.content_hash`` (which
    hashes the same skill from disk). That function keys files by
    ``relative_to(...).as_posix()`` — forward slashes on every OS. Bundle
    keys built on Windows carry backslashes (``str(f.relative_to(dir))``),
    which changed both the hashed bytes AND the sort order, so every
    installed skill reported ``update_available`` forever on Windows
    (#62310). Normalize to POSIX separators before sorting/hashing.
    """
    h = hashlib.sha256()
    normalized = {
        rel_path.replace("\\", "/"): content
        for rel_path, content in bundle.files.items()
        if rel_path.replace("\\", "/").casefold()
        not in _REMOTE_SCAN_IGNORE_FILENAMES
    }
    for rel_path in sorted(normalized):
        # Include the path so swapping file contents between two paths
        # changes the hash (avoids filename-swap evading update detection).
        h.update(rel_path.encode("utf-8"))
        h.update(b"\x00")
        content = normalized[rel_path]
        if isinstance(content, bytes):
            h.update(content)
        else:
            h.update(content.encode("utf-8"))
    return f"sha256:{h.hexdigest()[:16]}"


def _source_matches(
    source: SkillSource,
    source_name: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> bool:
    """Match a lock entry to its adapter without changing enterprise origin."""
    aliases = {
        "skills.sh": "skills-sh",
    }
    normalized = aliases.get(source_name, source_name)
    if source.source_id() != normalized:
        return False
    if not normalized.startswith("enterprise:"):
        return True

    config = getattr(source, "config", None)
    if not isinstance(config, dict) or not isinstance(metadata, dict):
        return False

    current_protocol = str(config.get("protocol") or "").strip().lower()
    current_url = (
        config.get("base_url")
        if current_protocol == "clawhub"
        else config.get("index_url")
    )
    current_origin = _canonical_origin(str(current_url or ""))
    current_endpoint = _canonical_endpoint(str(current_url or ""))

    locked_protocol = str(metadata.get("source_protocol") or "").strip().lower()
    if not locked_protocol:
        if metadata.get("base_url"):
            locked_protocol = "clawhub"
        elif metadata.get("index_url"):
            locked_protocol = "well-known"
    locked_origin = metadata.get("source_origin")
    if not locked_origin:
        legacy_url = (
            metadata.get("base_url")
            if locked_protocol == "clawhub"
            else metadata.get("index_url")
        )
        locked_origin = _canonical_origin(str(legacy_url or ""))
    locked_endpoint = metadata.get("source_endpoint")
    if not locked_endpoint:
        legacy_url = (
            metadata.get("base_url")
            if locked_protocol == "clawhub"
            else metadata.get("index_url")
        )
        locked_endpoint = _canonical_endpoint(str(legacy_url or ""))

    return (
        locked_protocol in _ENTERPRISE_SOURCE_PROTOCOLS
        and locked_protocol == current_protocol
        and isinstance(locked_origin, str)
        and locked_origin == current_origin
        and isinstance(locked_endpoint, str)
        and locked_endpoint == current_endpoint
    )


def check_for_skill_updates(
    name: Optional[str] = None,
    *,
    lock: Optional[HubLockFile] = None,
    sources: Optional[List[SkillSource]] = None,
    auth: Optional[GitHubAuth] = None,
) -> List[dict]:
    """Check installed hub skills for upstream changes."""
    lock = lock or HubLockFile()
    installed = lock.list_installed()
    if name:
        installed = [entry for entry in installed if entry.get("name") == name]

    if sources is None:
        sources = create_source_router(auth=auth)

    results: List[dict] = []
    for entry in installed:
        identifier = entry.get("identifier", "")
        source_name = entry.get("source", "")
        candidate_sources = [
            src
            for src in sources
            if _source_matches(src, source_name, entry.get("metadata"))
        ]
        if not candidate_sources:
            # No adapter for the recorded source (e.g. a tap was removed, or the
            # source was renamed upstream). Previously this fell back to *all*
            # sources, which meant a same-named skill in a DIFFERENT registry
            # could satisfy the fetch and be reported as an update for this
            # entry -- silently reassigning provenance. Skill names are not
            # namespaced across registries, so that fallback is unsafe by
            # construction. Report unavailable instead and let the user decide.
            results.append({
                "name": entry.get("name", ""),
                "identifier": identifier,
                "source": source_name,
                "status": "unavailable",
            })
            continue

        bundle = None
        for src in candidate_sources:
            try:
                bundle = src.fetch(identifier)
            except Exception:
                bundle = None
            if bundle:
                break

        if not bundle:
            results.append({
                "name": entry.get("name", ""),
                "identifier": identifier,
                "source": source_name,
                "status": "unavailable",
            })
            continue

        current_hash = entry.get("content_hash", "")
        latest_hash = bundle_content_hash(bundle)
        status = "up_to_date" if current_hash == latest_hash else "update_available"
        results.append({
            "name": entry.get("name", ""),
            "identifier": identifier,
            "source": source_name,
            "status": status,
            "current_hash": current_hash,
            "latest_hash": latest_hash,
            "bundle": bundle,
        })

    return results


# ---------------------------------------------------------------------------
# Hermes centralized index source
# ---------------------------------------------------------------------------

HERMES_INDEX_URL = "https://hermes-agent.nousresearch.com/docs/api/skills-index.json"
HERMES_INDEX_TTL = 6 * 3600  # 6 hours


def _hermes_index_cache_file() -> Path:
    return _index_cache_dir() / "hermes-index.json"


def _load_hermes_index() -> Optional[dict]:
    """Fetch the centralized skills index, with local cache.

    The index is a JSON file hosted on the docs site, rebuilt daily by CI.
    We cache it locally for HERMES_INDEX_TTL seconds to avoid repeated
    downloads within a session.
    """
    # Check local cache
    hermes_index_cache_file = _hermes_index_cache_file()
    if hermes_index_cache_file.exists():
        try:
            age = time.time() - hermes_index_cache_file.stat().st_mtime
            if age < HERMES_INDEX_TTL:
                return json.loads(hermes_index_cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass

    # Fetch from docs site.
    #
    # We deliberately DON'T let httpx negotiate Brotli here.  The index is a
    # large body (tens of MB); httpx's streaming Brotli decoder, backed by
    # brotlicffi 1.2.0.1 (pinned for Discord attachment decoding), trips over
    # its own output_buffer_limit on payloads this size and raises
    # DecodingError("brotli: decoder process called with data when
    # 'can_accept_more_data()' is False").  That surfaces as an empty Skills
    # Hub (blank Browse-hub landing, index contributes 0 search hits) because
    # the error is caught below and we silently fall back to a (often absent)
    # stale cache.  Requesting gzip/deflate sidesteps the broken decoder while
    # still compressing the transfer.  The identity retry is belt-and-braces
    # for any future proxy that ignores the header and returns Brotli anyway.
    data = None
    for accept_encoding in ("gzip, deflate", "identity"):
        try:
            resp = httpx.get(
                HERMES_INDEX_URL,
                timeout=15,
                follow_redirects=True,
                headers={"Accept-Encoding": accept_encoding},
            )
            if resp.status_code != 200:
                logger.debug("Hermes index fetch returned %d", resp.status_code)
                return _load_stale_index_cache()
            data = resp.json()
            break
        except httpx.DecodingError as e:
            # Content-Encoding decode failed — retry once uncompressed before
            # giving up on the network path entirely.
            logger.debug(
                "Hermes index decode failed (Accept-Encoding=%s): %s",
                accept_encoding,
                e,
            )
            continue
        except (httpx.HTTPError, json.JSONDecodeError) as e:
            logger.debug("Hermes index fetch failed: %s", e)
            return _load_stale_index_cache()

    if data is None:
        return _load_stale_index_cache()

    # Validate structure
    if not isinstance(data, dict) or "skills" not in data:
        return _load_stale_index_cache()

    # Cache locally
    try:
        hermes_index_cache_file.parent.mkdir(parents=True, exist_ok=True)
        hermes_index_cache_file.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass

    return data


def _load_stale_index_cache() -> Optional[dict]:
    """Fall back to stale cache when the network fetch fails."""
    hermes_index_cache_file = _hermes_index_cache_file()
    if hermes_index_cache_file.exists():
        try:
            return json.loads(hermes_index_cache_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    return None


class HermesIndexSource(SkillSource):
    """Skill source backed by the centralized Hermes Skills Index.

    The index is a JSON catalog published to the docs site and rebuilt
    daily by CI.  It contains metadata + resolved GitHub paths for every
    skill, eliminating the need for users to hit the GitHub API for
    search or path discovery.

    When the index is unavailable, all methods return empty / None so
    downstream sources take over transparently.
    """

    def __init__(self, auth: GitHubAuth):
        self._index: Optional[dict] = None
        self._loaded = False
        self.auth = auth
        # Lazily create GitHubSource for fetch — only used when actually
        # downloading files, which requires real GitHub API calls.
        self._github: Optional[GitHubSource] = None

    def _ensure_loaded(self) -> dict:
        if not self._loaded:
            self._index = _load_hermes_index()
            self._loaded = True
        return self._index or {}

    def _get_github(self) -> GitHubSource:
        if self._github is None:
            self._github = GitHubSource(auth=self.auth)
        return self._github

    def source_id(self) -> str:
        return "hermes-index"

    @property
    def is_available(self) -> bool:
        """Whether the index is loaded and has skills."""
        index = self._ensure_loaded()
        return bool(index.get("skills"))

    def trust_level_for(self, identifier: str) -> str:
        index = self._ensure_loaded()
        for skill in index.get("skills", []):
            if skill.get("identifier") == identifier:
                return skill.get("trust_level", "community")
        return "community"

    def search(self, query: str, limit: int = 10) -> List[SkillMeta]:
        """Search the cached index.  Zero API calls.

        Matches against name, description, tags, identifier, and the per-tap
        ``extra.provider`` label (so a query like ``nvidia`` surfaces the
        ``NVIDIA/skills/...`` entries even though their ``source`` is the bare
        ``github``).  Results are scored and ranked (exact name > name prefix >
        whole-word > substring) rather than returned in raw index order and
        truncated at the first ``limit`` hits — that earlier break-at-limit
        behaviour returned an arbitrary file-order slice and buried the most
        relevant skills.
        """
        index = self._ensure_loaded()
        skills = index.get("skills", [])
        if not skills:
            return []

        if not query.strip():
            # No query — return featured/popular (index order)
            return [self._to_meta(s) for s in skills[:limit]]

        query_lower = query.lower()
        scored: List[Tuple[int, int, dict]] = []
        for i, s in enumerate(skills):
            name = str(s.get("name", "")).lower()
            provider = str((s.get("extra") or {}).get("provider", "")).lower()
            haystack = " ".join([
                name,
                str(s.get("description", "")).lower(),
                " ".join(str(t).lower() for t in s.get("tags", [])),
                str(s.get("identifier", "")).lower(),
                provider,
            ])
            if query_lower not in haystack:
                continue
            # Lower score sorts first.
            if name == query_lower:
                score = 0
            elif name.startswith(query_lower):
                score = 1
            elif provider == query_lower:
                score = 2
            elif query_lower in name.split() or query_lower in provider.split():
                score = 3
            elif query_lower in name:
                score = 4
            else:
                score = 5
            # i (original index order) is the stable tiebreaker.
            scored.append((score, i, s))

        scored.sort(key=lambda x: (x[0], x[1]))
        return [self._to_meta(s) for _, _, s in scored[:limit]]

    def fetch(self, identifier: str) -> Optional[SkillBundle]:
        """Fetch a skill using the resolved path from the index.

        If the index has a ``resolved_github_id`` for this skill, we skip
        the entire candidate/discovery chain and go directly to GitHub
        with the exact path.  This reduces install from ~31 API calls to
        just the file content downloads (~5-22 depending on skill size).
        """
        index = self._ensure_loaded()
        entry = self._find_entry(identifier, index)
        if not entry:
            return None

        # Use resolved path if available
        resolved = entry.get("resolved_github_id")
        if resolved:
            bundle = self._get_github().fetch(resolved)
            if bundle:
                bundle.source = entry.get("source", "hermes-index")
                bundle.identifier = identifier
                return bundle

        # Fall back to identifier-based fetch via repo/path
        repo = entry.get("repo", "")
        path = entry.get("path", "")
        if repo and path:
            github_id = f"{repo}/{path}"
            bundle = self._get_github().fetch(github_id)
            if bundle:
                bundle.source = entry.get("source", "hermes-index")
                bundle.identifier = identifier
                return bundle

        return None

    def inspect(self, identifier: str) -> Optional[SkillMeta]:
        """Return metadata from the index.  Zero API calls."""
        index = self._ensure_loaded()
        entry = self._find_entry(identifier, index)
        if entry:
            return self._to_meta(entry)
        return None

    def _find_entry(self, identifier: str, index: dict) -> Optional[dict]:
        """Look up a skill in the index by identifier or name."""
        skills = index.get("skills", [])

        # Exact identifier match
        for s in skills:
            if s.get("identifier") == identifier:
                return s

        # Try without source prefix (e.g. "skills-sh/" stripped)
        normalized = identifier
        for prefix in ("skills-sh/", "skills.sh/", "official/", "github/", "clawhub/"):
            if identifier.startswith(prefix):
                normalized = identifier[len(prefix):]
                break

        # Match on normalized identifier or name
        for s in skills:
            sid = s.get("identifier", "")
            # Strip prefix from stored identifier too
            stored_normalized = sid
            for prefix in ("skills-sh/", "skills.sh/", "official/", "github/", "clawhub/"):
                if sid.startswith(prefix):
                    stored_normalized = sid[len(prefix):]
                    break
            if stored_normalized == normalized:
                return s

        return None

    @staticmethod
    def _to_meta(entry: dict) -> SkillMeta:
        return SkillMeta(
            name=entry.get("name", ""),
            description=entry.get("description", ""),
            source=entry.get("source", "hermes-index"),
            identifier=entry.get("identifier", ""),
            trust_level=entry.get("trust_level", "community"),
            repo=entry.get("repo"),
            path=entry.get("path"),
            tags=entry.get("tags", []),
            extra=entry.get("extra", {}),
        )


def create_source_router(auth: Optional[GitHubAuth] = None) -> List[SkillSource]:
    """
    Create all configured source adapters.
    Returns a list of active sources for search/fetch operations.
    """
    if auth is None:
        auth = GitHubAuth()

    hub_config = load_skills_hub_config()
    enterprise_sources: List[SkillSource] = [
        create_enterprise_source(source)
        for source in hub_config["sources"]
    ]

    # Local optional skills remain available in every mode. Private mode then
    # adds only explicitly configured enterprise origins: public adapters are
    # not even constructed, so no status probe/search/fallback can leak egress.
    local_sources: List[SkillSource] = [
        OptionalSkillSource(
            auth=auth,
            allow_remote_fallback=hub_config["mode"] != "private",
        )
    ]
    if hub_config["mode"] == "private":
        return [*local_sources, *enterprise_sources]

    taps_mgr = TapsManager()
    extra_taps = taps_mgr.list_taps()
    public_sources: List[SkillSource] = [
        HermesIndexSource(auth=auth), # Centralized index (search + resolved install paths)
        SkillsShSource(auth=auth),
        WellKnownSkillSource(),
        UrlSource(),                  # Direct HTTP(S) URL to a SKILL.md file
        GitHubSource(auth=auth, extra_taps=extra_taps),
        ClawHubSource(),
        LobeHubSource(),
        BrowseShSource(),   # browse.sh: 169+ site-specific browser automation skills
    ]
    if hub_config["mode"] == "hybrid":
        return [*local_sources, *enterprise_sources, *public_sources]
    return [*local_sources, *public_sources]


def _search_one_source(
    src: SkillSource, query: str, limit: int
) -> Tuple[str, List[SkillMeta]]:
    """Search a single source.  Runs in a thread for parallelism."""
    try:
        return src.source_id(), src.search(query, limit=limit)
    except Exception as e:
        logger.debug("Search failed for %s: %s", src.source_id(), e)
        return src.source_id(), []


def parallel_search_sources(
    sources: List[SkillSource],
    query: str = "",
    per_source_limits: Optional[Dict[str, int]] = None,
    source_filter: str = "all",
    overall_timeout: float = 30,
    on_source_done: Optional[Any] = None,
) -> Tuple[List[SkillMeta], Dict[str, int], List[str]]:
    """Search all sources in parallel with per-source timeout.

    Returns ``(all_results, source_counts, timed_out_ids)``.

    *on_source_done* is an optional callback ``(source_id, count) -> None``
    invoked as each source completes — useful for progress indicators.
    """
    import contextvars
    from concurrent.futures import as_completed

    per_source_limits = per_source_limits or {}

    # A provider filter (e.g. "nvidia", "openai") targets GitHub-tap skills
    # that the runtime index stores under source="github" with an
    # ``extra.provider`` label. It is NOT a real source id, so source-level
    # selection must treat it like "all" (the index / github source carries
    # the data); the per-provider narrowing happens downstream on the merged
    # results (see ``_filter_results_by_provider``).
    _provider_filter = source_filter.strip().lower() in _PROVIDER_FILTER_VALUES
    _effective_filter = "all" if _provider_filter else source_filter

    active: List[SkillSource] = []
    # When the centralized index is available and the user hasn't filtered
    # to a specific source, skip external API sources (github, skills-sh,
    # clawhub, etc.) — the index already has their data.  This avoids
    # ~70 GitHub API calls per search for unauthenticated users.
    _index_available = False
    _api_source_ids = frozenset({"github", "skills-sh", "clawhub",
                                  "lobehub", "well-known"})
    if _effective_filter == "all":
        for src in sources:
            if (src.source_id() == "hermes-index"
                    and getattr(src, "is_available", False)):
                _index_available = True
                break

    for src in sources:
        sid = src.source_id()
        if _effective_filter != "all" and sid != _effective_filter and sid != "official":
            continue
        # Skip external API sources when the index covers them
        if _index_available and sid in _api_source_ids:
            continue
        active.append(src)

    all_results: List[SkillMeta] = []
    source_counts: Dict[str, int] = {}
    timed_out_ids: List[str] = []

    if not active:
        return all_results, source_counts, timed_out_ids

    # NOTE: a `with ThreadPoolExecutor(...) as pool` block calls
    # ``shutdown(wait=True)`` on exit, which blocks until every submitted
    # worker finishes — so a single slow source (e.g. ClawHub) keeps the
    # caller blocked for minutes and renders ``overall_timeout`` a no-op.
    # Manage the executor manually and shut it down with ``wait=False`` so
    # the timeout is actually honoured.  Daemon workers (tools.daemon_pool):
    # an abandoned slow source must not block interpreter exit either —
    # stdlib workers are joined unconditionally by the atexit hook.
    from tools.daemon_pool import DaemonThreadPoolExecutor
    pool = DaemonThreadPoolExecutor(max_workers=min(len(active), 8))
    futures = {}
    for src in active:
        lim = per_source_limits.get(src.source_id(), 50)
        # Profile home + secret scopes are contextvars. ThreadPoolExecutor does
        # not propagate them automatically, so give every worker its own copy.
        ctx = contextvars.copy_context()
        fut = pool.submit(ctx.run, _search_one_source, src, query, lim)
        futures[fut] = src.source_id()

    try:
        try:
            for fut in as_completed(futures, timeout=overall_timeout):
                try:
                    sid, results = fut.result(timeout=0)
                    source_counts[sid] = len(results)
                    all_results.extend(results)
                    if on_source_done:
                        on_source_done(sid, len(results))
                except Exception:
                    pass
        except TimeoutError:
            timed_out_ids = [
                futures[f] for f in futures if not f.done()
            ]
            if timed_out_ids:
                logger.debug(
                    "Skills browse timed out waiting for: %s",
                    ", ".join(timed_out_ids),
                )
    finally:
        # wait=False so a slow source cannot block the caller's return;
        # cancel_futures drops not-yet-started work.
        pool.shutdown(wait=False, cancel_futures=True)

    return all_results, source_counts, timed_out_ids


def unified_search(query: str, sources: List[SkillSource],
                   source_filter: str = "all", limit: int = 10) -> List[SkillMeta]:
    """Search all sources (in parallel) and merge results."""
    all_results, _, _ = parallel_search_sources(
        sources,
        query=query,
        source_filter=source_filter,
        overall_timeout=30,
    )

    # A provider filter (nvidia/openai/...) is applied here, on the merged set,
    # because it targets the per-tap ``extra.provider`` label rather than a real
    # source id (the runtime index stores every GitHub tap as source="github").
    if source_filter.strip().lower() in _PROVIDER_FILTER_VALUES:
        all_results = _filter_results_by_provider(all_results, source_filter)

    # Deduplicate by identifier, preferring higher trust levels.
    # identifier is always unique per skill (e.g. "browse-sh/airbnb.com/search-listings-ddgioa").
    # Using name would incorrectly collapse browse-sh skills from different sites that share
    # the same task name (e.g. "search-listings" from Airbnb and Booking.com).
    _TRUST_RANK = {"builtin": 2, "trusted": 1, "community": 0}
    seen: Dict[str, SkillMeta] = {}
    for r in all_results:
        if r.identifier not in seen:
            seen[r.identifier] = r
        elif _TRUST_RANK.get(r.trust_level, 0) > _TRUST_RANK.get(seen[r.identifier].trust_level, 0):
            seen[r.identifier] = r
    deduped = list(seen.values())

    return deduped[:limit]
