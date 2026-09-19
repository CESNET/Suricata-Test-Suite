"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Helpers for working with the local persistent/cache directory (``./.cache``).

The cache stores transient generated files (merged or VLAN-tagged pcaps,
TRex/Suricata configs, ...) under deterministic, content-independent names so
that identical inputs reuse previously generated artifacts.

The cache has two scopes:

- ``.cache/persistent/``: kept until the cache is deleted manually.
- ``.cache/run/``: wiped once at the start of each pytest session by the
  session-scoped ``run_cache_cleanup`` fixture in ``conftest.py``.

``try_cache()`` looks into the run cache first and then into the persistent
one, so a session-local artifact always shadows an older persistent one with
the same key. Delete the whole ``.cache/`` directory to force regeneration of
everything.
"""

import hashlib
import logging
import shutil
from collections.abc import Sequence
from pathlib import Path

logger = logging.getLogger(__name__)

CACHE_ROOT = Path(__file__).resolve().parent.parent / ".cache"
PERSISTENT_DIR = CACHE_ROOT / "persistent"
RUN_DIR = CACHE_ROOT / "run"

_KEY_LENGTH = 12


def _cache_key(*parts: object) -> str:
    """Return a short hash derived from the given parts."""
    return hashlib.md5("|".join(str(p) for p in parts).encode()).hexdigest()[
        :_KEY_LENGTH
    ]


def _cache_name(name: str, *key_parts: object) -> str:
    """Return the cache filename for `name` with `key_parts` baked in.

    The key is inserted between the stem and the suffix, e.g.
    ``("stf_profile.yaml", ...parts)`` -> ``stf_profile_<key>.yaml``.
    Without key parts the name is used as-is.
    """
    if not key_parts:
        return name
    path = Path(name)
    return f"{path.stem}_{_cache_key(name, *key_parts)}{path.suffix}"


def file_fingerprint(*paths: Path) -> list[str]:
    """Return a short content hash for each given file.

    Opt-in for inputs that may change in place: spread the returned
    fingerprints into `key_parts` of `try_cache()`/`cache_path()` to make
    the cache sensitive to file contents rather than just names.
    """
    fingerprints = []
    for path in paths:
        digest = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                digest.update(chunk)
        fingerprints.append(digest.hexdigest()[:_KEY_LENGTH])
    return fingerprints


def cache_path(name: str, *key_parts: object, persistent: bool = True) -> Path:
    """Return the path of `name` inside the cache, creating the directory.

    `name` may carry an extension; when `key_parts` are given, a short hash
    of them is embedded into the filename. Pass `persistent=False` to get a
    path under the run-scoped cache (wiped at the start of every pytest
    session).
    """
    base = PERSISTENT_DIR if persistent else RUN_DIR
    base.mkdir(parents=True, exist_ok=True)
    return base / _cache_name(name, *key_parts)


def try_cache(name: str, key_parts: Sequence[object] = ()) -> Path | None:
    """Return the path to a cached `name` if it exists, `None` otherwise.

    The run cache is checked before the persistent one. On a miss the caller
    should generate the artifact and write it to a path obtained from
    `cache_path()` with the same `name` and `key_parts`.
    """
    filename = _cache_name(name, *key_parts)
    for base in (RUN_DIR, PERSISTENT_DIR):
        candidate = base / filename
        if candidate.is_file():
            logger.debug("Cache hit: %s", candidate)
            return candidate
    logger.debug("Cache miss: %s", filename)
    return None


def clear_run_cache() -> None:
    """Delete the run-scoped cache directory."""
    shutil.rmtree(RUN_DIR, ignore_errors=True)


def clear_cache() -> None:
    """Delete the whole cache directory."""
    shutil.rmtree(CACHE_ROOT, ignore_errors=True)
