"""Not-Ready alerting for the configured Kubernetes resources, sent to Sentry.

Replaces SigNoz's "Kubernetes resource not Ready" rule (teable:coilyco/deploy#8693).
A resource whose Ready condition has been False for the grace period earns one Sentry
event, and another each renotify interval while it stays False. This is the one
handled-error path to Sentry, bounded to a single event per resource per interval.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import sentry_sdk
from sentry_sdk.transport import Transport

from node_stats_mcp.crash import node_name

_log = logging.getLogger(__name__)

# The old rule's window: every point in 15 minutes read not-Ready, renotified hourly.
DEFAULT_GRACE_SECONDS = 900
DEFAULT_RENOTIFY_SECONDS = 3600
MESSAGE_LIMIT = 300
# Sentry drops an event whose tag value is over 200 characters.
TAG_LIMIT = 200
FLUSH_SECONDS = 2.0
ALERT_DSN_ENV = "NODE_STATS_ALERT_SENTRY_DSN"

Key = tuple[str, str, str]


@dataclass(frozen=True)
class NotReadyConfig:
    grace_seconds: int
    renotify_seconds: int


@dataclass(frozen=True)
class NotReady:
    source: str
    namespace: str
    name: str
    reason: str
    message: str
    # How long Kubernetes says the Ready condition has been False, when it says.
    known_seconds: int | None


Sender = Callable[[NotReady, int, int], None]


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def load_config() -> NotReadyConfig:
    return NotReadyConfig(
        grace_seconds=_bounded_int(
            "NODE_STATS_NOTREADY_GRACE_SECONDS", DEFAULT_GRACE_SECONDS, 60, 86_400
        ),
        renotify_seconds=_bounded_int(
            "NODE_STATS_NOTREADY_RENOTIFY_SECONDS", DEFAULT_RENOTIFY_SECONDS, 300, 86_400
        ),
    )


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def scan(snapshot: Mapping[str, Any]) -> tuple[dict[Key, NotReady], set[Key], set[str]]:
    """Split a conditions snapshot into the not-Ready resources, every resource seen, and
    the sources whose list failed, so a failed list is never read as recovery."""
    not_ready: dict[Key, NotReady] = {}
    seen: set[Key] = set()
    failed: set[str] = set()
    for source in _items(snapshot.get("sources")):
        source_name = str(source.get("name") or "unknown")
        if source.get("errors"):
            failed.add(source_name)
            continue
        for item in _items(source.get("items")):
            namespace = str(item.get("namespace") or "cluster")
            key = (source_name, namespace, str(item.get("name") or "unknown"))
            seen.add(key)
            # Only a condition literally named Ready, False, as the SigNoz rule read it.
            for condition in _items(item.get("conditions")):
                is_ready = condition.get("type") == "Ready"
                if is_ready and str(condition.get("status")).lower() == "false":
                    age = condition.get("last_transition_age_seconds")
                    not_ready[key] = NotReady(
                        source=key[0],
                        namespace=key[1],
                        name=key[2],
                        reason=str(condition.get("reason") or "")[:MESSAGE_LIMIT],
                        message=str(condition.get("message") or "")[:MESSAGE_LIMIT],
                        known_seconds=int(age) if isinstance(age, int | float) else None,
                    )
                    break
    return not_ready, seen, failed


def make_sentry_sender(dsn: str, transport: Transport | None = None) -> Sender:
    """A sender on its own Sentry client, so it neither shares crash reporting's budget nor
    needs it on. Events carry alert=true, the tag the fleet-heartbeats rule keys on."""
    try:
        client = sentry_sdk.Client(
            dsn=dsn,
            transport=transport,
            traces_sample_rate=0.0,
            send_default_pii=False,
            default_integrations=False,
            environment=os.environ.get("OTEL_DEPLOYMENT_ENVIRONMENT", "homelab"),
        )
    except Exception as exc:
        # The class only: a BadDsn message can carry the DSN itself.
        raise ValueError(
            f"{ALERT_DSN_ENV} is not a valid Sentry DSN ({type(exc).__name__})"
        ) from exc

    def send(report: NotReady, seconds: int, notification: int) -> None:
        node = node_name()
        minutes = max(1, seconds // 60)
        tags = {
            "alert": "true",
            "source": "k8s-not-ready",
            "node": node,
            "kind": report.source,
            "namespace": report.namespace,
            "name": report.name,
        }
        client.capture_event(
            {
                "message": (
                    f"{report.source} {report.namespace}/{report.name} "
                    f"has been not Ready for {minutes}m"
                ),
                "level": "error",
                "logger": "node-stats-not-ready",
                "fingerprint": [
                    "k8s-not-ready",
                    node,
                    report.source,
                    report.namespace,
                    report.name,
                ],
                "tags": {key: value[:TAG_LIMIT] for key, value in tags.items()},
                "extra": {
                    "reason": report.reason,
                    "condition_message": report.message,
                    "not_ready_seconds": seconds,
                    "notification": notification,
                },
            }
        )
        client.flush(timeout=FLUSH_SECONDS)

    return send


def sender_from_env() -> Sender | None:
    """The Sentry sender when NODE_STATS_ALERT_SENTRY_DSN is set, else None."""
    dsn = os.environ.get(ALERT_DSN_ENV, "").strip()
    return make_sentry_sender(dsn) if dsn else None


class NotReadyWatch:
    """Remembers when each resource was first seen not Ready, and who has been told."""

    def __init__(
        self,
        config: NotReadyConfig,
        send: Sender,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._config = config
        self._send = send
        self._clock = clock
        self._first: dict[Key, float] = {}
        self._sent_at: dict[Key, float] = {}
        self._notifications: dict[Key, int] = {}

    def observe(self, snapshot: Mapping[str, Any]) -> int:
        """Take one conditions snapshot and return how many events it sent."""
        now = self._clock()
        not_ready, seen, failed = scan(snapshot)
        sent = 0
        for key, report in not_ready.items():
            first = self._first.setdefault(key, now)
            seconds = int(max(now - first, report.known_seconds or 0))
            if seconds < self._config.grace_seconds:
                continue
            last = self._sent_at.get(key)
            if last is not None and now - last < self._config.renotify_seconds:
                continue
            count = self._notifications.get(key, 0) + 1
            try:
                self._send(report, seconds, count)
            except Exception as exc:
                # The class only: a Sentry error can carry the DSN.
                _log.warning("not-Ready event for %s failed (%s)", key, type(exc).__name__)
                continue
            self._sent_at[key] = now
            self._notifications[key] = count
            sent += 1
        # Recovered, or gone, unless its source failed to list this cycle.
        settled = [
            key
            for key in self._first
            if key not in not_ready and (key in seen or key[0] not in failed)
        ]
        for key in settled:
            for state in (self._first, self._sent_at, self._notifications):
                state.pop(key, None)
        return sent
