"""Crash reporting to Sentry, beside SigNoz: crashes only, fully annotated.

Handled errors stay in SigNoz to keep inside Sentry's free quota
(teable:coilyco/deploy#8347). Every integration stays on to annotate a crash,
and the scrubber takes the keys that hold process and host data.
"""

from __future__ import annotations

import logging
import os
import socket
import time
from typing import TYPE_CHECKING, Any

import sentry_sdk
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.integrations.starlette import StarletteIntegration
from sentry_sdk.scrubber import DEFAULT_DENYLIST, EventScrubber

if TYPE_CHECKING:
    from sentry_sdk.types import Event

_log = logging.getLogger(__name__)

SENTRY_EVENTS_PER_MINUTE = 20

# Frame locals and request bodies stay on to annotate a crash. These keys hold
# process command lines and environments, which can carry secrets.
USER_DATA_KEYS = [
    "cmdline",
    "argv",
    "args",
    "environ",
    "env",
    "command",
    "body",
    "payload",
]
_initialized = False
_active = False
_window: list[float] = []


def _within_budget(now: float) -> bool:
    """Cap events per process so one crash loop cannot spend the monthly quota."""
    cutoff = now - 60.0
    while _window and _window[0] < cutoff:
        _window.pop(0)
    if len(_window) >= SENTRY_EVENTS_PER_MINUTE:
        return False
    _window.append(now)
    return True


def _before_send(event: Event, _hint: dict[str, Any]) -> Event | None:
    return event if _within_budget(time.monotonic()) else None


def init_crash_reporting(component: str) -> bool:
    """Send unhandled exceptions to Sentry once, when SENTRY_DSN is set."""
    global _active, _initialized
    if _initialized:
        return _active
    _initialized = True
    dsn = os.environ.get("SENTRY_DSN", "").strip()
    if not dsn:
        return False
    try:
        sentry_sdk.init(
            dsn=dsn,
            traces_sample_rate=0.0,
            environment=os.environ.get("OTEL_DEPLOYMENT_ENVIRONMENT", "homelab"),
            before_send=_before_send,
            send_default_pii=False,
            event_scrubber=EventScrubber(
                denylist=DEFAULT_DENYLIST + USER_DATA_KEYS, recursive=True
            ),
            integrations=[
                # Breadcrumbs only: an ERROR log is a handled error, kept in SigNoz.
                LoggingIntegration(event_level=None),
                # Only uncaught exceptions, never a 5xx response the server chose to send.
                StarletteIntegration(failed_request_status_codes=set()),
            ],
        )
        # The same image runs on two nodes, so the node tag keeps them apart.
        node = os.environ.get("NODE_STATS_K3S_NODE_NAME", "").strip() or socket.gethostname()
        sentry_sdk.set_tag("node", node)
        sentry_sdk.set_tag("component", component)
    except Exception as exc:
        # The class only: a BadDsn message can carry the DSN itself.
        _log.warning("Sentry initialization failed (%s); continuing", type(exc).__name__)
        return False
    _active = True
    return True
