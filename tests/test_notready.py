"""Not-Ready alerting replaces SigNoz's rule (teable:coilyco/deploy#8693)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sentry_sdk.transport import Transport

from node_stats_mcp import crash, exporter, notready

GRACE = 900
RENOTIFY = 3600
DSN = "https://public@example.invalid/1"


def _config() -> notready.NotReadyConfig:
    return notready.NotReadyConfig(grace_seconds=GRACE, renotify_seconds=RENOTIFY)


def _item(
    name: str,
    status: str = "False",
    *,
    age: int | None = None,
    ctype: str = "Ready",
    reason: str = "SecretSyncedError",
    message: str = "could not get secret data",
) -> dict[str, Any]:
    return {
        "namespace": "apps",
        "name": name,
        "conditions": [
            {
                "type": ctype,
                "status": status,
                "reason": reason,
                "message": message,
                "last_transition_age_seconds": age,
            }
        ],
    }


def _snapshot(
    *items: dict[str, Any], source: str = "externalsecrets", errors: list[str] | None = None
) -> dict[str, Any]:
    return {"sources": [{"name": source, "items": list(items), "errors": errors or []}]}


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _watch() -> tuple[notready.NotReadyWatch, list[tuple[str, int, int]], _Clock]:
    sent: list[tuple[str, int, int]] = []
    clock = _Clock()

    def send(report: notready.NotReady, seconds: int, notification: int) -> None:
        sent.append((report.name, seconds, notification))

    return notready.NotReadyWatch(_config(), send, clock), sent, clock


def test_a_resource_not_ready_past_the_grace_is_reported_once_per_interval() -> None:
    watch, sent, clock = _watch()
    snapshot = _snapshot(_item("sirens-secret"))
    assert watch.observe(snapshot) == 0, "first sight is inside the grace period"
    clock.now += GRACE
    assert watch.observe(snapshot) == 1
    assert sent == [("sirens-secret", GRACE, 1)]
    clock.now += RENOTIFY - 1
    assert watch.observe(snapshot) == 0, "inside the renotify interval it stays quiet"
    clock.now += 1
    assert watch.observe(snapshot) == 1
    assert sent[-1][2] == 2


def test_kubernetes_transition_age_counts_so_a_restart_does_not_restart_the_grace() -> None:
    watch, sent, _ = _watch()
    assert watch.observe(_snapshot(_item("stuck", age=5 * 3600))) == 1
    assert sent[0][1] == 5 * 3600


def test_a_recovered_resource_starts_a_fresh_grace_when_it_fails_again() -> None:
    watch, sent, clock = _watch()
    watch.observe(_snapshot(_item("flaky")))
    clock.now += GRACE
    assert watch.observe(_snapshot(_item("flaky"))) == 1
    clock.now += 60
    assert watch.observe(_snapshot(_item("flaky", status="True"))) == 0
    clock.now += RENOTIFY
    assert watch.observe(_snapshot(_item("flaky"))) == 0, "a new failure waits out its own grace"
    assert len(sent) == 1


@pytest.mark.parametrize(
    "item",
    [_item("a", status="True"), _item("b", status="Unknown"), _item("c", ctype="Healthy")],
)
def test_only_a_ready_condition_that_is_false_counts(item: dict[str, Any]) -> None:
    watch, sent, clock = _watch()
    watch.observe(_snapshot(item))
    clock.now += GRACE * 2
    assert watch.observe(_snapshot(item)) == 0
    assert sent == []


def test_a_source_whose_list_failed_is_not_read_as_recovery() -> None:
    watch, sent, clock = _watch()
    watch.observe(_snapshot(_item("held")))
    clock.now += GRACE
    watch.observe(_snapshot(errors=["list failed"]))
    clock.now += RENOTIFY
    assert watch.observe(_snapshot(_item("held"))) == 1, "the clock survived the failed list"
    assert len(sent) == 1


def test_a_deleted_resource_is_forgotten() -> None:
    watch, sent, clock = _watch()
    watch.observe(_snapshot(_item("gone")))
    clock.now += GRACE
    watch.observe(_snapshot())
    clock.now += RENOTIFY
    assert watch.observe(_snapshot(_item("gone"))) == 0
    assert sent == []


def test_a_send_that_raises_does_not_stop_the_cycle_and_is_retried() -> None:
    clock = _Clock()
    calls = {"n": 0}

    def send(report: notready.NotReady, seconds: int, notification: int) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("sentry down")

    watch = notready.NotReadyWatch(_config(), send, clock)
    snapshot = _snapshot(_item("x", age=GRACE))
    assert watch.observe(snapshot) == 0
    assert watch.observe(snapshot) == 1, "a failed send is not recorded, so the next cycle retries"


class _Capture(Transport):
    def __init__(self) -> None:
        super().__init__()
        self.events: list[Any] = []

    def capture_envelope(self, envelope: Any) -> None:
        event = envelope.get_event()
        if event is not None:
            self.events.append(event)


def _sender() -> tuple[notready.Sender, _Capture]:
    transport = _Capture()
    return notready.make_sentry_sender(DSN, transport), transport


def test_the_event_carries_alert_true_and_groups_by_resource(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NODE_STATS_K3S_NODE_NAME", "node-b")
    send, transport = _sender()
    watch = notready.NotReadyWatch(_config(), send)
    assert watch.observe(_snapshot(_item("sirens-secret", age=3 * 3600))) == 1
    (event,) = transport.events
    assert event["level"] == "error"
    assert event["fingerprint"] == [
        "k8s-not-ready",
        "node-b",
        "externalsecrets",
        "apps",
        "sirens-secret",
    ]
    assert event["message"] == "externalsecrets apps/sirens-secret has been not Ready for 180m"
    assert event["tags"]["alert"] == "true", "the fleet-heartbeats rule keys on this tag"
    assert (event["tags"]["kind"], event["tags"]["namespace"]) == ("externalsecrets", "apps")
    assert event["extra"]["reason"] == "SecretSyncedError"


def test_the_alert_client_does_not_touch_crash_reporting(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    send, transport = _sender()
    assert crash.init_crash_reporting("exporter") is False
    send(
        notready.NotReady("externalsecrets", "apps", "x", "r", "m", None),
        GRACE,
        1,
    )
    assert len(transport.events) == 1


def test_a_malformed_alert_dsn_fails_loudly_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(notready.ALERT_DSN_ENV, "https://secretkey@")
    with pytest.raises(ValueError, match="not a valid Sentry DSN") as raised:
        notready.sender_from_env()
    assert "secretkey" not in str(raised.value)


def test_no_alert_dsn_means_no_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(notready.ALERT_DSN_ENV, raising=False)
    assert notready.sender_from_env() is None


def test_the_condition_message_is_bounded() -> None:
    long = "x" * 5000
    not_ready, _, _ = notready.scan(_snapshot(_item("loud", message=long)))
    assert len(next(iter(not_ready.values())).message) == notready.MESSAGE_LIMIT


def test_the_run_cycle_alerts_before_it_posts_so_a_dead_collector_cannot_silence_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def collect(_limit: int, *, include_volume: bool) -> dict[str, dict[str, Any]]:
        return {"conditions": _snapshot(_item("stuck", age=2 * GRACE))}

    monkeypatch.setattr(exporter, "collect_sources", collect)

    def dead(_url: str, _body: bytes, _timeout: float) -> int:
        raise ConnectionError("collector down")

    sent: list[str] = []
    watch = notready.NotReadyWatch(_config(), lambda r, s, n: sent.append(r.name))
    result = asyncio.run(
        exporter.run_cycle(
            exporter.ExportConfig("http://c:4318", 60, 900, 50, 2_048, 65_536, 2_000, 5.0),
            include_volume=False,
            post=dead,
            watch=watch,
        )
    )
    assert sent == ["stuck"]
    assert result.not_ready_events == 1
    assert not result.succeeded, "the post failures still show"


def test_a_failed_conditions_collection_leaves_the_watch_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def collect(_limit: int, *, include_volume: bool) -> dict[str, dict[str, Any]]:
        return {"conditions": {"collection_error": "boom", "errors": ["boom"]}}

    monkeypatch.setattr(exporter, "collect_sources", collect)
    watch = notready.NotReadyWatch(_config(), lambda r, s, n: None)
    result = asyncio.run(
        exporter.run_cycle(
            exporter.ExportConfig("http://c:4318", 60, 900, 50, 2_048, 65_536, 2_000, 5.0),
            include_volume=False,
            dry_run=True,
            watch=watch,
        )
    )
    assert result.not_ready_events == 0


def test_the_thresholds_come_from_bounded_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NODE_STATS_NOTREADY_GRACE_SECONDS", "120")
    assert notready.load_config().grace_seconds == 120
    monkeypatch.setenv("NODE_STATS_NOTREADY_GRACE_SECONDS", "5")
    with pytest.raises(ValueError, match="between 60"):
        notready.load_config()
