import asyncio
import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

import pytest

from node_stats_mcp import exporter, health


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class StopCycleError(Exception):
    pass


@pytest.fixture
def served() -> Iterator[tuple[str, health.Heartbeat, Clock]]:
    clock = Clock()
    heartbeat = health.Heartbeat(clock)
    server = health.start_health_server("127.0.0.1", 0, "kai-server", heartbeat)
    yield f"http://127.0.0.1:{server.server_address[1]}", heartbeat, clock
    server.shutdown()
    server.server_close()


def _get(url: str) -> tuple[int, dict[str, Any]]:
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.status, json.loads(response.read())


def _config(**overrides: Any) -> exporter.ExportConfig:
    values: dict[str, Any] = {
        "endpoint": "http://collector:4318",
        "interval_seconds": 60,
        "volume_interval_seconds": 900,
        "limit": 50,
        "max_log_bytes": 2_048,
        "max_payload_bytes": 65_536,
        "max_metric_points": 2_000,
        "timeout_seconds": 5.0,
    }
    return exporter.ExportConfig(**{**values, **overrides})


def _collect(filesystem: dict[str, Any] | None) -> Any:
    async def fake(limit: int, *, include_volume: bool) -> dict[str, dict[str, Any]]:
        return {} if filesystem is None else {"filesystem": filesystem}

    return fake


def _cycle(heartbeat: health.Heartbeat) -> None:
    asyncio.run(
        exporter.run_cycle(
            _config(), include_volume=False, post=lambda *_: 200, heartbeat=heartbeat
        )
    )


def test_the_field_is_present_and_large_before_the_first_cycle(served: Any) -> None:
    url, _, _ = served
    status, body = _get(f"{url}/healthz")
    assert status == 200
    assert body == {
        "ok": True,
        "node": "kai-server",
        "last_cycle_age_seconds": health.NEVER_COLLECTED_AGE_SECONDS,
    }
    assert isinstance(body["last_cycle_age_seconds"], int)
    assert body["last_cycle_age_seconds"] > 900


def test_age_counts_from_the_last_beat(served: Any) -> None:
    url, heartbeat, clock = served
    heartbeat.beat()
    clock.now += 61.9
    assert _get(f"{url}/healthz")[1]["last_cycle_age_seconds"] == 61
    heartbeat.beat()
    assert _get(f"{url}/healthz")[1]["last_cycle_age_seconds"] == 0


def test_age_keeps_growing_while_collection_fails_and_the_endpoint_still_answers(
    served: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, heartbeat, clock = served
    monkeypatch.setattr(exporter, "collect_sources", _collect({"root": {"status": "ok"}}))
    _cycle(heartbeat)
    ages = []
    monkeypatch.setattr(
        exporter, "collect_sources", _collect({"collection_error": "OSError: boom", "errors": []})
    )
    for _ in range(3):
        clock.now += 300
        _cycle(heartbeat)
        status, body = _get(f"{url}/healthz")
        assert status == 200
        ages.append(body["last_cycle_age_seconds"])
    assert ages == [300, 600, 900]


def test_a_cycle_without_a_filesystem_source_does_not_beat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    heartbeat = health.Heartbeat(Clock())
    monkeypatch.setattr(exporter, "collect_sources", _collect(None))
    _cycle(heartbeat)
    assert heartbeat.age_seconds() == health.NEVER_COLLECTED_AGE_SECONDS


def test_a_collected_filesystem_snapshot_beats(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Clock()
    heartbeat = health.Heartbeat(clock)
    monkeypatch.setattr(exporter, "collect_sources", _collect({"root": {"status": "ok"}}))
    _cycle(heartbeat)
    clock.now += 5
    assert heartbeat.age_seconds() == 5


def test_other_paths_are_not_found(served: Any) -> None:
    url, _, _ = served
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(f"{url}/metrics", timeout=5)
    assert caught.value.code == 404


def test_the_endpoint_is_off_unless_the_port_is_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NODE_STATS_HEALTH_PORT", raising=False)
    assert exporter.load_config(require_endpoint=False).health_port is None
    started: list[Any] = []
    monkeypatch.setattr(exporter, "start_health_server", lambda *a: started.append(a))
    monkeypatch.setattr(exporter, "collect_sources", _collect({"root": {}}))
    asyncio.run(exporter.run_exporter(_config(), once=True, dry_run=True))
    asyncio.run(exporter.run_exporter(_config(health_port=None), once=True, dry_run=False))
    assert started == []


def test_the_port_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NODE_STATS_HEALTH_PORT", "9111")
    assert exporter.load_config(require_endpoint=False).health_port == 9111


@pytest.mark.parametrize("value", ["abc", "0", "70000", "-1"])
def test_a_bad_port_stops_the_start(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("NODE_STATS_HEALTH_PORT", value)
    with pytest.raises(ValueError, match="NODE_STATS_HEALTH_PORT"):
        exporter.load_config(require_endpoint=False)


def test_the_long_running_exporter_binds_all_interfaces_with_its_node_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started: list[Any] = []

    async def stop_after_one_cycle(_: float) -> None:
        raise StopCycleError

    monkeypatch.setattr(exporter, "start_health_server", lambda *a: started.append(a))
    monkeypatch.setenv("NODE_STATS_K3S_NODE_NAME", "other-node")
    monkeypatch.setattr(exporter, "collect_sources", _collect({"root": {}}))
    monkeypatch.setattr(exporter.asyncio, "sleep", stop_after_one_cycle)
    with pytest.raises(StopCycleError):
        asyncio.run(exporter.run_exporter(_config(health_port=9111), once=False, dry_run=False))
    assert [(a[0], a[1], a[2]) for a in started] == [("0.0.0.0", 9111, "other-node")]


def test_a_port_already_taken_does_not_stop_the_exporter(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(*_: Any) -> None:
        raise OSError("Address already in use")

    monkeypatch.setattr(exporter, "start_health_server", refuse)
    exporter._serve_health(9111, health.Heartbeat())
    event = json.loads(capsys.readouterr().err)
    assert event["status"] == "error"
    assert "already in use" in event["why"]
