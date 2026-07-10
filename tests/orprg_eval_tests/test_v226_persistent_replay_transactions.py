from pathlib import Path

from orprg_eval.persistent_replay import SQLiteReplayCache


def test_sqlite_reservation_release_does_not_consume_nonce(tmp_path: Path):
    cache = SQLiteReplayCache(tmp_path / "replay.sqlite3")
    first = cache.reserve("domain", "nonce")
    assert first is not None
    assert cache.contains("domain", "nonce")
    first.release()
    assert not cache.contains("domain", "nonce")
    second = cache.reserve("domain", "nonce")
    assert second is not None
    assert second.commit()
    assert cache.count() == 1


def test_sqlite_reservation_commit_persists_across_instances(tmp_path: Path):
    path = tmp_path / "replay.sqlite3"
    cache = SQLiteReplayCache(path)
    reservation = cache.reserve("domain", "nonce")
    assert reservation is not None and reservation.commit()
    reopened = SQLiteReplayCache(path)
    assert reopened.contains("domain", "nonce")
    assert reopened.reserve("domain", "nonce") is None
