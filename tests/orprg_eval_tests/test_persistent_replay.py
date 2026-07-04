from pathlib import Path
from orprg_eval.persistent_replay import SQLiteReplayCache

def test_sqlite_replay_cache_persists(tmp_path: Path):
    db = tmp_path / "replay.sqlite3"
    c = SQLiteReplayCache(db)
    assert c.check_and_mark("receipt", "n1") is True
    assert c.check_and_mark("receipt", "n1") is False
    c2 = SQLiteReplayCache(db)
    assert c2.check_and_mark("receipt", "n1") is False
