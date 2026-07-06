import sqlite3

from contextlib import contextmanager

DBNAME = "db.sqlite3"
DB_TIMEOUT = 30.0  # ロック競合時に他スレッドの解放を待つ秒数


@contextmanager
def get_connection():
    conn = None
    try:
        conn = sqlite3.connect(DBNAME, timeout=DB_TIMEOUT, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        yield conn
        conn.commit()
    except Exception:
        if conn is not None:
            conn.rollback()
        raise
    finally:
        if conn is not None:
            conn.close()
