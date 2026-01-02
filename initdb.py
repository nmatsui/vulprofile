import sqlite3

DBNAME = 'db.sqlite3'

with sqlite3.connect(DBNAME) as conn:
    cur = conn.cursor()
    cur.execute('CREATE TABLE users(\
                    username STRING PRIMARY KEY, \
                    password STRING, \
                    profile STRING)')
    conn.commit()
