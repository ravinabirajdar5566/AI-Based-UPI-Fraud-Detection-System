"""In-app notifications (the bell). Also pushed live to that user's open stream."""
from . import bus, db


def add(user_id, level, title, body=""):
    db.x("INSERT INTO notifications(user_id,ts,level,title,body) VALUES(?,?,?,?,?)",
         (user_id, db.now(), level, title, body))
    bus.publish({"type": "notify", "user_id": user_id, "level": level, "title": title, "body": body})


def for_user(user_id, limit=30):
    return db.q("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT ?", (user_id, limit))


def unread(user_id):
    return db.q("SELECT COUNT(*) AS c FROM notifications WHERE user_id=? AND read=0", (user_id,))[0]["c"]


def mark_all_read(user_id):
    db.x("UPDATE notifications SET read=1 WHERE user_id=?", (user_id,))
