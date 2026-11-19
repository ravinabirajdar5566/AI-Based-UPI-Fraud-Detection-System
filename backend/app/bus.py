"""Tiny in-process event bus that feeds the live (Server-Sent Events) streams.
Worker threads call publish(); every open browser stream receives the event instantly."""
import asyncio
import collections
import threading
import time

_subs = []
_lock = threading.Lock()
_recent = collections.deque(maxlen=60)


def subscribe():
    sub = (asyncio.get_running_loop(), asyncio.Queue(maxsize=300))
    with _lock:
        _subs.append(sub)
    return sub


def unsubscribe(sub):
    with _lock:
        if sub in _subs:
            _subs.remove(sub)


def _put(q, e):
    try:
        q.put_nowait(e)
    except asyncio.QueueFull:
        pass


def publish(event):
    event = {**event, "ts": time.time()}
    with _lock:
        _recent.append(event)
        subs = list(_subs)
    for loop, q in subs:
        try:
            loop.call_soon_threadsafe(_put, q, event)
        except RuntimeError:  # loop closed
            pass


def recent():
    with _lock:
        return list(_recent)


def listeners():
    with _lock:
        return len(_subs)
