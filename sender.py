"""Fixed publisher destination; only a bounded background worker performs HTTP."""

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DISCOVERY = "https://kiablauf.de/h3rm35/push-service.json"
logger = logging.getLogger("h3rm35.push")
_cached = None
_cache_lock = threading.Lock()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def publisher_origin():
    global _cached
    with _cache_lock:
        if _cached and _cached[0] > time.monotonic():
            return _cached[1]
        with opener().open(DISCOVERY, timeout=8) as response:
            raw = response.read(2049)
            if response.status != 200 or len(raw) > 2048:
                raise ValueError("publisher unavailable")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate publisher key")
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or set(data) != {"schema", "enabled", "relay_origin"}
                or type(data["schema"]) is not int or data["schema"] != 2 or data["enabled"] is not True
                or not isinstance(data["relay_origin"], str) or len(data["relay_origin"]) > 512):
            raise ValueError("publisher unavailable")
        value = data["relay_origin"]
        parts = urllib.parse.urlsplit(value)
        if (parts.scheme != "https" or not parts.hostname or not parts.hostname.isascii()
                or parts.username is not None or parts.password is not None
                or parts.path or parts.query or parts.fragment or "?" in value or "#" in value
                or "%" in value or "\\" in value or any(c.isspace() for c in value)
                or parts.port == 0 or value != "https://"+parts.netloc.lower()):
            raise ValueError("invalid publisher origin")
        _cached = (time.monotonic()+3600, value)
        return value


def send(item):
    try:
        origin = publisher_origin()
    except (OSError, ValueError):
        return "retry"
    request = urllib.request.Request(origin+"/v1/events", data=item["payload"].encode(), method="POST",
                                     headers={"Authorization": "Bearer "+item["host_secret"], "Content-Type": "application/json"})
    try:
        with opener().open(request, timeout=8) as response:
            raw = response.read(2049)
            if response.status != 202 or len(raw) > 2048:
                logger.warning("notification delivery rejected (invalid acknowledgement)")
                return "done"
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("event_id") != item["event_id"]:
                logger.warning("notification delivery rejected (invalid identity)")
            return "done"
    except urllib.error.HTTPError as error:
        if error.code in {401, 403, 410}:
            return "revoke"
        if error.code == 429 or error.code >= 500:
            return "retry"
        logger.warning("notification delivery rejected (HTTP %d)", error.code)
        return "done"
    except (OSError, ValueError):
        return "retry"


class Worker:
    def __init__(self, store):
        self.store = store
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, name="h3rm35-push-send", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=0.1)

    def run(self):
        while not self.stopped.is_set():
            try:
                item = self.store.claim()
                if item is None:
                    self.stopped.wait(1)
                else:
                    outcome = send(item)
                    if outcome == "revoke":
                        self.store.remove(item["binding_id"])
                    else:
                        self.store.finish(item, outcome == "retry")
                    if outcome == "done":
                        logger.debug("notification delivery attempt settled")
            except Exception as error:
                # The capability, full request and exception text must never be logged.
                logger.warning("notification delivery unavailable (%s)", type(error).__name__)
                self.stopped.wait(5)
