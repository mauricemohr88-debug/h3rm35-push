"""Observer hooks only. No tools, actions, prompt injection or approval response."""

import logging

from .core import event_identity, process_store, supported_host, supports_private_storage
from .sender import Worker

logger = logging.getLogger("h3rm35.push")
INTERNAL_PLATFORMS = frozenset({"subagent", "curator"})


class Observer:
    def __init__(self, store, identity=event_identity):
        self.store, self.identity = store, identity

    def emit(self, kind, session_id, marker, platform):
        if not isinstance(platform, str) or platform in INTERNAL_PLATFORMS:
            return
        try:
            identity = self.identity(session_id)
            if identity is not None:
                self.store.enqueue(kind, *identity, marker)
        except Exception as error:
            logger.warning("notification observation unavailable (%s)", type(error).__name__)

    def completed(self, *, session_id="", turn_id="", platform="", assistant_response=None, **_):
        # A missing turn marker cannot be replaced with a timestamp: repeated
        # hooks would then manufacture distinct notifications for one turn.
        if (isinstance(turn_id, str) and turn_id
                and isinstance(assistant_response, str) and assistant_response.strip()):
            self.emit("response", session_id, turn_id, platform)

    def human_request(self, *, kind="", session_id="", request_id="", platform="", **_):
        if not isinstance(kind, str):
            return
        mapped = {"clarify": "clarification", "clarification": "clarification", "approval": "approval"}.get(kind)
        if mapped and isinstance(request_id, str) and request_id:
            self.emit(mapped, session_id, request_id, platform)


def register(ctx):
    if not supported_host():
        logger.warning("H3rm35 push requires the current human-input observer contract")
        return
    if not supports_private_storage():
        logger.warning("H3rm35 push native Windows private storage is not qualified; use WSL")
        return
    store = process_store()
    observer = Observer(store)
    worker = Worker(store)
    ctx.register_hook("post_llm_call", observer.completed)
    ctx.register_hook("on_human_input_request", observer.human_request)
    ctx.on_unload(worker.stop)
    worker.start()
