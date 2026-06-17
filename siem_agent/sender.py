from __future__ import annotations

import queue
import time
from typing import Any

import requests

from siem_agent.config import AgentConfig


def send_event(config: AgentConfig, event: dict[str, Any]) -> bool:
    try:
        response = requests.post(config.server_url, json=event, timeout=5)
        response.raise_for_status()
        print(f"sent {event['event_type']} from {event['source']}")
        return True
    except requests.RequestException as exc:
        print(f"failed to send event: {exc}")
        return False


def sender_worker(config: AgentConfig, events: queue.Queue[dict[str, Any]]) -> None:
    while True:
        event = events.get()
        try:
            if not send_event(config, event):
                time.sleep(3)
                send_event(config, event)
        finally:
            events.task_done()
