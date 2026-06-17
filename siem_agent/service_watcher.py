from __future__ import annotations

import queue
import subprocess
import time
from typing import Any

from siem_agent.config import AgentConfig
from siem_agent.events import create_event


def service_status(service: str) -> str:
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def watch_service(service: str, config: AgentConfig, events: queue.Queue[dict[str, Any]]) -> None:
    previous = service_status(service)
    events.put(create_event(config, "service_status", "info", f"Service {service} status: {previous}", service))

    while True:
        time.sleep(config.interval)
        current = service_status(service)
        if current != previous:
            severity = "medium" if current not in {"active", "activating"} else "low"
            events.put(create_event(config, "service_status_changed", severity, f"Service {service}: {previous} -> {current}", service))
            previous = current
