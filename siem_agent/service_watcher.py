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
        if result.returncode == 4:
            return "not-found"
        return result.stdout.strip() or result.stderr.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def watch_service(service: str, config: AgentConfig, events: queue.Queue[dict[str, Any]]) -> None:
    previous = service_status(service)
    if previous == "not-found":
        print(f"service not found, skipping: {service}")
        return

    if previous in {"active", "activating"}:
        events.put(create_event(config, "service_started", "low", f"Service {service} status: {previous}", service))
    elif previous not in {"unknown", "inactive"}:
        events.put(create_event(config, "service_stopped", "high", f"Service {service} status: {previous}", service))

    while True:
        time.sleep(config.interval)
        current = service_status(service)
        if current != previous:
            if current in {"active", "activating"}:
                event_type = "service_started"
                severity = "low"
            else:
                event_type = "service_stopped"
                severity = "high"
            events.put(create_event(config, event_type, severity, f"Service {service}: {previous} -> {current}", service))
            previous = current
