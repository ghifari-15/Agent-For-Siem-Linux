from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from siem_agent.config import AgentConfig


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def create_event(config: AgentConfig, event_type: str, severity: str, message: str, source: str) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "agent_id": config.agent_id,
        "hostname": config.hostname,
        "source_ip": get_local_ip(),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "message": message,
        "raw_log": message,
    }
