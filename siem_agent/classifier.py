from __future__ import annotations

import re
from typing import Any

from siem_agent.config import AgentConfig
from siem_agent.events import create_event


def classify_log_line(config: AgentConfig, source: str, line: str) -> dict[str, Any]:
    normalized = line.strip()
    lower = normalized.lower()

    if re.search(r"failed password|authentication failure|invalid user", lower):
        event = create_event(config, "ssh_login_failed", "medium", normalized, source)
    elif re.search(r"accepted password|accepted publickey", lower):
        event = create_event(config, "ssh_login_success", "low", normalized, source)
    elif "sudo" in lower and re.search(r"authentication failure|incorrect password|not in the sudoers", lower):
        event = create_event(config, "sudo_failed", "medium", normalized, source)
    elif re.search(r"new user|useradd|adduser", lower):
        event = create_event(config, "user_created", "medium", normalized, source)
    elif re.search(r"delete user|userdel|deluser", lower):
        event = create_event(config, "user_deleted", "high", normalized, source)
    elif re.search(r"install |installed|apt\[|dpkg", lower):
        event = create_event(config, "package_activity", "low", normalized, source)
    elif re.search(r"started |stopped |systemd", lower):
        event = create_event(config, "service_activity", "low", normalized, source)
    else:
        event = create_event(config, "log_event", "info", normalized, source)

    event["raw_log"] = normalized
    return event
