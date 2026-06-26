from __future__ import annotations

import re
from typing import Any

from siem_agent.config import AgentConfig
from siem_agent.events import create_event

def classify_log_line(config: AgentConfig, source: str, line: str) -> dict[str, Any]:
    normalized = line.strip()
    lower = normalized.lower()

    if "sudo" in lower and re.search(r"authentication failure|incorrect password|not in the sudoers|conversation failed|auth could not identify password", lower):
        event = create_event(config, "failed_sudo", "high", normalized, source)
    elif re.search(r"\b(delete user|userdel|deluser)\b", lower):
        event = create_event(config, "user_deleted", "high", normalized, source)

    elif re.search(r"sshd.*(failed password|authentication failure|invalid user)|failed password.*sshd|invalid user.*sshd", lower):
        event = create_event(config, "failed_ssh_login", "medium", normalized, source)

    elif re.search(r"sshd.*accepted (password|publickey)|accepted (password|publickey).*sshd", lower):
        event = create_event(config, "successful_ssh_login", "low", normalized, source)

    elif re.search(r"\b(new user|useradd|adduser)\b", lower):
        event = create_event(config, "user_created", "medium", normalized, source)

    elif re.search(r"\b(apt|apt-get|dpkg)\b.*\b(install|installed|status installed)\b|\binstalled\b.*\bpackage\b", lower):
        event = create_event(config, "package_installed", "low", normalized, source)

    elif re.search(r"systemd.*\bstarted\b|\bstarted\b.*\.service", lower):
        event = create_event(config, "service_started", "low", normalized, source)

    elif re.search(r"systemd.*\bstopped\b|\bstopped\b.*\.service", lower):
        event = create_event(config, "service_stopped", "high", normalized, source)

    else:
        event = create_event(config, "service_or_custom_log", "info", normalized, source)

    event["raw_log"] = normalized
    return event
