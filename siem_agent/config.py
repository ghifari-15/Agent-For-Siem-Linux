from __future__ import annotations

import argparse
import getpass
import os
import socket
from dataclasses import dataclass


DEFAULT_SERVER_URL = "http://192.168.8.220:5000/api/events"
DEFAULT_LOG_FILES = ["/var/log/auth.log", "/var/log/syslog"]
DEFAULT_WATCH_DIRS = ["/tmp/siem-watch"]
DEFAULT_SERVICES = ["ssh"]


@dataclass
class AgentConfig:
    server_url: str
    log_files: list[str]
    watch_dirs: list[str]
    services: list[str]
    interval: int
    hostname: str
    agent_id: str
    custom_log: str | None


def parse_csv(value: str | None, default: list[str]) -> list[str]:
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


def load_config() -> AgentConfig:
    parser = argparse.ArgumentParser(description="Python SIEM endpoint agent")
    parser.add_argument("--server-url", default=os.getenv("SIEM_SERVER_URL", DEFAULT_SERVER_URL))
    parser.add_argument("--log-files", default=os.getenv("SIEM_LOG_FILES", ",".join(DEFAULT_LOG_FILES)))
    parser.add_argument("--watch-dirs", default=os.getenv("SIEM_WATCH_DIRS", ",".join(DEFAULT_WATCH_DIRS)))
    parser.add_argument("--services", default=os.getenv("SIEM_SERVICES", ",".join(DEFAULT_SERVICES)))
    parser.add_argument("--custom-log", default=os.getenv("SIEM_CUSTOM_LOG"))
    parser.add_argument("--interval", type=int, default=int(os.getenv("SIEM_INTERVAL", "5")))
    args = parser.parse_args()

    hostname = socket.gethostname()
    return AgentConfig(
        server_url=args.server_url,
        log_files=parse_csv(args.log_files, DEFAULT_LOG_FILES),
        watch_dirs=parse_csv(args.watch_dirs, DEFAULT_WATCH_DIRS),
        services=parse_csv(args.services, DEFAULT_SERVICES),
        interval=max(args.interval, 1),
        hostname=hostname,
        agent_id=f"{hostname}-{getpass.getuser()}",
        custom_log=args.custom_log,
    )
