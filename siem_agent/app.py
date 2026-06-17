from __future__ import annotations

import platform
import queue
import threading
import time
from typing import Any

from siem_agent.config import load_config
from siem_agent.file_watcher import watch_directory
from siem_agent.log_watcher import tail_file
from siem_agent.sender import sender_worker
from siem_agent.service_watcher import watch_service


def main() -> None:
    config = load_config()
    events: queue.Queue[dict[str, Any]] = queue.Queue()
    threads: list[threading.Thread] = []

    print(f"agent id: {config.agent_id}")
    print(f"server url: {config.server_url}")
    print(f"platform: {platform.platform()}")

    threads.append(threading.Thread(target=sender_worker, args=(config, events), daemon=True))

    log_files = list(config.log_files)
    if config.custom_log:
        log_files.append(config.custom_log)

    for log_file in log_files:
        threads.append(threading.Thread(target=tail_file, args=(log_file, config, events), daemon=True))
    for directory in config.watch_dirs:
        threads.append(threading.Thread(target=watch_directory, args=(directory, config, events), daemon=True))
    for service in config.services:
        threads.append(threading.Thread(target=watch_service, args=(service, config, events), daemon=True))

    for thread in threads:
        thread.start()

    while True:
        time.sleep(60)
