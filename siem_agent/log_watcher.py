from __future__ import annotations

import queue
import time
from pathlib import Path
from typing import Any

from siem_agent.classifier import classify_log_line
from siem_agent.config import AgentConfig


def tail_file(path: str, config: AgentConfig, events: queue.Queue[dict[str, Any]]) -> None:
    file_path = Path(path)
    while not file_path.exists():
        print(f"waiting for log file: {path}")
        time.sleep(config.interval)

    with file_path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        while True:
            line = handle.readline()
            if line:
                events.put(classify_log_line(config, path, line))
            else:
                time.sleep(1)
