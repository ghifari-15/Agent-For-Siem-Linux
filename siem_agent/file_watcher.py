from __future__ import annotations

import hashlib
import queue
import time
from pathlib import Path
from typing import Any

from siem_agent.config import AgentConfig
from siem_agent.events import create_event


def fingerprint_file(path: Path) -> str:
    stat = path.stat()
    digest = hashlib.sha256()
    digest.update(str(stat.st_size).encode())
    digest.update(str(stat.st_mtime_ns).encode())
    if path.is_file() and stat.st_size <= 1024 * 1024:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def snapshot_directory(directory: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    if not directory.exists():
        directory.mkdir(parents=True, exist_ok=True)
    for path in directory.rglob("*"):
        if path.is_file():
            try:
                snapshot[str(path)] = fingerprint_file(path)
            except OSError:
                continue
    return snapshot


def watch_directory(directory: str, config: AgentConfig, events: queue.Queue[dict[str, Any]]) -> None:
    root = Path(directory)
    previous = snapshot_directory(root)
    print(f"watching directory: {root}")

    while True:
        time.sleep(config.interval)
        current = snapshot_directory(root)

        for path in sorted(set(current) - set(previous)):
            events.put(create_event(config, "file_created", "low", f"File created: {path}", str(root)))
        for path in sorted(set(previous) - set(current)):
            events.put(create_event(config, "file_deleted", "medium", f"File deleted: {path}", str(root)))
        for path in sorted(set(current) & set(previous)):
            if current[path] != previous[path]:
                events.put(create_event(config, "file_modified", "low", f"File modified: {path}", str(root)))

        previous = current
