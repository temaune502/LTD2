"""
Progress rendering — rich live progress bars.

Usage::

    tracker = ProgressTracker(total_files=3, peer_name="laptop-01")
    tracker.start()

    with tracker.file("video.mp4", size=104857600) as fp:
        for chunk in ...:
            fp.advance(len(chunk))

    tracker.stop()
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Generator

from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Column


class FileProgress:
    """Context returned by ProgressTracker.file() — advance bytes as you go."""

    def __init__(self, progress: Progress, task_id: TaskID, size: int) -> None:
        self._progress = progress
        self._task_id = task_id
        self._size = size

    def advance(self, n: int) -> None:
        """Advance the progress bar by *n* raw (uncompressed) bytes."""
        self._progress.advance(self._task_id, n)

    def finish(self) -> None:
        self._progress.update(self._task_id, completed=self._size)


class ProgressTracker:
    """Live multi-file progress display using Rich."""

    def __init__(self, total_files: int, peer_name: str, direction: str = "→") -> None:
        self.total_files = total_files
        self.peer_name = peer_name
        self.direction = direction
        self._done = 0
        self._progress = Progress(
            SpinnerColumn(),
            TextColumn(
                f"[bold cyan]{direction}[/] [bold]{peer_name}[/]"
                " ([progress.percentage]{task.percentage:>5.1f}%)"
            ),
            BarColumn(bar_width=None),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            TextColumn("[dim]{task.fields[filename]}"),
            console=Console(stderr=True),
            expand=True,
        )

    def start(self) -> None:
        self._progress.start()

    def stop(self) -> None:
        self._progress.stop()

    @contextmanager
    def file(self, filename: str, size: int) -> Generator[FileProgress, None, None]:
        """Context manager for a single file transfer progress."""
        task_id = self._progress.add_task(
            "transfer",
            total=max(size, 1),
            filename=filename,
        )
        fp = FileProgress(self._progress, task_id, size)
        try:
            yield fp
        finally:
            fp.finish()
            self._done += 1
            self._progress.remove_task(task_id)


class NullProgress:
    """Drop-in no-op replacement when --quiet / --no-progress is set."""

    def start(self) -> None: ...
    def stop(self) -> None: ...

    @contextmanager
    def file(self, filename: str, size: int) -> Generator[FileProgress, None, None]:
        class _NopFP:
            def advance(self, n: int) -> None: ...
            def finish(self) -> None: ...
        yield _NopFP()  # type: ignore[misc]
