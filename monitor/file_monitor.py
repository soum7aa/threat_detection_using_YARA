# monitor/file_monitor.py
import os, time, threading, queue, sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DEFAULT_DIRS = []

def default_watch_paths():
    paths = set()
    home = os.path.expanduser("~")
    # Cross-platform sensible defaults
    for p in ["Downloads", "Desktop", "Documents"]:
        full = os.path.join(home, p)
        if os.path.isdir(full):
            paths.add(full)
    # temp dirs
    for p in ["/tmp", "/var/tmp"]:
        if os.path.isdir(p):
            paths.add(p)
    # Windows temp
    win_tmp = os.environ.get("TEMP") or os.environ.get("TMP")
    if win_tmp and os.path.isdir(win_tmp):
        paths.add(win_tmp)
    return sorted(paths)

class _Handler(FileSystemEventHandler):
    def __init__(self, out_queue):
        self.out_queue = out_queue

    def on_created(self, event):
        if not event.is_directory:
            self._emit("file_created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._emit("file_modified", event.src_path)

    def _emit(self, evtype, path):
        ev = {
            "type": "file_event",
            "subtype": evtype,
            "path": path,
            "timestamp": time.time()
        }
        self.out_queue.put(ev)

class FileMonitor(threading.Thread):
    def __init__(self, out_queue: queue.Queue, paths=None):
        super().__init__(daemon=True)
        self.out_queue = out_queue
        self.paths = paths or default_watch_paths()
        self._stop = threading.Event()
        self._observer = Observer()
        self._lock = threading.Lock()

    def run(self):
        handler = _Handler(self.out_queue)
        with self._lock:
            for p in self.paths:
                try:
                    self._observer.schedule(handler, p, recursive=True)
                except Exception:
                    pass
            self._observer.start()
        try:
            while not self._stop.is_set():
                time.sleep(0.5)
        finally:
            self._observer.stop()
            self._observer.join()

    def stop(self):
        self._stop.set()

    def get_paths(self):
        with self._lock:
            return list(self.paths)

    def reconfigure_paths(self, new_paths):
        """Replace watched paths at runtime. Safe to call while running."""
        if not isinstance(new_paths, (list, tuple)):
            return False
        new_paths = [p for p in new_paths if isinstance(p, str) and os.path.isdir(p)]
        with self._lock:
            # stop current scheduling but keep thread running
            try:
                self._observer.unschedule_all()
            except Exception:
                pass
            self.paths = new_paths
            handler = _Handler(self.out_queue)
            for p in self.paths:
                try:
                    self._observer.schedule(handler, p, recursive=True)
                except Exception:
                    continue
        return True
