# monitor/process_monitor.py
import psutil
import time
import threading
import queue

class ProcessMonitor(threading.Thread):
    def __init__(self, out_queue: queue.Queue, interval=0.5):
        super().__init__(daemon=True)
        self.out_queue = out_queue
        self.interval = interval
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            for p in psutil.process_iter(['pid','name','cmdline','cpu_percent','memory_percent','create_time','username','exe']):
                try:
                    info = p.info
                    event = {
                        'type': 'process_sample',
                        'pid': info.get('pid'),
                        'name': info.get('name'),
                        'cmdline': ' '.join(info.get('cmdline') or []),
                        'cpu_percent': p.cpu_percent(interval=None),
                        'mem_percent': info.get('memory_percent'),
                        'exe': info.get('exe'),
                        'timestamp': time.time()
                    }
                    self.out_queue.put(event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()
