# mitigation/actions.py
import psutil
import shutil
import os
import time

class MitigationEngine:
    def __init__(self, quarantine_dir='quarantine'):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def kill_process(self, pid):
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            gone, alive = psutil.wait_procs([p], timeout=3)
            if alive:
                for proc in alive:
                    proc.kill()
            return {'status':'ok', 'action':'kill', 'pid': pid}
        except Exception as e:
            return {'status':'error', 'error': str(e)}

    def quarantine_file(self, path):
        try:
            if not path or not os.path.exists(path):
                return {'status':'error', 'error':'file not found'}
            base = os.path.basename(path)
            dest = os.path.join(self.quarantine_dir, f"{int(time.time())}_{base}")
            shutil.copy2(path, dest)
            return {'status':'ok', 'action':'quarantine', 'src': path, 'dest': dest}
        except Exception as e:
            return {'status':'error', 'error': str(e)}

    def apply(self, action, **kwargs):
        if action=='kill_process':
            return self.kill_process(kwargs.get('pid'))
        if action=='quarantine_file':
            return self.quarantine_file(kwargs.get('path'))
        return {'status':'error','error':'unknown action'}
