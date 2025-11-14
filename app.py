# app.py
from flask import Flask, Response, request, jsonify, stream_with_context, send_from_directory
import queue, threading, json, time, os, hashlib
from pathlib import Path
from monitor.process_monitor import ProcessMonitor
from monitor.network_monitor import NetworkMonitor
from monitor.file_monitor import FileMonitor, default_watch_paths
from mitigation.actions import MitigationEngine
from detection.anomaly_model import SimpleAnomalyModel
from detection.signature import YaraScanner
import numpy as np
from utils.file_scanner import FileScanner

# simple in-memory incident store
INCIDENTS = []
MAX_INCIDENTS = 500

# background scan state
SCAN_STATE = {
    'running': False,
    'started_at': None,
    'paths': [],
    'settings': {'max_files': 5000, 'max_size_bytes': 50*1024*1024, 'include_exts': None},
    'total_listed': 0,
    'scanned': 0,
    'hits_count': 0,
    'hits_sample': [],
    'message': ''
}
_SCAN_CANCEL = threading.Event()

app = Flask(__name__, static_folder='static')

# central event queue
event_q = queue.Queue()

# Config persistence
CONFIG_PATH = Path(__file__).parent / 'config.json'
UPLOAD_DIR = Path(__file__).parent / 'uploads'


def ensure_upload_dir():
    try:
        UPLOAD_DIR.mkdir(exist_ok=True)
    except Exception:
        pass

def _load_watch_paths():
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
                cfg = json.load(fh)
                paths = cfg.get('watch_paths') or []
                # filter to existing directories only at load
                return [p for p in paths if os.path.isdir(p)]
    except Exception:
        pass
    return default_watch_paths()

def _save_watch_paths(paths):
    try:
        # merge with existing
        cfg = {}
        if CONFIG_PATH.exists():
            try:
                with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
                    cfg = json.load(fh) or {}
            except Exception:
                cfg = {}
        cfg['watch_paths'] = paths
        with open(CONFIG_PATH, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh, indent=2)
        return True
    except Exception:
        return False

def _check_path_access(p):
    ok = False
    err = None
    try:
        if not os.path.isdir(p):
            err = 'not_a_directory'
        else:
            # attempt to list to verify permission
            try:
                os.listdir(p)
                ok = True
            except PermissionError:
                err = 'permission_denied'
            except Exception as e:
                err = str(e)
    except Exception as e:
        err = str(e)
    return ok, err

# Start monitors
proc_monitor = ProcessMonitor(event_q, interval=0.2)  # Faster process monitoring
net_monitor = NetworkMonitor(event_q, interval=0.5)   # Faster network monitoring
file_mon = FileMonitor(event_q, paths=_load_watch_paths())
proc_monitor.start()
net_monitor.start()
file_mon.start()

# detectors & mitigator
mitigator = MitigationEngine()
detector = SimpleAnomalyModel()
scanner = YaraScanner()  # will load yara rules if present
file_scanner = FileScanner(scanner)

# optional: train detector on short baseline (very small fallback)
try:
    bs = []
    for _ in range(10):
        ev = event_q.get(timeout=1)
        if ev.get('type')=='process_sample':
            bs.append([ev.get('cpu_percent') or 0.0, ev.get('mem_percent') or 0.0])
    if len(bs) >= 5:
        X = np.array(bs)
        detector.train(X)
except Exception:
    pass


@app.route('/')
@app.route('/<path:path>')
def serve_react(path=''):
    """Serve React frontend (index.html for all routes except /api)."""
    if path.startswith('api/'):
        # Let API routes handle themselves
        return {'error': 'API route not found'}, 404
    # Serve React app for all other routes (SPA)
    return send_from_directory('static', 'index.html')


@app.route('/api/stream')
def stream():
    def gen():
        while True:
            try:
                event = event_q.get(timeout=5)
            except queue.Empty:
                yield ':\n\n'  # keepalive comment for SSE
                continue

            out = { 'event': event }

            # if process sample, run detectors
            if event.get('type')=='process_sample':
                features = np.array([event['cpu_percent'] or 0.0, event['mem_percent'] or 0.0])
                label = detector.predict(features)
                score = detector.score(features)
                out['detection'] = { 'label': int(label), 'score': float(score) }

            # run yara on executable path if exists
            exe = event.get('exe')
            if exe:
                yara_res = scanner.scan_file(exe)
                if yara_res:
                    out['yara'] = yara_res

            # File events → YARA scan
            if event.get('type')=='file_event':
                y = scanner.scan_file(event.get('path'))
                if y:
                    out['yara'] = y
                    out['mitre'] = out.get('mitre') or []
                suspicious = bool(out.get('yara'))
                if suspicious:
                    incident = {
                        'ts': time.time(),
                        'event': event,
                        'detection': out.get('detection'),
                        'yara': out.get('yara'),
                        'mitre': out.get('mitre')
                    }
                    INCIDENTS.append(incident)
                    if len(INCIDENTS) > MAX_INCIDENTS:
                        del INCIDENTS[:len(INCIDENTS)-MAX_INCIDENTS]

            # Process anomalies → store incident
            if event.get('type')=='process_sample' and out.get('detection') and out['detection'].get('label') == -1:
                incident = {
                    'ts': time.time(),
                    'event': event,
                    'detection': out.get('detection'),
                    'yara': out.get('yara'),
                    'mitre': out.get('mitre')
                }
                INCIDENTS.append(incident)
                if len(INCIDENTS) > MAX_INCIDENTS:
                    del INCIDENTS[:len(INCIDENTS)-MAX_INCIDENTS]

            yield f"data: {json.dumps(out, default=str)}\n\n"

    return Response(stream_with_context(gen()), mimetype='text/event-stream')


@app.route('/api/mitigate', methods=['POST'])
def api_mitigate():
    data = request.json or {}
    action = data.get('action')
    if action == 'kill_process':
        pid = data.get('pid')
        res = mitigator.kill_process(pid)
        return jsonify(res)
    if action == 'quarantine_file':
        path = data.get('path')
        res = mitigator.quarantine_file(path)
        return jsonify(res)
    return jsonify({'status':'error','error':'unknown action'}), 400


@app.route('/api/yara/reload', methods=['POST'])
def api_yara_reload():
    ok = scanner.reload()
    return jsonify({'status': 'ok' if ok else 'no_rules'})


@app.route('/api/incidents', methods=['GET'])
def api_incidents():
    # return newest first
    return jsonify(list(reversed(INCIDENTS)))


@app.route('/api/yara/status', methods=['GET'])
def api_yara_status():
    has_engine = scanner.rules is not None
    fallback_cnt = len(getattr(scanner, 'fallback_strings', []) or [])
    return jsonify({
        'engine': 'yara' if has_engine else 'fallback' if fallback_cnt else 'none',
        'fallback_strings': fallback_cnt
    })


@app.route('/api/paths', methods=['GET', 'POST'])
def api_paths():
    if request.method == 'GET':
        paths = file_mon.get_paths()
        statuses = []
        for p in paths:
            ok, err = _check_path_access(p)
            statuses.append({'path': p, 'accessible': bool(ok), 'error': err})
        return jsonify({'paths': paths, 'statuses': statuses})
    data = request.json or {}
    paths = data.get('paths') or []
    ok = file_mon.reconfigure_paths(paths)
    saved = False
    if ok:
        saved = _save_watch_paths(file_mon.get_paths())
    out_paths = file_mon.get_paths()
    statuses = []
    for p in out_paths:
        a, e = _check_path_access(p)
        statuses.append({'path': p, 'accessible': bool(a), 'error': e})
    return jsonify({'status': 'ok' if ok else 'error', 'saved': bool(saved), 'paths': out_paths, 'statuses': statuses})


@app.route('/api/scan_paths', methods=['POST'])
def api_scan_paths():
    """Recursively scan watched paths. Returns summary counts and sample hits.
    Intended as an on-demand operation; may take time on large trees.
    """
    paths = file_mon.get_paths()
    max_files = int((request.json or {}).get('max_files') or 5000)
    max_size_bytes = int((request.json or {}).get('max_size_bytes') or (50 * 1024 * 1024))
    include_exts = (request.json or {}).get('include_exts') or None  # e.g., ['.exe','.dll','.ps1']
    hits = []
    total = 0
    scanned = 0
    for root in paths:
        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # prevent deep trees from blocking forever
                for fn in filenames:
                    total += 1
                    if scanned >= max_files:
                        break
                    fp = os.path.join(dirpath, fn)
                    try:
                        if include_exts:
                            _, ext = os.path.splitext(fn)
                            if ext.lower() not in [e.lower() for e in include_exts]:
                                continue
                        st = os.stat(fp)
                        if st.st_size > max_size_bytes:
                            continue
                        scanned += 1
                        y = scanner.scan_file(fp)
                        if y:
                            hits.append({'path': fp, 'yara': y[:10]})
                            # also record incident (file evidence)
                            INCIDENTS.append({'ts': time.time(), 'event': {'type':'file_event','subtype':'scan','path': fp, 'timestamp': time.time()}, 'yara': y})
                            if len(INCIDENTS) > MAX_INCIDENTS:
                                del INCIDENTS[:len(INCIDENTS)-MAX_INCIDENTS]
                    except Exception:
                        continue
                if scanned >= max_files:
                    break
        except Exception:
            continue
        if scanned >= max_files:
            break
    return jsonify({'status':'ok','paths': paths,'total_listed': total,'scanned': scanned,'hits_count': len(hits),'hits': hits[:50]})


def _background_scan(paths, settings):
    SCAN_STATE.update({
        'running': True,
        'started_at': time.time(),
        'paths': list(paths),
        'settings': settings,
        'total_listed': 0,
        'scanned': 0,
        'hits_count': 0,
        'hits_sample': [],
        'message': ''
    })
    _SCAN_CANCEL.clear()
    max_files = int(settings.get('max_files') or 5000)
    max_size_bytes = int(settings.get('max_size_bytes') or (50*1024*1024))
    include_exts = settings.get('include_exts')
    if include_exts:
        include_exts = [e.lower() for e in include_exts]
    try:
        for root in paths:
            if _SCAN_CANCEL.is_set():
                break
            for dirpath, dirnames, filenames in os.walk(root):
                if _SCAN_CANCEL.is_set():
                    break
                for fn in filenames:
                    if _SCAN_CANCEL.is_set():
                        break
                    SCAN_STATE['total_listed'] += 1
                    if SCAN_STATE['scanned'] >= max_files:
                        break
                    fp = os.path.join(dirpath, fn)
                    try:
                        if include_exts:
                            _, ext = os.path.splitext(fn)
                            if ext.lower() not in include_exts:
                                continue
                        st = os.stat(fp)
                        if st.st_size > max_size_bytes:
                            continue
                        SCAN_STATE['scanned'] += 1
                        y = scanner.scan_file(fp)
                        if y:
                            SCAN_STATE['hits_count'] += 1
                            sample_item = {'path': fp, 'yara': y[:10]}
                            if len(SCAN_STATE['hits_sample']) < 50:
                                SCAN_STATE['hits_sample'].append(sample_item)
                            INCIDENTS.append({'ts': time.time(), 'event': {'type':'file_event','subtype':'scan','path': fp, 'timestamp': time.time()}, 'yara': y})
                            if len(INCIDENTS) > MAX_INCIDENTS:
                                del INCIDENTS[:len(INCIDENTS)-MAX_INCIDENTS]
                    except Exception:
                        continue
                if SCAN_STATE['scanned'] >= max_files:
                    break
    finally:
        SCAN_STATE['running'] = False


@app.route('/api/scan_paths/start', methods=['POST'])
def api_scan_paths_start():
    if SCAN_STATE.get('running'):
        return jsonify({'status':'busy', 'state': SCAN_STATE})
    paths = file_mon.get_paths()
    body = request.json or {}
    settings = {
        'max_files': int(body.get('max_files') or 5000),
        'max_size_bytes': int(body.get('max_size_bytes') or (50*1024*1024)),
        'include_exts': body.get('include_exts') or None
    }
    t = threading.Thread(target=_background_scan, args=(paths, settings), daemon=True)
    t.start()
    return jsonify({'status':'started', 'state': SCAN_STATE})


@app.route('/api/scan_paths/status', methods=['GET'])
def api_scan_paths_status():
    return jsonify(SCAN_STATE)


@app.route('/api/scan_paths/cancel', methods=['POST'])
def api_scan_paths_cancel():
    if SCAN_STATE.get('running'):
        _SCAN_CANCEL.set()
        return jsonify({'status':'cancelling'})
    return jsonify({'status':'idle'})


@app.route('/api/scan_settings', methods=['GET', 'POST'])
def api_scan_settings():
    # store/retrieve scan settings in config.json
    cfg = {}
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
                cfg = json.load(fh) or {}
        except Exception:
            cfg = {}
    if request.method == 'GET':
        return jsonify(cfg.get('scan_settings') or {'max_files': 5000, 'max_size_bytes': 50*1024*1024, 'include_exts': None})
    body = request.json or {}
    cfg['scan_settings'] = {
        'max_files': int(body.get('max_files') or 5000),
        'max_size_bytes': int(body.get('max_size_bytes') or (50*1024*1024)),
        'include_exts': body.get('include_exts') or None
    }
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as fh:
            json.dump(cfg, fh, indent=2)
        return jsonify({'status':'ok'})
    except Exception as e:
        return jsonify({'status':'error','error': str(e)}), 500


@app.route('/api/upload_scan', methods=['POST'])
def api_upload_scan():
    ensure_upload_dir()
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'status':'error','error':'no_file'}), 400
    name = f.filename
    safe_name = name.replace('..','_').replace('/','_').replace('\\','_')
    dest = UPLOAD_DIR / safe_name
    try:
        f.save(str(dest))
    except Exception as e:
        return jsonify({'status':'error','error': str(e)}), 500

    sha256_hash = None
    try:
        h = hashlib.sha256()
        with open(dest, 'rb') as fh:
            for chunk in iter(lambda: fh.read(65536), b''):
                if not chunk:
                    break
                h.update(chunk)
        sha256_hash = h.hexdigest()
    except Exception:
        sha256_hash = None

    # Modular scanning pipeline handles type classification and analysis
    scan_result = file_scanner.scan(str(dest))
    result_dict = scan_result.to_dict()

    response_payload = {
        'status': 'ok',
        'file': {
            'name': name,
            'size': result_dict['size'],
            'type': result_dict['file_type'],
            'mime_type': result_dict['mime_type'],
            'sha256': sha256_hash
        },
        'yara': result_dict['yara_hits'],
        'heuristics': result_dict['heuristics'],
        'analysis': result_dict['analysis_notes'],
        'scan_steps': result_dict['scan_steps'],
        'verdict': result_dict['verdict']
    }

    if result_dict.get('metadata'):
        response_payload['metadata'] = result_dict['metadata']
    if result_dict.get('inner_hits'):
        response_payload['inner_hits'] = result_dict['inner_hits']

    if result_dict['verdict'] == 'suspicious':
        INCIDENTS.append({
            'ts': time.time(),
            'event': {'type':'file_event','subtype':'upload_scan','path': str(dest), 'timestamp': time.time()},
            'yara': result_dict['yara_hits'],
            'heuristics': result_dict['heuristics'],
            'scan_steps': result_dict['scan_steps'],
            'metadata': result_dict.get('metadata'),
            'inner_hits': result_dict.get('inner_hits'),
            'verdict': result_dict['verdict']
        })
        if len(INCIDENTS) > MAX_INCIDENTS:
            del INCIDENTS[:len(INCIDENTS)-MAX_INCIDENTS]

    return jsonify(response_payload)

@app.route('/api/test_url', methods=['POST'])
def api_test_url():
    """Enhanced URL safety testing endpoint with advanced phishing + defacement + malware hosting heuristics.

    Note: This uses lightweight heuristics and optional live page fetch. It is educational and not a replacement for
    enterprise threat intel feeds.
    """
    import re
    import urllib.parse
    from urllib.parse import urlparse
    from difflib import SequenceMatcher
    
    data = request.json or {}
    url = data.get('url', '').strip()
    fetch = bool(data.get('fetch', True))
    
    if not url:
        return jsonify({'status': 'error', 'error': 'No URL provided'}), 400
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = (parsed.path or '/')
        query = (parsed.query or '')
        
        # Initialize result
        result = {
            'url': url,
            'domain': domain,
            'path': path,
            'query': query,
            'safety_rating': 'safe',
            'is_safe': True,
            'primary_category': 'benign',  # phishing | defacement | malware | scam | benign | unknown
            'categories': [],
            'threats': [],
            'warnings': [],
            'details': []
        }
        
        # Known malicious domains (expanded list)
        malicious_domains = {
            'malware.com', 'virus.net', 'trojan.org', 'phishing.site',
            'suspicious-domain.com', 'malicious-ip.net', 'botnet.cc',
            'c2-server.com', 'malware-distribution.net', 'fake-bank.com',
            'phishing-paypal.com', 'malicious-download.net',
            'test-malware.com', 'demo-phishing.net', 'fake-virus.org',
            'malicious-test.com', 'suspicious-demo.net',
            'phishing-bank.com', 'fake-paypal.com', 'malicious-command-center.com',
            'suspicious-proxy.net', 'malware-distribution.net',
            # Real-world phishing domains (educational examples)
            'br-icloud.com.br', 'apple-security.com', 'microsoft-update.net',
            'paypal-security.org', 'amazon-support.net', 'google-security.com',
            'facebook-login.net', 'twitter-verify.org', 'instagram-help.com'
        }
        
        # Check against known malicious domains
        if domain in malicious_domains:
            result['safety_rating'] = 'danger'
            result['is_safe'] = False
            result['threats'].append('Known malicious/phishing domain')
            result['details'].append(f'Domain "{domain}" is flagged as malicious/phishing')
        
        # Brand impersonation detection
        legitimate_brands = {
            'apple': ['icloud', 'apple', 'itunes', 'appstore'],
            'microsoft': ['microsoft', 'office', 'outlook', 'azure', 'windows'],
            'google': ['google', 'gmail', 'youtube', 'chrome', 'android'],
            'amazon': ['amazon', 'aws', 'prime'],
            'paypal': ['paypal'],
            'facebook': ['facebook', 'meta'],
            'twitter': ['twitter', 'x'],
            'instagram': ['instagram'],
            'netflix': ['netflix'],
            'spotify': ['spotify'],
            'uber': ['uber'],
            'airbnb': ['airbnb']
        }
        
        # Extract domain parts for analysis
        domain_parts = domain.split('.')
        main_domain = domain_parts[0] if domain_parts else ''
        
        # Check for brand impersonation
        for brand, keywords in legitimate_brands.items():
            for keyword in keywords:
                if keyword in main_domain.lower():
                    # Check if it's suspiciously similar to legitimate brand domains
                    similarity_score = SequenceMatcher(None, main_domain.lower(), keyword).ratio()
                    
                    # If similarity is high but not exact, it might be impersonation
                    if similarity_score > 0.7 and main_domain.lower() != keyword:
                        if result['safety_rating'] == 'safe':
                            result['safety_rating'] = 'warning'
                        result['warnings'].append(f'Potential {brand} impersonation')
                        result['details'].append(f'Domain "{main_domain}" suspiciously similar to "{keyword}" (similarity: {similarity_score:.2f})')
                    
                    # Check for common phishing patterns
                    phishing_patterns = [
                        f'{keyword}-security', f'{keyword}-support', f'{keyword}-help',
                        f'{keyword}-update', f'{keyword}-verify', f'{keyword}-login',
                        f'{keyword}-account', f'{keyword}-billing', f'{keyword}-payment',
                        f'secure-{keyword}', f'login-{keyword}', f'verify-{keyword}',
                        f'br-{keyword}', f'us-{keyword}', f'uk-{keyword}', f'ca-{keyword}'
                    ]
                    
                    for pattern in phishing_patterns:
                        if pattern in main_domain.lower():
                            result['safety_rating'] = 'danger'
                            result['is_safe'] = False
                            result['threats'].append(f'Phishing pattern detected: {pattern}')
                            result['details'].append(f'Domain uses common phishing pattern "{pattern}" to impersonate {brand}')
                            break
        
        # Check for suspicious patterns in domain
        suspicious_patterns = [
            'malware', 'virus', 'trojan', 'phishing', 'fake', 'scam',
            'botnet', 'c2', 'command-and-control', 'exploit', 'payload',
            'hack', 'crack', 'steal', 'fraud', 'suspicious', 'malicious',
            'security', 'support', 'help', 'update', 'verify', 'login',
            'account', 'billing', 'payment', 'secure', 'official'
        ]
        
        for pattern in suspicious_patterns:
            if pattern in domain:
                if result['safety_rating'] == 'safe':
                    result['safety_rating'] = 'warning'
                result['warnings'].append(f'Suspicious keyword: "{pattern}"')
                result['details'].append(f'Domain contains suspicious keyword "{pattern}"')
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.onion', '.bit', '.tk', '.ml', '.ga', '.cf', '.ru', '.cn']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                if result['safety_rating'] == 'safe':
                    result['safety_rating'] = 'warning'
                result['warnings'].append(f'Suspicious TLD: {tld}')
                result['details'].append(f'Domain uses suspicious top-level domain {tld}')
        
        # Check for IP addresses (often suspicious)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ip_pattern, domain):
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('Direct IP address')
            result['details'].append('URL uses direct IP address instead of domain name')
        
        # Malware hosting / scam download patterns (URL only)
        download_indicators = ['download', 'setup', 'installer', 'update', 'patch', 'crack', 'keygen']
        ext_indicators = ['.exe', '.apk', '.msi', '.bat', '.ps1', '.js', '.scr']
        if any(k in path.lower() for k in download_indicators) or any(path.lower().endswith(ext) for ext in ext_indicators):
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('Executable download pattern')
            result['details'].append('URL path resembles software download/installer')

        # Check for suspicious URL structure
        if len(domain) > 50:  # Very long domains are often suspicious
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('Unusually long domain name')
            result['details'].append('Domain name is unusually long, which can indicate suspicious activity')
        
        # Check for multiple subdomains (potential evasion)
        subdomain_count = len(domain.split('.')) - 2  # Subtract domain and TLD
        if subdomain_count > 3:
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('Multiple subdomains')
            result['details'].append(f'Domain has {subdomain_count} subdomains, which can indicate evasion attempts')
        
        # Check for suspicious characters
        suspicious_chars = ['-', '_', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
        char_count = sum(1 for char in domain if char in suspicious_chars)
        if char_count > len(domain) * 0.5:  # More than 50% suspicious characters
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('High ratio of suspicious characters')
            result['details'].append('Domain contains many numbers and special characters')
        
        # Check for typosquatting patterns
        typosquatting_patterns = [
            r'[a-z]+[0-9]+[a-z]+',  # Mixed letters and numbers
            r'[0-9]+[a-z]+[0-9]+',  # Numbers around letters
            r'[a-z]+-[a-z]+-[a-z]+',  # Multiple hyphens
        ]
        
        for pattern in typosquatting_patterns:
            if re.search(pattern, main_domain):
                if result['safety_rating'] == 'safe':
                    result['safety_rating'] = 'warning'
                result['warnings'].append('Typosquatting pattern detected')
                result['details'].append(f'Domain uses typosquatting pattern: {pattern}')
        
        # Check for recently registered domains (simulated)
        # In a real implementation, you'd check WHOIS data
        if any(char.isdigit() for char in main_domain) and len(main_domain) > 10:
            if result['safety_rating'] == 'safe':
                result['safety_rating'] = 'warning'
            result['warnings'].append('Potentially recently registered domain')
            result['details'].append('Domain contains numbers and is long, suggesting recent registration')
        
        # Optional live fetch for defacement and content-based checks
        fetched = None
        if fetch:
            try:
                # Lightweight fetch with strict limits
                import requests
                headers = {'User-Agent': 'ThreatMain-URL-Analyzer/1.0'}
                resp = requests.get(url, headers=headers, timeout=5, allow_redirects=True, stream=True)
                # Read up to 200 KB
                content = resp.raw.read(200_000, decode_content=True) if hasattr(resp, 'raw') else resp.content[:200_000]
                ct = resp.headers.get('Content-Type','').lower()
                fetched = {
                    'status_code': int(resp.status_code),
                    'content_type': ct,
                    'server': resp.headers.get('Server'),
                    'content_sample_len': len(content or b''),
                }

                # Basic HTML extraction
                text = ''
                if isinstance(content, bytes):
                    try:
                        text = content.decode('utf-8', 'ignore')
                    except Exception:
                        text = ''
                else:
                    text = str(content or '')

                # Defacement heuristics
                deface_terms = [
                    'hacked by', 'defaced by', 'owned by', 'pwned by', 'defacement',
                    'we are legion', 'anonymous', 'free palestine', 'sqlmap', 'rooted by'
                ]
                if 'text/html' in ct or '<html' in text.lower():
                    low = text.lower()
                    if any(term in low for term in deface_terms):
                        result['safety_rating'] = 'danger'
                        result['is_safe'] = False
                        result['primary_category'] = 'defacement'
                        result['categories'].append('defacement')
                        result['threats'].append('Defacement indicators on page')
                        result['details'].append('Page content contains defacement phrases')

                    # Extremely minimal content with single banner or oversized heading
                    if len(low) < 2000 and (low.count('<h1') >= 1 or 'hacked' in low):
                        if result['primary_category'] == 'benign':
                            result['primary_category'] = 'defacement'
                            result['categories'].append('defacement')
                            if result['safety_rating'] != 'danger':
                                result['safety_rating'] = 'warning'
                        result['warnings'].append('Minimal page content typical of defacements')

                # Content-based malware lure checks
                lure_terms = ['download crack', 'free keygen', 'serial key', 'no survey', 'latest hack']
                if any(t in (text.lower() if text else '') for t in lure_terms):
                    result['safety_rating'] = 'danger'
                    result['is_safe'] = False
                    result['primary_category'] = 'malware'
                    if 'malware' not in result['categories']:
                        result['categories'].append('malware')
                    result['threats'].append('Malware lure content')

                result['fetched'] = fetched
            except Exception as e:
                result['warnings'].append('Live fetch failed')
                result['details'].append(f'Fetch error: {str(e)}')

        # Derive primary category from threats if not set by fetch
        if result['primary_category'] == 'benign':
            if any('Phishing' in t or 'phishing' in t for t in result['threats']) or any('impersonation' in w for w in result['warnings']):
                result['primary_category'] = 'phishing'
                if 'phishing' not in result['categories']:
                    result['categories'].append('phishing')
            elif any('Executable download' in w for w in result['warnings']):
                result['primary_category'] = 'malware'
                if 'malware' not in result['categories']:
                    result['categories'].append('malware')

        # Add general safety information
        if result['safety_rating'] == 'safe':
            result['details'].append('No obvious threats detected')
            result['details'].append('Domain appears to be legitimate')
        elif result['safety_rating'] == 'warning':
            result['details'].append('Some suspicious patterns detected - proceed with caution')
        else:  # danger
            result['details'].append('Multiple threats detected - avoid this URL')
        
        # Add timestamp
        result['analyzed_at'] = time.time()
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'status': 'error', 'error': f'URL analysis failed: {str(e)}'}), 500


@app.route('/api/test_malicious', methods=['POST'])
def api_test_malicious():
    """Legacy endpoint for backward compatibility"""
    data = request.json or {}
    test_domain = data.get('domain', 'test-malware.com')
    
    # Create a fake malicious connection event
    fake_event = {
        'type': 'net_conn',
        'fd': 999,
        'laddr': {'ip': '127.0.0.1', 'port': 12345},
        'raddr': {'ip': '192.168.1.100', 'port': 80},
        'status': 'ESTABLISHED',
        'pid': 1234,
        'timestamp': time.time(),
        'remote_hostname': test_domain,
        'is_suspicious': True,
        'suspicious_reason': f'🚨 Test malicious domain: {test_domain}',
        'is_browsing': True
    }
    
    # Add to event queue
    event_q.put(fake_event)
    
    return jsonify({'status': 'ok', 'message': f'Test malicious connection to {test_domain} added'})


if __name__ == '__main__':
    # ensure static exists
    os.makedirs('static', exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    print('Starting Adaptive Unified Real-time Analyzer on http://127.0.0.1:5000')
    app.run(debug=True, port=5000)
