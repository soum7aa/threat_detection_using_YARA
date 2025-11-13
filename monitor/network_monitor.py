# monitor/network_monitor.py
import psutil
import time
import threading
import queue

class NetworkMonitor(threading.Thread):
    def __init__(self, out_queue: queue.Queue, interval=0.5):
        super().__init__(daemon=True)
        self.out_queue = out_queue
        self.interval = interval
        self._stop = threading.Event()
        # Educational malicious detection - simplified but effective
        self.malicious_domains = {
            # Common malicious patterns (educational examples)
            'malware.com', 'virus.net', 'trojan.org', 'phishing.site',
            'suspicious-domain.com', 'malicious-ip.net', 'botnet.cc',
            'c2-server.com', 'malware-distribution.net', 'fake-bank.com',
            'phishing-paypal.com', 'malicious-download.net',
            # Test domains for demonstration
            'test-malware.com', 'demo-phishing.net', 'fake-virus.org',
            'malicious-test.com', 'suspicious-demo.net'
        }
        
        # Suspicious IP ranges (educational examples)
        self.suspicious_ip_ranges = [
            '192.168.1.100',  # Simulated malicious C2
            '10.0.0.50',      # Simulated proxy
            '172.16.0.10',    # Simulated phishing
        ]
        # Suspicious patterns
        self.suspicious_patterns = [
            'tor', 'proxy', 'vpn', 'anonymizer', 'bitcoin', 'crypto',
            'mining', 'botnet', 'command-and-control', 'c2', 'malware',
            'virus', 'trojan', 'phishing', 'exploit', 'payload', 'fake',
            'scam', 'fraud', 'steal', 'hack', 'crack'
        ]
        
        # Track recent connections to avoid spam
        self.recent_connections = set()
        self.connection_timeout = 10  # seconds

    def _is_suspicious_domain(self, hostname):
        if not hostname:
            return False
        hostname_lower = hostname.lower()
        
        # Check against known malicious domains
        if hostname_lower in self.malicious_domains:
            return True
            
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern in hostname_lower:
                return True
                
        # Check for suspicious TLDs or IP patterns
        if hostname_lower.endswith('.onion') or hostname_lower.endswith('.bit'):
            return True
            
        return False

    def _get_domain_from_ip(self, ip):
        """Educational domain resolution - simplified for learning"""
        try:
            # Educational simulation of malicious domains
            # In real-world: Use threat intelligence feeds, DNS reputation services
            malicious_simulations = {
                '192.168.1.100': 'malicious-command-center.com',
                '10.0.0.50': 'suspicious-proxy.net', 
                '172.16.0.10': 'phishing-bank.com',
                '203.0.113.1': 'malware-distribution.net',
                '198.51.100.1': 'fake-paypal.com'
            }
            
            return malicious_simulations.get(ip)
            
        except Exception:
            return None

    def _is_suspicious_connection_pattern(self, conn):
        """Educational behavioral analysis - simplified patterns"""
        try:
            # Check for suspicious connection patterns
            raddr = getattr(conn, 'raddr', None)
            if not raddr:
                return False, None
                
            # Pattern 1: Suspicious ports
            suspicious_ports = [4444, 6666, 31337, 8080, 9999]
            if raddr.port in suspicious_ports:
                return True, f"⚠️ Suspicious port: {raddr.port}"
            
            # Pattern 2: Multiple connections to same IP (simplified)
            # In real-world: Track connection frequency, timing patterns
            if raddr.ip in self.suspicious_ip_ranges:
                return True, f"🚨 Known malicious IP: {raddr.ip}"
                
            # Pattern 3: Non-standard browsing ports
            if conn.status == 'ESTABLISHED' and raddr.port not in [80, 443, 8080, 8443]:
                return True, f"⚠️ Non-standard port: {raddr.port}"
                
            return False, None
            
        except Exception:
            return False, None

    def run(self):
        while not self._stop.is_set():
            try:
                conns = psutil.net_connections(kind='inet')
                current_time = time.time()
                
                for c in conns:
                    # Create unique connection identifier to avoid spam
                    conn_id = f"{c.pid}_{c.laddr}_{c.raddr}_{c.status}"
                    if conn_id in self.recent_connections:
                        continue
                    self.recent_connections.add(conn_id)
                    
                    # Clean old connections from tracking
                    if len(self.recent_connections) > 500:
                        self.recent_connections.clear()
                    
                    # Extract connection info
                    laddr = getattr(c,'laddr',None)
                    raddr = getattr(c,'raddr',None)
                    
                    # Determine if this is browsing activity
                    is_browsing = False
                    if raddr and c.status == 'ESTABLISHED':
                        # Common browsing ports
                        browsing_ports = [80, 443, 8080, 8443, 8000, 3000, 5000]
                        if raddr.port in browsing_ports:
                            is_browsing = True
                    
                    # Get remote hostname if available
                    remote_hostname = None
                    if raddr:
                        remote_hostname = self._get_domain_from_ip(raddr.ip)
                    
                    # Educational malicious detection - simplified but effective
                    is_suspicious = False
                    suspicious_reason = None
                    
                    # Method 1: Domain-based detection
                    if remote_hostname and self._is_suspicious_domain(remote_hostname):
                        is_suspicious = True
                        suspicious_reason = f"🚨 Malicious domain: {remote_hostname}"
                    
                    # Method 2: Behavioral pattern analysis
                    if not is_suspicious:
                        pattern_suspicious, pattern_reason = self._is_suspicious_connection_pattern(c)
                        if pattern_suspicious:
                            is_suspicious = True
                            suspicious_reason = pattern_reason
                    
                    event = {
                        'type': 'net_conn',
                        'fd': getattr(c,'fd',None),
                        'laddr': laddr._asdict() if laddr else None,
                        'raddr': raddr._asdict() if raddr else None,
                        'status': c.status,
                        'pid': c.pid,
                        'timestamp': current_time,
                        'remote_hostname': remote_hostname,
                        'is_suspicious': is_suspicious,
                        'suspicious_reason': suspicious_reason,
                        'is_browsing': is_browsing
                    }
                    self.out_queue.put(event)
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()
