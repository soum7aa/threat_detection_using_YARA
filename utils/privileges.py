"""
Utility module to check for elevated privileges on Windows and Unix systems.
"""
import os
import sys

def is_admin_windows():
    """Check if running with administrator privileges on Windows."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def is_admin_unix():
    """Check if running with root privileges on Unix/Linux/Mac."""
    return os.geteuid() == 0

def is_elevated():
    """
    Check if the current process has elevated privileges.
    Returns True if running as admin (Windows) or root (Unix).
    """
    if sys.platform == 'win32':
        return is_admin_windows()
    else:
        return is_admin_unix()

def get_privilege_status():
    """
    Get detailed privilege status information.
    Returns a dictionary with status information.
    """
    is_admin = is_elevated()
    platform = sys.platform
    
    status = {
        'is_elevated': is_admin,
        'platform': platform,
        'user': os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
        'message': ''
    }
    
    if sys.platform == 'win32':
        if is_admin:
            status['message'] = 'Running with Administrator privileges'
        else:
            status['message'] = 'Running as standard user (some features may be limited)'
    else:
        if is_admin:
            status['message'] = 'Running as root'
        else:
            status['message'] = 'Running as standard user (some features may be limited)'
    
    return status

if __name__ == '__main__':
    status = get_privilege_status()
    print(f"Elevated Privileges: {status['is_elevated']}")
    print(f"Platform: {status['platform']}")
    print(f"User: {status['user']}")
    print(f"Status: {status['message']}")


