#!/usr/bin/env python3
"""
Single-port launcher for Flask backend serving the web UI.
"""
import os
import sys

if __name__ == '__main__':
    print('Starting Adaptive Unified Real-time Analyzer on http://127.0.0.1:5000 ...')
    os.execv(sys.executable, [sys.executable, 'app.py'])
