# main_window.py
# Minimal PyQt6 wrapper that can subscribe to SSE or use the internal queue
# For brevity this file keeps the GUI light and relies on app.py for streaming
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit, QPushButton
import sys

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Adaptive Unified Real-time Analyzer GUI')
        self.resize(800,600)
        self.layout = QVBoxLayout()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.layout.addWidget(self.log)
        self.btn = QPushButton('Open web UI')
        self.btn.clicked.connect(self.open_web_ui)
        self.layout.addWidget(self.btn)
        self.setLayout(self.layout)

    def open_web_ui(self):
        import webbrowser
        webbrowser.open('http://127.0.0.1:5000/')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    w = MainWindow(); w.show()
    sys.exit(app.exec())
