import sys
import os
import json
import hashlib
from datetime import datetime, timezone
import time

from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout,
                             QHBoxLayout, QWidget, QLabel, QFileDialog, QTableWidget,
                             QTableWidgetItem, QHeaderView, QMessageBox, QTabWidget,
                             QTextEdit, QLineEdit, QCheckBox, QGroupBox, QFormLayout)
from PyQt6.QtCore import QTimer, Qt, pyqtSlot, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QColor


def compute_hash(path, skip_file=None):
    """Generate a SHA-256 hash of a file or all files in a folder."""
    sha256 = hashlib.sha256()

    if os.path.isfile(path):
        # Hash a single file
        with open(path, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
    else:
        # Hash an directory
        for root, _, files in os.walk(path):
            for file_name in sorted(files):
                if skip_file and os.path.join(root, file_name) == skip_file:
                    continue
                fpath = os.path.join(root, file_name)
                sha256.update(file_name.encode())
                try:
                    with open(fpath, "rb") as f:
                        while chunk := f.read(4096):
                            sha256.update(chunk)
                except (PermissionError, FileNotFoundError):
                    # Skip files we can't read
                    pass

    return sha256.hexdigest()


class HashMonitor(QThread):
    status_updated = pyqtSignal(dict)

    def __init__(self, target_path, status_file):
        super().__init__()
        self.target_path = target_path
        self.status_file = status_file
        self.running = True

    def compute_hash(self, path):
        """Generate a SHA-256 hash of a file or all files in a folder."""
        return compute_hash(path, self.status_file)

    def check_status(self):
        """Check if status file exists and return contents"""
        if os.path.exists(self.status_file):
            try:
                with open(self.status_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {"opened": False, "hash": None, "timestamp": None}
        return {"opened": False, "hash": None, "timestamp": None}

    def mark_opened(self):
        """Update status file with current timestamp and hash"""
        try:
            current_hash = self.compute_hash(self.target_path)
            prev_status = self.check_status()

            # Get the previous hash (if any)
            prev_hash = prev_status.get("hash", None)

            # Use timezone-aware datetime
            status = {
                "opened": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hash": current_hash,
                "previous_hash": prev_hash,
                "changed": prev_hash is not None and prev_hash != current_hash
            }

            # Create directory for status file if it doesn't exist
            os.makedirs(os.path.dirname(self.status_file), exist_ok=True)

            with open(self.status_file, "w") as f:
                json.dump(status, f, indent=4)

            return status
        except Exception as e:
            print(f"Error marking as opened: {e}")
            return {"error": str(e)}

    def run(self):
        """Background monitoring thread"""
        prev_mtime = 0

        while self.running:
            try:
                # Check if target exists
                if not os.path.exists(self.target_path):
                    status = {"error": "Target path no longer exists"}
                    self.status_updated.emit(status)
                    time.sleep(2)
                    continue

                # Check if file/folder was accessed by comparing modification time
                try:
                    current_mtime = os.path.getmtime(self.target_path)
                except (FileNotFoundError, PermissionError):
                    current_mtime = 0

                if current_mtime != prev_mtime:
                    status = self.mark_opened()
                    self.status_updated.emit(status)
                    prev_mtime = current_mtime

                # Also check current status for any manual updates
                status = self.check_status()
                self.status_updated.emit(status)

            except Exception as e:
                status = {"error": str(e)}
                self.status_updated.emit(status)

            time.sleep(2)  # Check every 2 seconds

    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        self.wait()


class FileMonitorApp(QMainWindow):
    def __init__(self):
        super().__init__()
        # Initialize all instance attributes in __init__
        self.target_path = None
        self.status_file = None
        self.monitor_thread = None
        self.history = []

        # Initialize UI elements that were causing warnings
        self.tabs = None
        self.monitor_tab = None
        self.history_tab = None
        self.settings_tab = None
        self.path_input = None
        self.status_label = None
        self.last_opened_label = None
        self.hash_label = None
        self.changed_label = None
        self.start_btn = None
        self.stop_btn = None
        self.check_now_btn = None
        self.history_table = None
        self.status_dir_input = None
        self.status_filename_input = None
        self.hide_status_checkbox = None
        self.auto_start_checkbox = None

        # Initialize the UI
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("File & Folder Monitor")
        self.setGeometry(100, 100, 800, 600)

        # Create tab widget
        self.tabs = QTabWidget()
        self.monitor_tab = QWidget()
        self.history_tab = QWidget()
        self.settings_tab = QWidget()

        self.tabs.addTab(self.monitor_tab, "Monitor")
        self.tabs.addTab(self.history_tab, "History")
        self.tabs.addTab(self.settings_tab, "Settings")

        self.setup_monitor_tab()
        self.setup_history_tab()
        self.setup_settings_tab()

        self.setCentralWidget(self.tabs)

    def setup_monitor_tab(self):
        layout = QVBoxLayout()

        # Target selection
        target_group = QGroupBox("Target Selection")
        target_layout = QHBoxLayout()

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("📂 Select a file or folder to monitor...")
        self.path_input.setReadOnly(True)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_target)
        # Style the browse button
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #222;
                color: white;
                border: 1px solid #5CE1E6;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #333;
                border: 1px solid #00ffc8;
            }
        """)

        target_layout.addWidget(self.path_input)
        target_layout.addWidget(browse_btn)
        target_group.setLayout(target_layout)

        # Status display
        status_group = QGroupBox("Monitoring Status")
        status_layout = QFormLayout()

        self.status_label = QLabel("Not monitoring")
        self.last_opened_label = QLabel("Never")
        self.hash_label = QLabel("N/A")
        self.changed_label = QLabel("N/A")

        status_layout.addRow("Status:", self.status_label)
        status_layout.addRow("Last Opened:", self.last_opened_label)
        status_layout.addRow("Current Hash:", self.hash_label)
        status_layout.addRow("Content Changed:", self.changed_label)

        status_group.setLayout(status_layout)

        # Control buttons
        control_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        self.start_btn.setEnabled(False)
        self.start_btn.setStyleSheet("""
            QPushButton {
                background-color: #222;
                color: white;
                border: 1px solid #5CE1E6;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #333;
                border: 1px solid #00ffc8;
            }
        """)

        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("""
            QPushButton {
                background-color: #222;
                color: white;
                border: 1px solid #5CE1E6;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #333;
                border: 1px solid #00ffc8;
            }
        """)

        self.check_now_btn = QPushButton("Check Now")
        self.check_now_btn.clicked.connect(self.check_now)
        self.check_now_btn.setEnabled(False)
        self.check_now_btn.setStyleSheet("""
            QPushButton {
                background-color: #222;
                color: white;
                border: 1px solid #5CE1E6;
                border-radius: 6px;
                padding: 6px 12px;
            }
            QPushButton:hover {
                background-color: #333;
                border: 1px solid #00ffc8;
            }
        """)

        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.stop_btn)
        control_layout.addWidget(self.check_now_btn)

        layout.addWidget(target_group)
        layout.addWidget(status_group)
        layout.addLayout(control_layout)

        # Wrap the entire layout in a QGroupBox for the dashboard
        monitor_group = QGroupBox("📁 Monitor Dashboard")
        monitor_group.setStyleSheet("""
            QGroupBox {
                background-color: rgba(255, 255, 255, 0.05);
                border: 1px solid #5CE1E6;
                border-radius: 12px;
                margin-top: 20px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 3px;
                font-size: 16px;
                font-weight: bold;
                color: #00ffc8;
            }
        """)
        monitor_group.setLayout(layout)
        self.monitor_tab.setLayout(QVBoxLayout())
        self.monitor_tab.layout().addWidget(monitor_group)

        # Style the status labels at the end
        self.status_label.setStyleSheet("font-weight: bold; color: gray; font-size: 14px;")
        self.last_opened_label.setStyleSheet("color: #aaa; font-family: monospace;")
        self.hash_label.setStyleSheet("color: #ccc; font-family: monospace;")
        self.changed_label.setStyleSheet("font-weight: bold;")

    def setup_history_tab(self):
        layout = QVBoxLayout()

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(4)
        self.history_table.setHorizontalHeaderLabels(["Timestamp", "Target", "Hash", "Changed"])
        self.history_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.history_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)

        clear_btn = QPushButton("Clear History")
        clear_btn.clicked.connect(self.clear_history)

        layout.addWidget(self.history_table)
        layout.addWidget(clear_btn)

        self.history_tab.setLayout(layout)

    def setup_settings_tab(self):
        layout = QVBoxLayout()

        # Status file location
        status_file_group = QGroupBox("Status File Location")
        status_file_layout = QFormLayout()

        self.status_dir_input = QLineEdit()
        self.status_dir_input.setText(os.path.expanduser("~/.file_monitor"))

        self.status_filename_input = QLineEdit()
        self.status_filename_input.setText(".opened_status.json")

        status_file_layout.addRow("Directory:", self.status_dir_input)
        status_file_layout.addRow("Filename:", self.status_filename_input)

        status_file_group.setLayout(status_file_layout)

        # Monitoring options
        options_group = QGroupBox("Monitoring Options")
        options_layout = QFormLayout()

        self.hide_status_checkbox = QCheckBox()
        self.hide_status_checkbox.setChecked(True)

        self.auto_start_checkbox = QCheckBox()
        self.auto_start_checkbox.setChecked(False)

        options_layout.addRow("Hide status file:", self.hide_status_checkbox)
        options_layout.addRow("Auto-start monitoring:", self.auto_start_checkbox)

        options_group.setLayout(options_layout)

        # Save button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)

        layout.addWidget(status_file_group)
        layout.addWidget(options_group)
        layout.addWidget(save_btn)
        layout.addStretch()

        self.settings_tab.setLayout(layout)

    def browse_target(self):
        """Open file dialog to select target file or folder"""
        path, _ = QFileDialog.getOpenFileName(self, "Select File to Monitor")

        if not path:  # User might have canceled or selected directory
            path = QFileDialog.getExistingDirectory(self, "Select Folder to Monitor")

        if path:
            self.target_path = path
            self.path_input.setText(path)
            self.start_btn.setEnabled(True)

            # Update status file path based on target
            self._update_status_file_path()

    def _update_status_file_path(self):
        """Update the status file path based on current settings"""
        if not self.target_path:
            return

        status_dir = self.status_dir_input.text()
        status_filename = self.status_filename_input.text()

        # Create a hash of the target path to use in the status filename
        target_hash = hashlib.md5(self.target_path.encode()).hexdigest()[:8]

        self.status_file = os.path.join(
            status_dir,
            f"{target_hash}_{status_filename}"
        )

    def start_monitoring(self):
        """Start the monitoring thread"""
        if not self.target_path:
            return

        self._update_status_file_path()

        # Create and start monitor thread
        self.monitor_thread = HashMonitor(self.target_path, self.status_file)
        self.monitor_thread.status_updated.connect(self.update_status)
        self.monitor_thread.start()

        # Update UI
        self.status_label.setText("Monitoring")
        self.status_label.setStyleSheet("font-weight: bold; color: green;")

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.check_now_btn.setEnabled(True)

    def stop_monitoring(self):
        """Stop the monitoring thread"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()

        # Update UI
        self.status_label.setText("Not monitoring")
        self.status_label.setStyleSheet("font-weight: bold; color: gray;")

        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.check_now_btn.setEnabled(False)

    def check_now(self):
        """Force an immediate check of the target"""
        if not self.monitor_thread or not self.monitor_thread.isRunning():
            return

        # Perform a manual check
        status = self.monitor_thread.mark_opened()
        self.update_status(status)

    @pyqtSlot(dict)
    def update_status(self, status):
        """Update the UI with the latest status"""
        if "error" in status:
            self.status_label.setText(f"Error: {status['error']}")
            self.status_label.setStyleSheet("font-weight: bold; color: red;")
            return

        # Update status display
        if status.get("opened", False):
            timestamp = status.get("timestamp", "Unknown")
            if timestamp != "Unknown":
                # Convert ISO format to more readable format
                try:
                    # Use timezone-aware datetime
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            self.last_opened_label.setText(timestamp)

        if "hash" in status and status["hash"]:
            hash_val = status["hash"]
            self.hash_label.setText(f"{hash_val[:10]}...{hash_val[-10:]}")

        if "changed" in status:
            if status["changed"]:
                self.changed_label.setText("Yes")
                self.changed_label.setStyleSheet("color: red;")
            else:
                self.changed_label.setText("No")
                self.changed_label.setStyleSheet("color: green;")

        # Add to history if this is a new entry
        if status.get("timestamp") and status.get("hash"):
            # Check if this is a new entry we haven't seen before
            entry = {
                "timestamp": status.get("timestamp"),
                "target": self.target_path,
                "hash": status.get("hash"),
                "changed": status.get("changed", False)
            }

            # Only add if it's a new unique timestamp
            if not any(h.get("timestamp") == entry["timestamp"] for h in self.history):
                self.history.append(entry)
                self.update_history_table()

    def update_history_table(self):
        """Update the history table with all recorded entries"""
        self.history_table.setRowCount(0)  # Clear table

        for i, entry in enumerate(reversed(self.history)):  # Show newest first
            self.history_table.insertRow(i)

            # Format timestamp
            timestamp = entry.get("timestamp", "Unknown")
            if timestamp != "Unknown":
                try:
                    dt = datetime.fromisoformat(timestamp)
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                except ValueError:
                    pass

            # Add items to row
            self.history_table.setItem(i, 0, QTableWidgetItem(timestamp))
            self.history_table.setItem(i, 1, QTableWidgetItem(os.path.basename(entry.get("target", "Unknown"))))

            hash_val = entry.get("hash", "N/A")
            if hash_val != "N/A":
                hash_display = f"{hash_val[:10]}...{hash_val[-10:]}"
            else:
                hash_display = hash_val
            self.history_table.setItem(i, 2, QTableWidgetItem(hash_display))

            changed_item = QTableWidgetItem("Yes" if entry.get("changed", False) else "No")
            if entry.get("changed", False):
                changed_item.setForeground(QColor("red"))
            else:
                changed_item.setForeground(QColor("green"))
            self.history_table.setItem(i, 3, changed_item)

    def clear_history(self):
        """Clear the history table and list"""
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear the history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.history = []
            self.history_table.setRowCount(0)

    def save_settings(self):
        """Save the current settings"""
        self._update_status_file_path()

        QMessageBox.information(
            self,
            "Settings Saved",
            f"Settings saved. Status file will be stored at:\n{self.status_file}"
        )

    def closeEvent(self, event):
        """Handle application close"""
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileMonitorApp()
    window.show()
    sys.exit(app.exec())