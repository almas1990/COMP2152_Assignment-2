"""
Author: Almas Sultana
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime

print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# Dictionary that stores common port numbers and their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

class NetworkTool:

    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property allows controlled access to private variables
    # while keeping simple syntax. The setter lets us validate values
    # before updating them, preventing invalid data such as an empty target.
    @property
    def target(self):
        return self.__target

    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
        else:
            self.__target = value

    def __del__(self):
        print("NetworkTool instance destroyed")


# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner inherits from NetworkTool which allows it to reuse the
# target property and constructor defined in the parent class.
# Instead of rewriting the initialization logic, PortScanner calls
# super().__init__(target) to initialize the target variable.
class PortScanner(NetworkTool):

    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    def scan_port(self, port):

        # Q4: What would happen without try-except here?
        # Without exception handling, any network error such as a timeout,
        # unreachable host, or socket failure would stop the entire program.
        # Using try-except allows the scanner to continue scanning other ports
        # even if one port causes an error.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            result = sock.connect_ex((self.target, port))

            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Error scanning port {port}: {e}")

        finally:
            sock.close()

    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading allows the scanner to check many ports simultaneously.
    # If ports were scanned sequentially, the program would wait for each
    # timeout before continuing. Scanning hundreds of ports would take much
    # longer without threads.
    def scan_range(self, start_port, end_port):

        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):

    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        for port, status, service in results:
            cursor.execute(
                "INSERT INTO scans (target, port, status, service, scan_date) VALUES (?, ?, ?, ?, ?)",
                (target, port, status, service, str(datetime.datetime.now()))
            )

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        print("Database error:", e)


def load_past_scans():

    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        for target, port, status, service, date in rows:
            print(f"[{date}] {target} : Port {port} ({service}) - {status}")

        conn.close()

    except sqlite3.Error:
        print("No past scans found.")


if __name__ == "__main__":

    target = input("Enter target IP (default 127.0.0.1): ")

    if target == "":
        target = "127.0.0.1"

    try:
        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
            exit()

        if end_port < start_port:
            print("End port must be greater than or equal to start port.")
            exit()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")
        exit()

    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")

    scanner.scan_range(start_port, end_port)

    open_ports = scanner.get_open_ports()

    print(f"\n--- Scan Results for {target} ---")

    for port, status, service in open_ports:
        print(f"Port {port}: Open ({service})")

    print("------")
    print("Total open ports found:", len(open_ports))

    save_results(target, scanner.scan_results)

    view_history = input("Would you like to see past scan history? (yes/no): ")

    if view_history.lower() == "yes":
        load_past_scans()


# Q5: New Feature Proposal
# One additional feature I would add is a port risk classification system.
# The program could use nested if-statements to categorize open ports
# into HIGH, MEDIUM, or LOW security risk based on known vulnerable services.
# Diagram: See diagram_101568934.png in the repository root