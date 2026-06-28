#!/usr/bin/env python3
"""
tor_mode_host.py — native messaging host for the Tor Mode extension.

The extension talks to this script over stdin/stdout using the browser's
native messaging framing (a 4-byte little-endian length prefix followed by
a UTF-8 JSON payload). This script handles everything a sandboxed
extension cannot do on its own:

  * starting/stopping the Tor systemd service (needs root)
  * waiting for the local SOCKS port to come up
  * verifying the resulting exit node through check.torproject.org
  * looking up a rough location for that exit IP

The extension itself owns flipping Firefox's actual proxy settings
(via browser.proxy.settings) once this script reports success.
"""
import json
import socket
import struct
import subprocess
import sys
import time

SOCKS_HOST = "127.0.0.1"
SOCKS_PORT = 9050
TOR_SERVICE = "tor"
CURL_TIMEOUT = 10


def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if len(raw_length) == 0:
        sys.exit(0)
    length = struct.unpack("<I", raw_length)[0]
    raw_message = sys.stdin.buffer.read(length)
    return json.loads(raw_message.decode("utf-8"))


def send_message(payload):
    encoded = json.dumps(payload).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(encoded)))
    sys.stdout.buffer.write(encoded)
    sys.stdout.buffer.flush()


def run_privileged(args):
    """Try passwordless sudo first; fall back to a graphical pkexec prompt."""
    try:
        result = subprocess.run(
            ["sudo", "-n", *args], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    try:
        result = subprocess.run(
            ["pkexec", *args], capture_output=True, text=True, timeout=60
        )
        return result.returncode == 0, (result.stdout or result.stderr).strip()
    except FileNotFoundError:
        return False, "Neither passwordless sudo nor pkexec is available on this system."


def is_tor_active():
    result = subprocess.run(
        ["systemctl", "is-active", TOR_SERVICE], capture_output=True, text=True
    )
    return result.stdout.strip() == "active"


def wait_for_socks_port(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((SOCKS_HOST, SOCKS_PORT), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def curl_through_tor(url, timeout=CURL_TIMEOUT):
    """Runs curl through the Tor SOCKS port, resolving DNS through it too
    (--socks5-hostname rather than --socks5), so this check doesn't leak
    DNS itself."""
    try:
        result = subprocess.run(
            [
                "curl", "-s", "--max-time", str(timeout),
                "--socks5-hostname", f"{SOCKS_HOST}:{SOCKS_PORT}",
                url,
            ],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def check_tor_exit():
    raw = curl_through_tor("https://check.torproject.org/api/ip")
    if not raw:
        return {"is_tor": None, "exit_ip": None}
    try:
        data = json.loads(raw)
        return {"is_tor": data.get("IsTor"), "exit_ip": data.get("IP")}
    except json.JSONDecodeError:
        return {"is_tor": None, "exit_ip": None}


def lookup_location(ip):
    if not ip:
        return None
    raw = curl_through_tor(f"http://ip-api.com/json/{ip}")
    if not raw:
        return None
    try:
        data = json.loads(raw)
        city = data.get("city")
        country = data.get("country")
        if city and country:
            return f"{city}, {country}"
        return country or None
    except json.JSONDecodeError:
        return None


def handle_start():
    send_message({"phase": "progress", "step": "Starting the Tor service"})

    if not is_tor_active():
        ok, output = run_privileged(["systemctl", "start", TOR_SERVICE])
        if not ok:
            send_message({
                "phase": "started",
                "success": False,
                "tor_active": False,
                "error": f"Could not start the Tor service: {output}",
            })
            return

    send_message({"phase": "progress", "step": "Waiting for the SOCKS port to open"})
    socks_open = wait_for_socks_port()
    if not socks_open:
        send_message({
            "phase": "started",
            "success": False,
            "tor_active": is_tor_active(),
            "socks_port_open": False,
            "error": "Tor service is active but the SOCKS port never opened.",
        })
        return

    send_message({"phase": "progress", "step": "Verifying through check.torproject.org"})
    exit_info = check_tor_exit()
    location = lookup_location(exit_info.get("exit_ip"))

    send_message({
        "phase": "started",
        "success": bool(exit_info.get("is_tor")),
        "tor_active": True,
        "socks_port_open": True,
        "is_tor": exit_info.get("is_tor"),
        "exit_ip": exit_info.get("exit_ip"),
        "location": location,
    })


def handle_stop():
    send_message({"phase": "progress", "step": "Stopping the Tor service"})
    ok, output = run_privileged(["systemctl", "stop", TOR_SERVICE])
    send_message({
        "phase": "stopped",
        "success": ok,
        "tor_active": is_tor_active(),
        "error": None if ok else output,
    })


def handle_status():
    send_message({
        "phase": "status",
        "tor_active": is_tor_active(),
        "socks_port_open": wait_for_socks_port(timeout=1),
    })


def main():
    while True:
        message = read_message()
        action = message.get("action")
        if action == "start":
            handle_start()
        elif action == "stop":
            handle_stop()
        elif action == "status":
            handle_status()
        else:
            send_message({"phase": "error", "error": f"Unknown action: {action}"})


if __name__ == "__main__":
    main()