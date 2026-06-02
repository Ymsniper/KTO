# KTO -- Kick Them Out

A WiFi deauthentication tool built for authorized penetration testing. KTO scans a target network for connected clients and sends 802.11 deauthentication frames to disconnect them. It supports passive client discovery, MAC whitelisting, dual deauth engines, and an aggressive threaded mode where scanning and deauthing run in parallel so clients have no window to reconnect.

> **For authorized use only.** Only run this against networks you own or have explicit written permission to test. Unauthorized deauthentication attacks are illegal in most jurisdictions.

---

## Features

- Discovers connected clients using airodump-ng and parses results automatically
- Deauthenticates clients using either Scapy (raw 802.11) or aireplay-ng
- Aggressive mode: scan and deauth threads run in parallel, clients get no reconnect window
- Passive scan-only mode for client discovery without sending any frames
- MAC whitelist support via inline flag or file, so specific devices are never touched
- Handles multi-AP SSIDs (mesh networks, roaming setups) with auto BSSID selection or interactive picker
- Auto monitor mode via airmon-ng, restores interface to managed mode on exit
- OUI vendor lookup so you can see Apple/Samsung/etc next to each MAC
- Configurable 802.11 deauth reason code
- Broadcast deauth support
- Clean session summary on exit showing bursts per client

---

## Requirements

**Python**

- Python 3.10 or higher
- scapy

```
pip install scapy
```

**System tools (aircrack-ng suite)**

```
sudo apt install aircrack-ng
```

This gives you `airodump-ng`, `aireplay-ng`, and `airmon-ng`.

**Permissions**

Must be run as root.

---

## Installation

```bash
git clone <repo-url>
cd kto
pip install scapy
```

No other setup needed. The script is self-contained.

---

## Usage

```
sudo python3 kto.py -i <interface> -t <SSID> [options]
```

Your wireless interface needs to be in monitor mode before running, unless you pass `--auto-monitor` to let KTO handle it.

### Required arguments

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Wireless interface to use (e.g. `wlan0mon`) |
| `-t`, `--target` | Target WiFi SSID name |

### Optional arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-w`, `--whitelist` | none | Comma-separated MACs to spare from deauth |
| `--whitelist-file FILE` | none | Path to a file of MACs to spare, one per line (lines starting with `#` are comments) |
| `-c`, `--channel` | auto | Lock to a specific channel instead of auto-detecting |
| `-n`, `--count` | 5 | Number of deauth frames per burst per direction |
| `-s`, `--sleep` | 5.0 | Seconds between client sweeps |
| `--scan-duration` | 8.0 | Seconds airodump-ng listens per sweep |
| `--delay` | 0.1 | Seconds between clients in aggressive deauth loop |
| `--broadcast` | off | Also send deauth to `ff:ff:ff:ff:ff:ff` |
| `--aireplay` | off | Use aireplay-ng instead of Scapy for deauth |
| `--aggressive` | off | Threaded mode: deauth runs in parallel with scanning |
| `--scan-only` | off | Passive mode, discover and log clients without deauthing |
| `--auto-monitor` | off | Auto-enable monitor mode via airmon-ng (pass base interface e.g. `wlan0`) |
| `--auto-bssid` | off | Auto-select strongest AP when the SSID spans multiple BSSIDs |
| `--reason` | 7 | 802.11 deauth reason code (1=unspecified, 4=inactivity, 7=class3-frame) |

---

## Examples

Basic run against a network, interface already in monitor mode:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet"
```

Let KTO put the interface in monitor mode automatically:

```bash
sudo python3 kto.py -i wlan0 -t "CorpNet" --auto-monitor
```

Aggressive mode, scan and deauth in parallel:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --aggressive
```

Passive scan only, no frames sent:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --scan-only
```

Whitelist one device by MAC:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" -w AA:BB:CC:DD:EE:FF
```

Whitelist multiple devices from a file:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --whitelist-file safe.txt
```

Bigger burst, use aireplay-ng, add broadcast:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" -n 10 --aireplay --broadcast
```

Longer scan windows:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --scan-duration 12 --delay 0.2
```

Mesh or multi-AP network, auto-pick strongest BSSID:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --auto-bssid
```

Custom reason code:

```bash
sudo python3 kto.py -i wlan0mon -t "CorpNet" --reason 1
```

---

## Whitelist file format

One MAC per line. Lines starting with `#` are treated as comments and ignored.

```
# safe devices
AA:BB:CC:DD:EE:FF
11:22:33:44:55:66
```

---

## Notes on PMF / 802.11w

If the target AP has Protected Management Frames enabled, KTO will warn you. Clients that support 802.11w will ignore unprotected deauth frames, so the PoC effectiveness depends on which clients are connected and whether they are patched.

---

## Stopping

Press `Ctrl+C` at any time. KTO will stop cleanly, restore the interface to managed mode if it created the monitor interface, and print a session summary showing how many deauth bursts were sent per client.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
