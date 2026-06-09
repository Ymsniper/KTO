# KTO 🦿 Kick Them Out

Point it at an SSID and it automatically discovers every connected client and kicks them — including ones that try to reconnect — with no manual targeting needed.

Tools like `aireplay-ng` make you supply a BSSID and a client MAC. You have to know who's on the network first, and if someone reconnects you have to catch them yourself and run it again. KTO does all of that automatically in a loop: continuous scan → live client list → auto deauth → repeat. Anyone who reconnects gets caught on the next sweep.

> **Authorized use only.** Only run this against networks you own or have explicit written permission to test. Unauthorized deauthentication is illegal in most jurisdictions.

---

## Features

- **Live blacklist** — client list updates every sweep, new joiners get kicked automatically
- **Auto deauth** — no manual targeting, runs fully unattended
- **Aggressive mode** — scan and deauth threads run in parallel so there's no reconnect window between sweeps
- **Whitelist** — spare specific devices via inline MACs or a file
- **Mesh / multi-AP** — handles SSIDs that span multiple BSSIDs, auto-picks the strongest or lets you choose
- **PMF detection** — warns you when 802.11w is active and unprotected frames will be dropped by patched clients
- **Dual deauth engine** — Scapy raw 802.11 frames (default) or aireplay-ng
- **Live table** — `--live-table` shows a refreshing client table instead of scrolling log, good for demos
- **Session log** — `--log FILE` saves every kick with a timestamp, appends across sessions
- **Passive mode** — `--scan-only` discovers and logs clients without sending any frames
- **Auto monitor mode** — enables and restores monitor mode automatically via airmon-ng
- **OUI lookup** — shows Apple / Samsung / etc next to each MAC
- **Self-updating** — checks for new releases on startup and notifies you if one is available

---

## Requirements

```bash
# Python 3.10+
pip install scapy

# aircrack-ng suite
sudo apt install aircrack-ng
```

Must be run as root.

---

## Installation

```bash
git clone https://github.com/Ymsniper/KTO.git
cd KTO
pip install scapy
```

No other setup. Single script, no config files.

---

## Usage

```
sudo python3 kto.py -i <interface> -t <SSID> [options]
```

The interface needs to be in monitor mode, or pass `--auto-monitor` to let KTO handle it.

### Arguments

| Flag | Default | Description |
|------|---------|-------------|
| `-i`, `--interface` | required | Wireless interface (e.g. `wlan0mon`) |
| `-t`, `--target` | required | Target SSID name |
| `-w`, `--whitelist` | — | Comma-separated MACs to spare |
| `--whitelist-file FILE` | — | File of MACs to spare, one per line (`#` = comment) |
| `-c`, `--channel` | auto | Lock to a specific channel |
| `-n`, `--count` | 5 | Deauth frames per burst per direction |
| `-s`, `--sleep` | 5.0 | Seconds between sweeps |
| `--scan-duration` | 8.0 | Seconds airodump-ng listens per sweep |
| `--delay` | 0.1 | Per-client delay in aggressive loop |
| `--broadcast` | off | Also deauth `ff:ff:ff:ff:ff:ff` |
| `--aireplay` | off | Use aireplay-ng instead of Scapy |
| `--aggressive` | off | Parallel scan + deauth threads |
| `--scan-only` | off | Passive mode, no frames sent |
| `--auto-monitor` | off | Auto-enable monitor mode via airmon-ng |
| `--auto-bssid` | off | Auto-pick strongest BSSID for mesh / multi-AP SSIDs |
| `--reason` | 7 | 802.11 reason code (1=unspecified, 4=inactivity, 7=class3-frame) |
| `--log FILE` | — | Save timestamped kick log to a file |
| `--live-table` | off | Refreshing client table instead of scrolling output |

---

## Examples

```bash
# basic
sudo python3 kto.py -i wlan0mon -t "CorpNet"

# let KTO handle monitor mode
sudo python3 kto.py -i wlan0 -t "CorpNet" --auto-monitor

# aggressive mode — no reconnect window
sudo python3 kto.py -i wlan0mon -t "CorpNet" --aggressive

# spare your own device
sudo python3 kto.py -i wlan0mon -t "CorpNet" -w AA:BB:CC:DD:EE:FF

# passive discovery only, no deauth
sudo python3 kto.py -i wlan0mon -t "CorpNet" --scan-only

# mesh or multi-AP network
sudo python3 kto.py -i wlan0mon -t "CorpNet" --auto-bssid

# save a log and show live table
sudo python3 kto.py -i wlan0mon -t "CorpNet" --log session.txt --live-table

# heavier burst with aireplay-ng
sudo python3 kto.py -i wlan0mon -t "CorpNet" -n 10 --aireplay --broadcast
```

---

## Whitelist file format

```
# my phone
AA:BB:CC:DD:EE:FF

# laptop
11:22:33:44:55:66
```

---

## Notes on PMF / 802.11w

If the target AP has Protected Management Frames enabled KTO will warn you at startup. Clients with 802.11w support will silently drop unprotected deauth frames, so effectiveness depends on which devices are connected.

However, **in aggressive mode with a high enough deauth burst**, KTO has been observed to still disconnect PMF‑protected clients on some networks—even without a bypass. The sheer volume of frames appears to overwhelm certain implementations. So while PMF is a critical defense, it isn’t bulletproof in every setup.

---

## Stopping

`Ctrl+C` stops everything cleanly, restores the interface to managed mode if KTO created the monitor interface, and prints a session summary with burst counts per client.

---

## License

MIT — see [LICENSE](LICENSE)
