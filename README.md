# CYD Advanced WiFi & BLE Scanner

A feature-rich wireless security scanner, sniffer, and human presence detector for the **ESP32-2432S028R (CYD — Cheap Yellow Display)**. Nine independent scanning modes accessible from a touch footer bar, including a two-device WiFi CSI-based presence detection system.

> **Hardware:** ESP32-2432S028R · ILI9341 320×240 touchscreen · XPT2046 touch · RGB LED · SD card (optional)

---

## Screenshots

| SCAN Mode | CHAN Mode | BLE Mode |
|-----------|-----------|----------|
| ![SCAN](IMG_20260304_004539.jpg) | ![CHAN](IMG_20260304_004612.jpg) | ![BLE](IMG_20260304_004709.jpg) |

*15 networks sorted by signal strength with live bars, dBm, channel, and encryption type · Channel activity heatmap hopping 1–13 · BLE device hunter showing MAC + RSSI*

---

## Two Firmware Builds

This repo contains **two separate firmware builds** — functionally identical, differing only in display hardware:

| Folder | Board | Display |
|--------|-------|---------|
| `src/` | Standard CYD (ESP32-2432S028R) | Normal color polarity |
| `InvertedCYDWifiScanner/` | Inverted CYD variant | `invertDisplay(true)` applied |

Flash the correct one for your board. If colors look wrong (white appears black, green appears magenta), use the inverted build.

---

## Modes

All nine modes are accessible from the touch footer bar at the bottom of the screen. Tap any label to switch instantly.

### `[SCAN]` — WiFi Network Scanner
Async WiFi scan with compact terminal-style display. Results persist on screen during rescans — no blank flicker.

- Up to 40 networks displayed, sorted by signal strength (strongest first)
- Color-coded signal bar per network: **green** (strong) · **yellow** (medium) · **red** (weak)
- Shows: SSID · lock icon · signal bar · dBm · channel · encryption type (WPA2/WPA3/WPA+/OPEN)
- Hidden networks deduplicated by BSSID and sorted to the bottom, labeled `[Hidden]`
- Header shows live count: `15 nets (0 hidden)` with `↻` spinner during active scan
- Rescans every 5 seconds automatically
- Touch upper/lower body to scroll

### `[PROBE]` — Probe Request Sniffer
Promiscuous mode capture of 802.11 probe request frames.

- Shows the last 8 probe requests with source MAC and requested SSID
- Wildcard probes (devices broadcasting for any network) labeled `<wildcard>`
- Updates in real time as frames are captured
- Touch to scroll history

### `[CHAN]` — Channel Activity Monitor
Live bar chart of 802.11 frame activity across all 13 WiFi channels.

- Auto-hops channel every 200ms, counting all frames seen on each channel
- Tap a channel bar to **lock** onto that channel; tap again to resume hopping
- Locked channel number highlighted in the header
- Great for visualizing channel congestion at a glance

### `[DAUTH]` — Deauth Attack Detector
Monitors for 802.11 deauthentication and disassociation frames — the hallmark of WiFi deauth attacks.

- Tracks per-BSSID deauth rate (frames/sec over a sliding 3-second window)
- **ALERT** flag triggers when rate exceeds threshold (≥5/sec)
- RGB LED flashes **red** when an attack is detected
- Shows BSSID, total frame count, and computed rate
- Tap body to clear the alert log

### `[BLE]` — Bluetooth Low Energy Scanner
Non-blocking BLE device discovery running on a dedicated FreeRTOS task.

- Detects nearby BLE devices with MAC address, name, and RSSI
- **Skimmer hunter**: flags devices matching known ATM/POS skimmer MAC prefixes and names
- **Threat detection**: unknown/unnamed devices at strong signal flagged as suspicious
- RGB LED pulses **blue** when scanning
- Shows: device name (or `<unnamed>`) · MAC · RSSI · threat flag

### `[SHADY]` — Suspicious Network Analyzer
Scans for WiFi networks with behavioral red flags — rogue APs, PineAP pineapples, and evil twins.

- Suspicion scoring: **OPEN** network · **HIDDEN** SSID · **STRONG** signal · **BEACON SPAM** (special chars in SSID)
- **PineAP detection**: tracks BSSIDs broadcasting multiple different SSIDs (≥3 = flagged)
- Results sorted by suspicion score descending
- RGB LED flashes **yellow** when shady networks are found

### `[HASH]` — WPA Handshake & EAPOL Sniffer
Promiscuous capture of WPA2 handshake (EAPOL) frames with PCAP file output.

- Tracks beacons (AP MAC → SSID mapping) and EAPOL frames in real time
- Dual live graphs: packets/sec bar chart + RSSI/EAPOL/deauth dot graph
- Saves captured frames to SD card as standard libpcap files (`/hash{timestamp}.pcap`) — open in Wireshark
- Channel hops across all 13 channels every 500ms
- Footer shows last beacon SSID/MAC and last EAPOL SSID/MAC

### `[AP]` — CSI Ping Access Point *(Board 1)*
Turns this CYD into a soft access point that broadcasts WiFi packets for CSI-based presence detection.

- Creates AP: **SSID:** `CYD_CSI` · **Password:** `cydscanner123`
- Sends UDP broadcast pings at 50/sec (20ms interval) to keep CSI frame delivery flowing
- 40ms beacon interval for maximum CSI trigger frequency
- Shows connected client count and ping counter
- Used together with a second CYD running `[PRES]` mode

### `[PRES]` — Human Presence Detector *(Board 2)*
Connects to a `[AP]`-mode CYD and uses **WiFi Channel State Information (CSI)** variance to detect human presence.

- Measures how a human body disturbs the WiFi signal between the two devices
- Rolling 30-frame variance window updated every 100ms
- Three detection states: **`-- CLEAR`** · **`?? MAYBE`** · **`>> PRESENT`**
- Confidence bar (0–100%) with color coding
- CSI variance sparkline with threshold lines always visible
- Peak variance tracker (`PK:`) to help tune detection thresholds
- **Tap to calibrate**: 6-second countdown — tap, walk out of signal path, green LED flash = done
- **Tap again** to reset a bad calibration
- RGB LED: **red** = present · **yellow** = maybe · **off** = clear
- Logs presence events to SD card

---

## Presence Detection Setup

The `[AP]` + `[PRES]` modes work as a two-device system. **Both CYDs run the same firmware** — just select the mode you want.

### How it works
The AP device sends constant WiFi packets. A human body absorbs and reflects 2.4GHz WiFi significantly — the PRES device measures how the received signal changes (CSI variance) and infers whether someone is in the signal path.

> **Important:** This detects **movement**, not static presence. Someone sitting perfectly still will eventually read as CLEAR. Walking through the signal path reliably triggers detection.

### Placement
- Put the two devices **on opposite sides** of the area you want to monitor, facing each other
- **3–15 feet apart** is the sweet spot
- Line of sight is ideal but not required — works through walls with reduced sensitivity
- Avoid placement near metal, fish tanks, microwaves, or anything that moves on its own
- For whole-home coverage in a small space: AP in center, multiple PRES devices around the perimeter

### Calibration
1. Let the PRES device connect and wait for `FR` to stabilize (~10–20/s)
2. **Tap the screen** — display shows `LEAVE ROOM — calibrating in 6s...`
3. Step out of the signal path (or to the side) during the countdown
4. Green LED flash = calibration complete — the empty-room baseline is now set
5. Walk back through the signal path — confidence should rise
6. **Tap again** at any time to reset a bad calibration and start over

### Tuning
The detection thresholds are defined at the top of `main.cpp`:

```cpp
#define CSI_VAR_LO   3.0f  // variance below this → empty room (0% confidence)
#define CSI_VAR_HI   6.0f  // variance above this → definitely present (100% confidence)
```

Watch the `PK:` (peak variance) value on the PRES display while moving around. Set `CSI_VAR_HI` to roughly your observed peak. Set `CSI_VAR_LO` to the idle variance when the room is empty.

---

## UI Layout

```
┌──────────────────────────────────────────────┐
│  [MODE]  •  status / count / info            │  ← Header (20px)
├──────────────────────────────────────────────┤
│                                              │
│              mode content                    │  ← Body
│                                              │
├──────────────────────────────────────────────┤
│ SCAN│PROBE│CHAN│DAUTH│BLE│SHADY│HASH│AP│PRES │  ← Footer touch bar
└──────────────────────────────────────────────┘
```

- **Green-on-black** hacker terminal theme throughout
- Active mode tab highlighted with white text
- RGB LED (active LOW): red=deauth/present · blue=BLE · yellow=shady/maybe · green=calibration done

---

## Hardware Pinout

| Function | GPIO |
|----------|------|
| Display DC | 2 |
| Display CS | 15 |
| Display SCK | 14 |
| Display MOSI | 13 |
| Display MISO | 12 |
| Backlight | 21 |
| Touch CLK | 25 |
| Touch MISO | 39 |
| Touch MOSI | 32 |
| Touch CS | 33 |
| Touch IRQ | 36 |
| RGB LED R | 4 (active LOW) |
| RGB LED G | 16 (active LOW) |
| RGB LED B | 17 (active LOW) |
| SD SCK | 18 |
| SD MISO | 19 |
| SD MOSI | 23 |
| SD CS | 5 |

---

## SD Card Logging

If an SD card is present (FAT32 formatted), all scan events are appended to `/cydscan.txt`:

```
[SCAN] SSID:"PsyClock" CH:01 RSSI:-30  WPA2 b4:fb:e4:xx:xx:xx
[PROBE] MAC:AA:BB:CC:DD:EE:FF SSID:"MyHomeNetwork"
[DEAUTH] BSSID:AA:BB:CC:DD:EE:FF rate:8.3/s total:25
[BLE] NAME:HC-08 MAC:aa:bb:cc:dd:ee:ff RSSI:-55 SKIMMER
[SHADY] SSID:"FreeWiFi" score:3 flags:OPEN,STRONG,HIDDEN
[HASH EAPOL] SSID:"HomeNet" BSSID:XX:XX:XX:XX:XX:XX EAPOL#15
[PRES] var:4.50 conf:50 rssi:-53
```

HASH mode also saves PCAP files (`/hash{timestamp}.pcap`) openable in Wireshark.

SD card is optional — the scanner runs fully without one.

---

## Build & Flash

**Requirements:** PlatformIO (VS Code extension or CLI)

```bash
# Build standard firmware
cd CYDWiFiScanner
pio run

# Flash (CYD connected via USB)
pio run --target upload

# Build inverted display firmware
cd InvertedCYDWifiScanner
pio run --target upload

# Monitor serial output (115200 baud)
pio device monitor
```

**platformio.ini highlights:**
- `board_build.partitions = huge_app.csv` — required for BLE (3MB app partition)
- `board_build.f_cpu = 240000000L` — full 240MHz for responsive UI
- BLE enabled via `-DCONFIG_BT_ENABLED=1 -DCONFIG_BLUEDROID_ENABLED=1`

---

## Known Issues & Notes

### ⚠️ First Boot: Switch Away from SCAN Before Using It
On first flash or cold boot, **tap any other mode first** (e.g. PROBE, CHAN) and then return to SCAN. Going straight into SCAN immediately after boot can cause a crash/reboot. This is a known quirk of the WiFi stack initialization timing — harmless.

### ⚠️ PRES Mode: RSSI -81 or Lower
If RSSI on the PRES device is below -70, move the two devices closer together. Weak signal degrades CSI quality and reduces detection sensitivity. Target -40 to -60 dBm for best results.

---

## External IPEX Antenna Mod (CYD)

This CYD board ships with the RF path set to the onboard PCB antenna.
To use the IPEX (u.FL) connector, **move the 0Ω RF selector resistor** from the PCB-antenna pad to the IPEX pad.

> ⚠️ Only one antenna path should be connected at a time — do not bridge both pads.

An external antenna improves WiFi and BLE scan range significantly, which directly benefits all modes including presence detection.

---

## Project History

| Version | Description |
|---------|-------------|
| **Jan 2026** (`OriginalPredDetectorJan2026/`) | Original ESP32-2432S028 predator detection — BLE skimmer hunter, shady WiFi analyzer, PineAP detection |
| **Mar 2026** (current `src/`) | Full rewrite: 9-mode scanner, WPA handshake capture, PCAP logging, WiFi CSI presence detection (AP + PRES modes), calibration countdown, inverted display variant |

The `OriginalPredDetectorJan2026/` folder is preserved as the pre-merge reference.

---

## Legal Notice

This tool is intended for **educational and authorized security research purposes only**. Only use on networks and devices you own or have explicit permission to test. Passive scanning (SCAN, PROBE, CHAN, BLE) is generally legal; active interference is not. The authors assume no responsibility for misuse.
