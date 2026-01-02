# AntiPredCYD Security Framework v1.2.9

A comprehensive security detection framework for the ESP32-2432S028 (ESP32 CYD) designed to detect and alert on various predatory wireless attacks.

## Features

### Main Detection Modules
- **Deauth Hunter** - Detects WiFi deauthentication attacks and jamming attempts
- **Shady WiFi Scanner** - Identifies suspicious WiFi networks, beacon spam, evil twins, and rogue access points
- **BLE/Card Skimmer Hunter** - Scans for suspicious Bluetooth devices including potential card skimmers
- **Credential Harvester Alert** - Detects WiFi handshake capture attempts and credential harvesting activities
- **All Available Networks** - Simple network scanner showing all detected WiFi networks with signal strength

### Additional Features
- **Export Logs** - Export detected threat data to SD card in CSV format
- **System Stats** - Display system information and hardware status
- **Matrix Screensaver** - WiFi signal-based matrix effect screensaver
- **About/Info** - Project information and version details

## Hardware Requirements

- ESP32-2432S028 (ESP32 CYD) board
- MicroSD card (recommended for logging)
- Touch screen interface included with board

## Installation

1. Install PlatformIO IDE or PlatformIO Core
2. Clone/download this project
3. Open project in PlatformIO
4. Build and upload to your ESP32-2432S028

```bash
pio run -t upload
```

## Hardware Configuration

The project is pre-configured for ESP32-2432S028 with:
- 320x240 TFT Display (ILI9341)
- Resistive Touch Screen (XPT2046)
- SD Card support
- WiFi and Bluetooth capabilities

## SD Card Logging

When an SD card is inserted, the system automatically logs:
- Suspicious WiFi networks with timestamps
- BLE threat detections
- Credential harvesting alerts
- System events

Logs are stored in CSV format for easy analysis.

## Usage

1. Power on the device
2. Use touch interface to navigate between detection modules
3. Each scanner runs independently and displays real-time results
4. Access "More Options" for system utilities and log export
5. All threat detections are automatically logged when SD card is present

## Detection Capabilities

### WiFi Threats
- Beacon spam attacks
- Evil twin access points
- Rogue AP detection
- Security downgrade attacks
- Deauthentication floods
- Handshake capture attempts
- PMKID harvesting

### Bluetooth Threats
- Suspicious BLE devices
- Potential card skimmers
- Unknown device detection
- Signal strength analysis

## Project Structure

```
AntiPred1.2.9/
├── src/
│   └── main.cpp          # Main application code
├── platformio.ini        # PlatformIO configuration
└── README.md            # This file
```

## Development

This project was developed as an anti-predator security tool to help identify wireless-based attacks in public spaces, hotels, cafes, and other environments where predatory WiFi attacks commonly occur.

### Key Design Principles
- Real-time threat detection
- Low false positive rate
- Clear threat classification
- Comprehensive logging
- User-friendly interface

## Legal Notice

This tool is designed for defensive security purposes only. Users are responsible for compliance with local laws and regulations regarding wireless monitoring and security testing.

## Version History

- v1.2.9 - Complete security framework with SD logging
- v1.2.x - Added matrix screensaver and system utilities  
- v1.1.x - Enhanced BLE and WiFi detection displays
- v1.0.x - Initial framework with basic detection modules

## License

This project is released under MIT License for educational and defensive security purposes.

## Contributing

Contributions welcome for additional detection modules, UI improvements, and optimization for ESP32 platform constraints.

---

*Built for ESP32-2432S028 CYD - New Year's Security Project 2025*