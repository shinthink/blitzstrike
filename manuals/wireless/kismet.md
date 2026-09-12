# kismet

- **Category**: Wireless / Passive Reconnaissance
- **Risk Level**: 🟡 Medium

---

## Description

Kismet is a powerful wireless network detector, sniffer, and intrusion detection system (WIDS). Compared to airodump-ng, Kismet supports more protocols (802.11 a/b/g/n/ac/ax, Bluetooth, Zigbee, etc.), provides a Web UI, supports GPS logging and map visualization, and can passively capture traffic without transmitting any packets (completely covert). Commonly used for large-scale wireless reconnaissance and RF environment analysis.

## Installation

```bash
sudo apt install kismet

# Build from source (latest version)
sudo apt install build-essential git libwebsockets-dev pkg-config \
    zlib1g-dev libnl-3-dev libnl-genl-3-dev libcap-dev \
    libpcap-dev libnm-dev libdw-dev libsqlite3-dev libprotobuf-dev \
    libprotobuf-c-dev protobuf-compiler protobuf-c-compiler \
    libsensors4-dev libusb-1.0-0-dev python3 python3-setuptools python3-protobuf \
    python3-requests python3-numpy python3-serial python3-usb python3-paho-mqtt
git clone https://github.com/kismetwireless/kismet.git
cd kismet
./configure
make -j$(nproc)
sudo make install
```

## Parameter Reference

### Command-Line Parameters

| Parameter | Description |
|------|------|
| `-c <source>` | Use the specified datasource |
| `--no-ncurses` | Disable server console wrapper |
| `-f <config>` | Use alternate configuration file |
| `--override <flavor>` | Load an alternate configuration override from `kismet_<flavor>.conf` |
| `--homedir <dir>` | Use an alternate path as the home directory |
| `--confdir <dir>` | Use an alternate path as the base config directory |
| `--log-prefix <prefix>` | Directory to store log files |
| `--log-types <types>` | Override activated log types |
| `--no-logging` | Disable all logging |
| `-t <title>` | Override default log title |

### Configuration File Options (kismet.conf)

| Parameter | Description |
|--------|------|
| `source=wlan0:name=wifi` | Capture source definition |
| `httpd_username=admin` | Web UI username |
| `httpd_password=password` | Web UI password |
| `gps=gpsd:host=localhost,port=2947` | GPS configuration |
| `channel_hop=true` | Enable channel hopping |
| `channel_hop_speed=5/sec` | Hopping speed |
| `log_prefix=/tmp/kismet` | Log path |

## Common Commands

### Scenario 1: Basic Startup

```bash
# Basic interactive startup (recommended)
sudo kismet -c wlan0

# Specify capture source and start
sudo kismet -c wlan0:name=wifi,type=linuxwifi

# Run in background (use --no-ncurses and system service, or nohup)
sudo kismet --no-ncurses -c wlan0 &

# Access Web UI: http://localhost:2501
# No default username/password; create credentials on first run
```

### Scenario 2: Monitor with Multiple Interfaces

```bash
# Use multiple adapters simultaneously (better coverage)
sudo kismet -c wlan0 -c wlan1

# Assign different frequency bands to each
sudo kismet -c wlan0:channels="1,6,11" -c wlan1:channels="36,40,44,48"
```

### Scenario 3: GPS Integration

```bash
# Install and start gpsd
sudo apt install gpsd
sudo gpsd /dev/ttyUSB0 -F /var/run/gpsd.sock

# Start kismet (auto-detects gpsd)
sudo kismet -c wlan0

# Once enabled, kismet records GPS coordinates for each AP
```

### Scenario 4: Save pcap Only, No UI

```bash
# Headless mode, log only
sudo kismet -c wlan0 --no-ncurses

# Logs are saved by default to ~/kismet-*.kismet (SQLite format)
# pcap files are saved to ~/kismet-*.pcapng
# Note: Actual filename uses a timestamp, e.g.: Kismet-20240101-00-00-00-1.kismet

# After stopping, view log data
kismetdb_dump_devices --in Kismet-20240101-*.kismet
```

### Scenario 5: Using the REST API

```bash
# Kismet provides a full REST API
# Get all device list
curl -u kismet:password http://localhost:2501/devices/all_devices.json | jq .
# Note: In newer Kismet versions, this endpoint may require POST with JSON body:
# curl -u kismet:password -X POST http://localhost:2501/devices/all_devices.json -d '{"fields":["kismet.device.base.macaddr","kismet.device.base.name"]}' | jq .

# Get information about a specific device
curl -u kismet:password http://localhost:2501/devices/by-mac/AA:BB:CC:DD:EE:FF/device.json

# Real-time event stream (WebSocket endpoint — requires a WebSocket client)
# Use websocat (install: cargo install websocat) or a browser:
# websocat -n ws://kismet:password@localhost:2501/eventbus/events.ws
# Note: plain curl http:// cannot properly connect to a WebSocket stream endpoint
```

### Scenario 6: kismetdb Log Analysis

```bash
# Install Python tools
pip3 install kismetdb

# Export all APs (outputs JSON by default)
kismetdb_dump_devices --in Kismet-20240101-00-00-00-1.kismet

# Export to a JSON file
kismetdb_dump_devices --in Kismet-20240101-00-00-00-1.kismet --out devices.json

# Use ekjson format (one device per line, suitable for parsing with jq)
kismetdb_dump_devices --in Kismet-20240101-00-00-00-1.kismet --ekjson --out devices.json

# Extract captured packets to pcap
kismetdb_to_pcap --in Kismet-20240101-00-00-00-1.kismet --out capture.pcap
```

## Notes & Tips

1. Kismet is entirely passive and transmits no packets, making it suitable for covert reconnaissance
2. The Web UI listens on `localhost:2501` by default; set `httpd_bind_address=0.0.0.0` in `kismet.conf` for remote access
3. Log files are in SQLite format (.kismet) and can be analyzed with the Python kismetdb library
4. 802.11ax (Wi-Fi 6) support requires a newer version and a compatible adapter
5. When running with multiple interfaces, different adapters can be assigned to different frequency bands for efficiency
6. The Web UI password must be set on the first run; credentials are stored in `~/.kismet/kismet_httpd.conf`

---

## Official References

- [Kismet Official Site](https://www.kismetwireless.net/)
- [Kismet (GitHub)](https://github.com/kismetwireless/kismet)
- [Kismet Documentation](https://www.kismetwireless.net/docs/readme/)
