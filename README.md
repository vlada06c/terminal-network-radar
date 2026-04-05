# Network Radar

Terminal-based network activity visualizer (radar-like).

Features
- Real sniffer using AF_PACKET raw sockets (requires root) or fallback `ss` + /proc/net/dev
- Simulated traffic mode for development and CI (`--simulate`)
- Configurable sampling, scale and visual options via CLI
- Headless sampling mode for testing without `curses`

Quick start

Run simulated (no root):

```bash
python3 radar.py --simulate
```

Run headless for quick verification:

```bash
python3 radar.py --simulate --headless --frames 5
```

Run live (recommended run as root for per-IP packet rates):

```bash
sudo python3 radar.py
```

CLI options
- `--iface`: interface to bind raw sniffer
- `--scale`: distance scale for mapping
- `--interval`: sampling interval (s)
- `--simulate`: use synthetic traffic
- `--hosts`: simulated host count
- `--max-rate`: simulated max packet rate
- `--verbose`: enable verbose logging
- `--headless`: print samples without launching curses
- `--frames`: number of samples to emit in headless mode

Repository readiness
- `radar.py` is the main entrypoint.
- Add tests and CI as needed; use `--simulate` in CI to validate render loop without root.

License: Add your preferred open-source license.
