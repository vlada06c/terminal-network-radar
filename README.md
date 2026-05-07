# Network Radar

Terminal network activity visualizer with a radar-style `curses` UI.

## What It Does

- Captures per-host packet activity with raw sockets when run as root
- Falls back to `ss` and `/proc`-based connection sampling without root
- Supports simulated traffic for development and quick demos
- Includes a headless mode for smoke testing without the full UI

## Run It

Simulated UI:

```bash
python3 radar.py --simulate
```

Simulated headless check:

```bash
python3 radar.py --simulate --headless --frames 5
```

Live mode:

```bash
sudo python3 radar.py
```

Live mode on a specific interface:

```bash
sudo python3 radar.py --iface wlan0
```

## Useful Flags

- `--iface`: bind the packet sniffer to one interface
- `--scale`: change how far hosts appear from the center
- `--interval`: sampling interval in seconds
- `--simulate`: generate fake traffic instead of reading the host network
- `--hosts`: number of simulated hosts
- `--max-rate`: max simulated packet rate
- `--theme`: color theme for the UI
- `--bg-color`: override background color
- `--fg-color`: override text color
- `--verbose`: enable debug logging
- `--headless`: print samples instead of launching `curses`
- `--frames`: number of headless samples to print

## Controls

- `q`: quit
- `p`: pause or resume sampling
- `+` / `-`: change radar scale
- `r`: reset tracked state
- `h`: open help

## Project Layout

- `radar.py`: CLI entrypoint and startup flow
- `display.py`: `curses` rendering and keyboard handling
- `collectors.py`: raw packet sniffer, `ss` fallback, and simulator
- `engine.py`: sampling and smoothing logic
- `helpers.py`: shared utility helpers
- `settings.py`: runtime tuning defaults

## Notes

- Root mode gives better packet-level visibility.
- Non-root mode estimates activity from connection counts and interface packet deltas.
- No external runtime dependency is required for the current code path.

## Quick Verification

```bash
python3 -m py_compile radar.py settings.py helpers.py collectors.py engine.py display.py
python3 radar.py --simulate --headless --frames 2
```
