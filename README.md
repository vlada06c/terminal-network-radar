# Network Radar

Network Radar is a small terminal app that turns live network activity into a radar-style view with a simple `curses` interface.

It is not trying to replace Wireshark or become a full packet analysis suite. The point is to give you a fast, visual feel for what your machine is doing: which hosts are active, when something suddenly spikes, and how traffic shifts over time.

## What It Can Do

- show active hosts in a live radar view
- run in raw packet sniffer mode when started as root
- fall back to `ss` and `/proc`-based estimates when root access is not available
- run in simulation mode for demos, testing, or development
- let you tweak the look with themes and manual foreground/background colors
- run headless when you just want to verify sampling without opening the UI

## Quick Start

Run the simulated UI:

```bash
python3 radar.py --simulate
```

Run a short headless check:

```bash
python3 radar.py --simulate --headless --frames 5
```

Run against live traffic:

```bash
sudo python3 radar.py
```

Target a specific interface:

```bash
sudo python3 radar.py --iface wlan0
```

## Customization

Try a built-in theme:

```bash
python3 radar.py --simulate --theme neon
```

Override the colors directly:

```bash
python3 radar.py --simulate --bg-color black --fg-color green
```

Make the radar feel tighter or faster:

```bash
python3 radar.py --simulate --scale 1.4 --interval 0.25
```

## Useful Flags

- `--iface` binds the sniffer to a specific interface
- `--scale` moves hosts closer to or farther from the center
- `--interval` changes the sampling interval
- `--simulate` generates fake traffic
- `--hosts` sets how many simulated hosts to create
- `--max-rate` controls simulated traffic intensity
- `--theme` selects a built-in color theme
- `--bg-color` overrides the background color
- `--fg-color` overrides the main text color
- `--verbose` enables debug logging
- `--headless` prints samples instead of launching the UI
- `--frames` controls how many headless samples to print

## Controls

- `q` quit
- `p` pause or resume sampling
- `+` / `-` increase or decrease scale
- `r` reset the current tracked state
- `h` open the help screen

## How It Works

When the app runs as root, it uses a raw socket sniffer and gives you a much better picture of actual packet activity per host.

When it runs without root, it switches to a fallback collector built on `ss`, `/proc/net/*`, and interface packet counters. That mode is less precise, but still useful when you want a quick picture of what is happening.

There is also a simulation collector, which makes it easy to work on the UI and sampling flow without needing real traffic at the time.

## Project Layout

- `radar.py` handles startup, CLI parsing, and mode selection
- `display.py` contains the `curses` UI, rendering, and keyboard controls
- `collectors.py` contains the packet sniffer, fallback scanner, and simulator
- `engine.py` contains sampling and smoothing logic
- `helpers.py` contains shared utility functions
- `settings.py` contains runtime defaults

## Quick Verification

```bash
python3 -m py_compile radar.py settings.py helpers.py collectors.py engine.py display.py
python3 radar.py --simulate --headless --frames 2
```
