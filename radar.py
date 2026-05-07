import logging
import argparse
import curses
import sys
import threading
import time

from collectors import ConnectionScanner, PacketSniffer, SimulationCollector
from display import main_curses
from engine import collect_sample
from helpers import get_iface_operstate, is_root
from settings import RadarSettings


def parse_args():
    parser = argparse.ArgumentParser(description="Network Radar - terminal visualization")
    parser.add_argument("--iface", help="Network interface to bind raw sniffer")
    parser.add_argument("--scale", type=float, default=1.0, help="Distance scale for mapping")
    parser.add_argument("--interval", type=float, default=0.5, help="Sampling interval (s)")
    parser.add_argument("--simulate", action="store_true", help="Run in simulated traffic mode")
    parser.add_argument("--hosts", type=int, default=12, help="Number of simulated hosts")
    parser.add_argument("--max-rate", type=int, default=200, help="Max simulated packet rate")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--theme", type=str, default="default", help="Color theme name")
    parser.add_argument("--bg-color", type=str, default=None, help="Background color name")
    parser.add_argument("--fg-color", type=str, default=None, help="Foreground/text color name")
    parser.add_argument("--headless", action="store_true", help="Run sampling loop without curses")
    parser.add_argument("--frames", type=int, default=5, help="Number of samples to print in headless mode")
    return parser.parse_args()


def build_settings(args) -> RadarSettings:
    return RadarSettings(sample_interval=args.interval, default_scale=args.scale)


def build_collectors(args, settings: RadarSettings):
    if args.simulate:
        sniffer = SimulationCollector(settings, hosts=args.hosts, max_rate=args.max_rate)
        return sniffer, sniffer
    sniffer = PacketSniffer(settings, iface=args.iface) if is_root() else None
    scanner = ConnectionScanner(settings, iface=args.iface)
    return sniffer, scanner


def run_headless(args, settings: RadarSettings, sniffer=None, scanner=None):
    mode = "SNIF" if (sniffer and sniffer._supported) else "SS"
    smoothing = {}
    proto_map = {}
    iface_state = get_iface_operstate(getattr(args, "iface", None))
    if sniffer and isinstance(sniffer, threading.Thread) and sniffer._supported:
        sniffer.start()
    try:
        if args.iface and iface_state:
            print(f"iface={args.iface} state={iface_state}")
        elif args.iface:
            print(f"iface={args.iface} state=unknown")
        for frame in range(max(1, args.frames)):
            rates, protos, meta = collect_sample(mode, sniffer, scanner, smoothing, proto_map, settings)
            print(
                f"[sample {frame + 1}/{max(1, args.frames)}] "
                f"mode={mode} collector={meta.get('collector')} "
                f"hosts={meta.get('sampled_hosts', 0)} "
                f"pkt_delta={int(meta.get('pkt_delta', 0))} "
                f"conns={int(meta.get('total_conns', 0))}"
            )
            error = meta.get("ss_error")
            if error:
                print(f"  ss_error: {error}")
            top_hosts = sorted(rates.items(), key=lambda item: item[1], reverse=True)[:5]
            if not top_hosts:
                print("  no active hosts detected")
            for ip, rate in top_hosts:
                proto = protos.get(ip, proto_map.get(ip, "UNK"))
                print(f"  {ip:39} {proto:3} {rate:8.1f} pkt/s")
            if frame < max(1, args.frames) - 1:
                time.sleep(max(0.05, settings.sample_interval))
    finally:
        if sniffer and hasattr(sniffer, "stop"):
            sniffer.stop()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    settings = build_settings(args)
    sniffer, scanner = build_collectors(args, settings)

    if args.headless:
        run_headless(args, settings, sniffer=sniffer, scanner=scanner)
        return

    try:
        curses.wrapper(lambda screen: main_curses(screen, args, settings, sniffer=sniffer, scanner=scanner))
    except Exception:
        logging.exception("ERROR initializing curses")
        print("Run with --simulate for non-root testing or run as root for sniffer mode")
        sys.exit(1)


if __name__ == "__main__":
    main()
