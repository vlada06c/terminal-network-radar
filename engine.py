from helpers import simulated_proto_for_ip
from settings import RadarSettings


def smooth_rates(
    smoothing: dict[str, float], rates: dict[str, float], settings: RadarSettings
) -> dict[str, float]:
    smoothed: dict[str, float] = {}
    for ip, rate in rates.items():
        previous = smoothing.get(ip, rate)
        current = previous * (1.0 - settings.smooth_alpha) + rate * settings.smooth_alpha
        smoothing[ip] = current
        smoothed[ip] = current
    for ip in list(smoothing.keys()):
        if ip in rates:
            continue
        smoothing[ip] *= settings.decay_rate
        if smoothing[ip] < 0.01:
            del smoothing[ip]
    return smoothed


def collect_sample(
    mode: str,
    sniffer,
    scanner,
    smoothing: dict[str, float],
    proto_map: dict[str, str],
    settings: RadarSettings,
) -> tuple[dict[str, float], dict[str, str], dict[str, int | str | None]]:
    if mode == "SNIF" and sniffer and sniffer._supported:
        raw = sniffer.snapshot_and_reset()
        rates = {
            ip: count / max(0.0001, settings.sample_interval)
            for ip, count in raw.items()
        }
        meta = {
            "pkt_delta": sum(raw.values()),
            "total_conns": len(raw),
            "ss_error": None,
            "collector": "simulation" if getattr(sniffer, "_simulated", False) else "sniffer",
            "sampled_hosts": len(raw),
        }
        if getattr(sniffer, "_simulated", False):
            protos = {ip: simulated_proto_for_ip(ip) for ip in rates}
        else:
            protos = {ip: proto_map.get(ip, "UNK") for ip in rates}
    else:
        ip_stats, meta = scanner.snapshot()
        total_connections = int(meta.get("total_conns", 0) or 1)
        rates: dict[str, float] = {}
        protos: dict[str, str] = {}
        for ip, details in ip_stats.items():
            connections = int(details.get("connections", 0))
            rates[ip] = (
                (connections / total_connections)
                * (int(meta.get("pkt_delta", 0)) / max(0.0001, settings.sample_interval))
            )
            protos[ip] = str(details.get("proto", "UNK"))
    smoothed = smooth_rates(smoothing, rates, settings)
    for ip, proto in protos.items():
        proto_map[ip] = proto
    meta["sampled_hosts"] = len(rates)
    return smoothed, protos, meta
