
import argparse
import curses
import ipaddress
import math
import time
import threading
import socket
import struct
import subprocess
import sys
import os
import random
import logging
from collections import defaultdict, deque, Counter
from typing import Optional

# ---------------------------
# Config
# ---------------------------
REFRESH = 0.05            # main draw refresh (s)
SAMPLE_INTERVAL = 0.5     # network sampling aggregation window (s)
DECAY_RATE = 0.88         # per-sample decay for display intensity (0..1)
SMOOTH_ALPHA = 0.4        # EMA alpha for packet rate smoothing
MAX_BLIP_SIZE = 3         # visual max size of a blip
DEFAULT_SCALE = 1.0       # distance scaling for mapping "connections" to radius
HISTORY_LENGTH = 40       # number of previous frames for trails
MIN_TERMINAL_SIZE = (24, 80)
SWEEP_LENGTH_DEG = 30     # angular width of the sweep beam
TRAIL_OPACITY = 0.9       # multiplier for trail visibility

# ---------------------------
# Utilities
# ---------------------------

def is_root():
    return os.geteuid() == 0

def clamp(v, a, b):
    return max(a, min(b, v))

def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def hash_ip_angle(ip):
    """Deterministic mapping IP -> angle (radians). Supports IPv4 and IPv6 via ipaddress."""
    try:
        a = ipaddress.ip_address(ip)
        b = int.from_bytes(a.packed, 'big', signed=False)
        x = b
        x = ((x >> 16) ^ x) * 0x45d9f3b
        x = ((x >> 16) ^ x) * 0x45d9f3b
        x = (x >> 16) ^ x
        return (x % 360) * (math.pi / 180.0)
    except Exception:
        return 0.0

def nice_ip_display(ip):
    return ip

def merge_proto(existing, new_proto):
    if not existing or existing == 'UNK':
        return new_proto
    if existing == new_proto:
        return existing
    return 'MIX'

def parse_ss_endpoint(endpoint):
    endpoint = (endpoint or '').strip()
    if not endpoint or endpoint in ('*', '-'):
        return None
    if endpoint.startswith('['):
        host = endpoint[1:].split(']', 1)[0]
    else:
        host = endpoint.rsplit(':', 1)[0] if ':' in endpoint else endpoint
    if '%' in host:
        host = host.split('%', 1)[0]
    if host.startswith('::ffff:'):
        host = host.split('::ffff:', 1)[1]
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None
    if addr.is_unspecified:
        return None
    return str(addr)

def normalize_error_text(text):
    if not text:
        return None
    return " | ".join(part.strip() for part in str(text).splitlines() if part.strip()) or None

def get_iface_operstate(iface):
    if not iface:
        return None
    try:
        with open(f'/sys/class/net/{iface}/operstate', 'r') as f:
            return f.read().strip()
    except Exception:
        return None

def simulated_proto_for_ip(ip):
    try:
        last_octet = int(str(ip).rsplit('.', 1)[-1])
    except Exception:
        return 'UNK'
    return 'TCP' if last_octet % 2 else 'UDP'

# color utility
def color_name_to_const(name: Optional[str]):
    if not name:
        return -1
    name = str(name).strip().lower()
    mapping = {
        'black': curses.COLOR_BLACK,
        'red': curses.COLOR_RED,
        'green': curses.COLOR_GREEN,
        'yellow': curses.COLOR_YELLOW,
        'blue': curses.COLOR_BLUE,
        'magenta': curses.COLOR_MAGENTA,
        'cyan': curses.COLOR_CYAN,
        'white': curses.COLOR_WHITE,
        'default': -1,
    }
    if name in mapping:
        return mapping[name]
    try:
        # allow numeric codes
        return int(name)
    except Exception:
        return -1

# ---------------------------
# Network data collectors
# ---------------------------

class PacketSniffer(threading.Thread):
    """If running as root: capture packets on AF_PACKET and count per-IP packet rate."""
    def __init__(self, iface=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.running = threading.Event()
        self.running.set()
        self.lock = threading.Lock()
        self.counter = Counter()
        self.last_ts = time.time()
        self.local_addrs = set(self._get_local_ips())
        # small queue for recent events for smoothing
        self._queue = deque()
        self._supported = True
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if iface:
                self.sock.bind((iface, 0))
        except PermissionError:
            self._supported = False
        except Exception as e:
            # Some systems may not allow raw sockets
            self._supported = False

    def _get_local_ips(self):
        """Return list of local IPv4 addresses (simple heuristic)."""
        addrs = []
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(socket.gethostname(), None):
                if fam == socket.AF_INET:
                    addrs.append(sockaddr[0])
        except:
            pass
        # also read from /proc/net/fib_trie or use socket trick
        # fallback: 127.0.0.1
        if not addrs:
            addrs.append("127.0.0.1")
        return addrs

    def run(self):
        if not self._supported:
            return
        # non-blocking recv
        self.sock.settimeout(1.0)
        while self.running.is_set():
            try:
                raw, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            # parse ethertype and IPv4 header only
            if len(raw) < 14 + 20:
                continue
            eth_proto = struct.unpack('!H', raw[12:14])[0]
            if eth_proto != 0x0800:  # IPv4 only
                continue
            # IP header begins at 14
            ip_header = raw[14:34]
            ver_ihl = ip_header[0]
            ihl = (ver_ihl & 0x0F) * 4
            if ihl < 20:
                continue
            src = socket.inet_ntoa(ip_header[12:16])
            dst = socket.inet_ntoa(ip_header[16:20])
            # choose remote IP relative to us: if src is local -> remote = dst; else remote = src
            remote = None
            if src in self.local_addrs:
                remote = dst
            elif dst in self.local_addrs:
                remote = src
            else:
                # neither matches local_addrs: heuristically pick src
                remote = src
            if not remote:
                continue
            with self.lock:
                self.counter[remote] += 1

    def snapshot_and_reset(self):
        """Return counter for last SAMPLE_INTERVAL and reset the internal counter, with smoothing"""
        with self.lock:
            data = dict(self.counter)
            self.counter.clear()
        return data

    def stop(self):
        self.running.clear()
        try:
            self.sock.close()
        except:
            pass


class SimulationCollector:
    """Simple simulator used for development and CI: mimics sniffer/scanner APIs."""
    def __init__(self, hosts=12, max_rate=200):
        self.hosts = hosts
        self.max_rate = max_rate
        self._hosts = [f"192.0.2.{i+1}" for i in range(hosts)]
        self._lock = threading.Lock()
        self._rng = random.Random(12345)
        # simulated packet counts accumulated since last snapshot
        self._counts = Counter()
        self._last = time.time()
        self._supported = True
        self._simulated = True

    def _tick(self):
        now = time.time()
        dt = max(0.001, now - self._last)
        self._last = now
        # randomly change rates
        for h in self._hosts:
            rate = abs(int(self._rng.gauss(self.max_rate/len(self._hosts), 5)))
            self._counts[h] += int(rate * dt)

    # sniffer API: snapshot_and_reset -> dict(ip -> count)
    def snapshot_and_reset(self):
        with self._lock:
            self._tick()
            data = dict(self._counts)
            self._counts.clear()
        return data

    # scanner API: snapshot -> (Counter, pkt_delta)
    def snapshot(self):
        with self._lock:
            self._tick()
            ip_stats = {}
            for ip, c in self._counts.items():
                ip_stats[ip] = {
                    'connections': max(1, int(c // max(1, len(self._hosts)))),
                    'proto': simulated_proto_for_ip(ip),
                }
            pkt_delta = sum(self._counts.values())
            # don't reset for scanner mode
        meta = {
            'pkt_delta': pkt_delta,
            'total_conns': sum(v['connections'] for v in ip_stats.values()),
            'ss_error': None,
            'collector': 'simulation',
        }
        return ip_stats, meta

class ConnectionScanner:
    """Non-root fallback: use `ss -ntu` and estimate per-IP activity from connection counts.
       Also compute global packet delta from /proc/net/dev to get a budget for weighting."""
    PROC_TABLES = (
        ('/proc/net/tcp', 'TCP', 4),
        ('/proc/net/udp', 'UDP', 4),
        ('/proc/net/tcp6', 'TCP', 16),
        ('/proc/net/udp6', 'UDP', 16),
    )

    def __init__(self, iface=None):
        self.iface = iface
        self.prev_iface_counts = None
        self.prev_ts = time.time()
        self.last_error = None

    def _read_proc_net_dev(self):
        lines = []
        try:
            with open('/proc/net/dev', 'r') as f:
                lines = f.readlines()
        except:
            return {}
        out = {}
        for line in lines[2:]:
            parts = line.strip().split()
            if len(parts) >= 17:
                ifname = parts[0].strip(':')
                if self.iface and ifname != self.iface:
                    continue
                rx_packets = int(parts[2])
                tx_packets = int(parts[10])
                out[ifname] = {'rx': rx_packets, 'tx': tx_packets}
        return out

    def _decode_proc_ip(self, hex_host, size):
        try:
            raw = bytes.fromhex(hex_host)
            if size == 4:
                raw = raw[::-1]
            else:
                raw = b''.join(raw[i:i+4][::-1] for i in range(0, len(raw), 4))
            return str(ipaddress.ip_address(raw))
        except Exception:
            return None

    def _read_proc_socket_tables(self):
        ip_stats = {}
        for path, proto, size in self.PROC_TABLES:
            try:
                with open(path, 'r') as f:
                    lines = f.readlines()[1:]
            except Exception:
                continue
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                remote = parts[2]
                hex_host = remote.split(':', 1)[0]
                ip = self._decode_proc_ip(hex_host, size)
                if not ip:
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if addr.is_unspecified:
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {'connections': 0, 'proto': proto}
                ip_stats[ip]['connections'] += 1
                ip_stats[ip]['proto'] = merge_proto(ip_stats[ip]['proto'], proto)
        return ip_stats

    def snapshot(self):
        # get connection counts via ss
        ip_stats = {}
        try:
            proc = subprocess.run(
                ['ss', '-H', '-n', '-t', '-u'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=1.0,
            )
            self.last_error = normalize_error_text(proc.stderr)
            out = proc.stdout.splitlines()
            for line in out:
                parts = line.split()
                if len(parts) < 5:
                    continue
                proto = parts[0].upper()
                if proto not in ('TCP', 'UDP'):
                    continue
                remote = parts[-1]
                ip = parse_ss_endpoint(remote)
                if not ip:
                    continue
                if ip not in ip_stats:
                    ip_stats[ip] = {'connections': 0, 'proto': proto}
                ip_stats[ip]['connections'] += 1
                ip_stats[ip]['proto'] = merge_proto(ip_stats[ip]['proto'], proto)
        except Exception:
            self.last_error = 'ss invocation failed'

        if not ip_stats:
            proc_ip_stats = self._read_proc_socket_tables()
            if proc_ip_stats:
                ip_stats = proc_ip_stats
                if self.last_error:
                    self.last_error = f"{self.last_error} | using /proc fallback"
                else:
                    self.last_error = 'using /proc fallback'

        # get packet delta across interfaces
        now = time.time()
        cur = self._read_proc_net_dev()
        pkt_delta = 0
        if self.prev_iface_counts is not None:
            dt = max(0.001, now - self.prev_ts)
            for iface, v in cur.items():
                prev = self.prev_iface_counts.get(iface)
                if prev:
                    drx = v['rx'] - prev['rx']
                    dtx = v['tx'] - prev['tx']
                    if drx < 0: drx = 0
                    if dtx < 0: dtx = 0
                    pkt_delta += (drx + dtx)
            # pkt_delta per SAMPLE_INTERVAL (may be scaled by dt)
        # update saved
        self.prev_iface_counts = cur
        self.prev_ts = now

        meta = {
            'pkt_delta': pkt_delta,
            'total_conns': sum(v['connections'] for v in ip_stats.values()),
            'ss_error': self.last_error,
            'collector': 'ss',
        }
        return ip_stats, meta

# ---------------------------
# Radar display
# ---------------------------

class Radar:
    def __init__(self, stdscr, sniffer: PacketSniffer=None, scanner: ConnectionScanner=None, theme: str = 'default', bg_color: Optional[str]=None, fg_color: Optional[str]=None):
        self.stdscr = stdscr
        self.sniffer = sniffer
        self.scanner = scanner
        self.running = True
        self.paused = False
        self.scale = DEFAULT_SCALE
        self.smoothing = {}
        self.proto_map = {}
        self.intensity = defaultdict(float)   # intensity for decay/trail
        self.history = defaultdict(lambda: deque(maxlen=HISTORY_LENGTH))
        self.last_sample_time = time.time()
        self.mode = 'SNIF' if (sniffer and sniffer._supported) else 'SS'
        self.last_meta = {
            'pkt_delta': 0,
            'total_conns': 0,
            'ss_error': None,
            'collector': 'sniffer' if self.mode == 'SNIF' else 'ss',
            'sampled_hosts': 0,
        }
        self.angle = 0.0
        self.sweep_speed = 120.0  # degrees per second
        self.sweep_length = SWEEP_LENGTH_DEG
        self.controls_text = "q:quit p:pause +/- scale r:reset h:help"
        # curses color palette
        curses.use_default_colors()
        curses.start_color()
        # theme handling: allow simple named themes and override via bg/fg
        try:
            # basic named palettes
            themes = {
                'default': {
                    'sweep': ('green', 'default'), 'udp': ('cyan', 'default'), 'tcp': ('yellow', 'default'),
                    'high': ('red', 'default'), 'unknown': ('magenta', 'default'), 'text': ('white', 'default'), 'bg':'black'
                },
                'neon': {
                    'sweep': ('green', 'black'), 'udp': ('cyan', 'black'), 'tcp': ('yellow', 'black'),
                    'high': ('magenta', 'black'), 'unknown': ('blue', 'black'), 'text': ('white', 'black'), 'bg':'black'
                },
                'solarized': {
                    'sweep': ('blue', 'black'), 'udp': ('cyan', 'black'), 'tcp': ('yellow', 'black'),
                    'high': ('red', 'black'), 'unknown': ('magenta', 'black'), 'text': ('white', 'black'), 'bg':'black'
                }
            }
            palette = themes.get(theme, themes['default'])
            # allow CLI overrides
            if bg_color:
                palette['bg'] = bg_color
            if fg_color:
                palette['text'] = (fg_color, palette.get('text', ('white','default'))[1])

            # initialize color pairs with mapping
            def pair(n, fg_name, bg_name=None):
                fg = color_name_to_const(fg_name)
                bg = -1 if bg_name is None else color_name_to_const(bg_name)
                try:
                    curses.init_pair(n, fg, bg)
                except Exception:
                    try:
                        curses.init_pair(n, fg, -1)
                    except Exception:
                        pass

            pair(1, palette['sweep'][0], palette.get('bg'))
            pair(2, palette['udp'][0], palette.get('bg'))
            pair(3, palette['tcp'][0], palette.get('bg'))
            pair(4, palette['high'][0], palette.get('bg'))
            pair(5, palette['unknown'][0], palette.get('bg'))
            pair(6, palette['text'][0], palette.get('bg'))
        except Exception:
            pass
        # glyphs with basic ASCII fallback
        try:
            '•'.encode('utf-8')
            self.glyphs = {1: '•', 2: '●', 3: '◉'}
        except Exception:
            self.glyphs = {1: '.', 2: 'o', 3: 'O'}

        # starfield for background
        self._star_count = max(20, min(200, (self.stdscr.getmaxyx()[0] * self.stdscr.getmaxyx()[1]) // 300))
        self.stars = []
        h, w = self._get_term_size()
        for i in range(self._star_count):
            sx = random.randint(1, max(1, w-2))
            sy = random.randint(1, max(1, h-3))
            ch = random.choice(['.', '+', '*'])
            phase = random.random() * 2 * math.pi
            self.stars.append([sx, sy, ch, phase])

    def _get_term_size(self):
        h, w = self.stdscr.getmaxyx()
        return h, w

    def _draw_border_and_legend(self, cx, cy, radius, h, w):
        # Title
        title = f" NETWORK RADAR  — mode: {self.mode}  scale:{self.scale:.2f}  (root={is_root()}) "
        try:
            self.stdscr.addstr(0, max(0, (w - len(title))//2), title, curses.A_BOLD | curses.color_pair(6))
        except:
            pass
        # legend
        legends = [
            ("● small", "low"),
            ("● med", "med"),
            ("● big", "high"),
            ("TCP", "tcp"),
            ("UDP", "udp"),
        ]
        # Controls
        try:
            self.stdscr.addstr(h-2, 1, self.controls_text, curses.color_pair(6))
        except:
            pass
        # draw range rings
        for r in range(1, 4):
            rr = int(radius * r / 3)
            self._draw_circle(cx, cy, rr, char='.', attr=curses.color_pair(6))

    def _draw_status_panel(self, h, w):
        sample_age = max(0.0, time.time() - self.last_sample_time)
        hosts = len(self.smoothing)
        status_lines = [
            f"status: {'PAUSED' if self.paused else 'LIVE'}",
            f"sample age: {sample_age:4.1f}s",
            f"tracked hosts: {hosts}",
            f"pkt delta: {int(self.last_meta.get('pkt_delta', 0))}",
            f"connections: {int(self.last_meta.get('total_conns', 0))}",
            f"collector: {self.last_meta.get('collector', self.mode.lower())}",
        ]
        error = self.last_meta.get('ss_error')
        if error:
            status_lines.append(f"ss: {error[:28]}")
        starty = 2
        startx = 2
        try:
            self.stdscr.addstr(starty - 1, startx, " Status ", curses.A_BOLD | curses.color_pair(6))
            for idx, line in enumerate(status_lines):
                self.stdscr.addstr(starty + idx, startx, line[:30], curses.color_pair(6))
        except Exception:
            pass

    def _draw_circle(self, cx, cy, r, char='.', attr=0):
        # Bresenham circle-ish approximation in float for terminal
        if r <= 0:
            return
        step = max(6, int(6 * (r/6)))
        for a in range(0, 360, step):
            rad = math.radians(a)
            x = int(cx + r * math.cos(rad))
            y = int(cy + r * math.sin(rad) * 0.5)  # squish Y to account for char aspect
            try:
                self.stdscr.addch(y, x, char, attr)
            except:
                pass

    def _draw_sweep(self, cx, cy, radius, angle_deg):
        # draw a soft sweep beam of width self.sweep_length degrees
        center_rad = math.radians(angle_deg)
        half = self.sweep_length / 2.0
        steps = radius
        now = time.time()
        for i in range(0, steps):
            # position along radius
            r = i
            # sample several offsets across the sweep width to make a soft beam
            for off in range(-int(half), int(half)+1, max(1, int(half/6) or 1)):
                a = center_rad + math.radians(off)
                # fading effect across beam width and along radius
                beam_fade = 1.0 - (abs(off) / max(1.0, half))
                radial_fade = 1.0 - (r / max(1, steps))
                intensity = clamp(beam_fade * radial_fade, 0.0, 1.0)
                ch = '/' if intensity > 0.6 else '.'
                attr = curses.color_pair(1)
                if intensity > 0.7:
                    attr |= curses.A_BOLD
                elif intensity < 0.25:
                    attr |= curses.A_DIM
                x = int(cx + r * math.cos(a))
                y = int(cy + r * math.sin(a) * 0.5)
                try:
                    self.stdscr.addch(y, x, ch, attr)
                except:
                    pass

    def _draw_starfield(self):
        # twinkle and draw stars behind everything
        try:
            now = time.time()
            for s in self.stars:
                sx, sy, ch, phase = s
                # simple twinkle
                v = 0.5 + 0.5 * math.sin(now * 3.0 + phase)
                if v > 0.66:
                    attr = curses.A_BOLD | curses.color_pair(6)
                    draw_ch = ch
                elif v > 0.33:
                    attr = curses.color_pair(6)
                    draw_ch = ch
                else:
                    attr = curses.A_DIM | curses.color_pair(6)
                    draw_ch = '.'
                try:
                    self.stdscr.addch(sy, sx, draw_ch, attr)
                except Exception:
                    pass
        except Exception:
            pass

    def _place_blip(self, cx, cy, radius, ip, rate, proto='UNK'):
        # map ip -> angle, connections -> distance, rate -> intensity/size
        a = hash_ip_angle(ip)
        # distance mapping: closer for local (small rate) - we want more distant for many connections
        dist = clamp((math.log1p(rate+1) * 1.8) * self.scale, 1.0, radius - 2)
        # convert polar -> canvas
        x = int(cx + dist * math.cos(a))
        y = int(cy + dist * math.sin(a) * 0.5)
        # size mapping from rate
        size = clamp(int(min(MAX_BLIP_SIZE, 1 + math.log1p(rate+1))), 1, MAX_BLIP_SIZE)
        # intensity mapping (0..1)
        intensity = clamp(min(1.0, math.log1p(rate+1) / 6.0), 0.01, 1.0)
        # choose char and color based on proto and intensity
        if proto == 'UDP':
            color = curses.color_pair(2)
        elif proto == 'TCP':
            color = curses.color_pair(3)
        else:
            color = curses.color_pair(5)
        if intensity > 0.75:
            color |= curses.A_BOLD
        # draw concentric based on size
        ch = self.glyphs.get(size, '●')
        try:
            self.stdscr.addch(y, x, ch, color)
        except:
            pass
        # save history for trail with timestamp
        self.history[ip].append((x, y, intensity, color, time.time()))

    def _decay_and_draw_trails(self):
        # draw older history with decayed intensity
        now = time.time()
        for ip, dq in list(self.history.items()):
            if not dq:
                continue
            # iterate over entries and fade
            for i, item in enumerate(reversed(dq)):
                # item: x, y, intensity, color, ts
                if len(item) == 5:
                    x, y, intensity, color, ts = item
                else:
                    x, y, intensity, color = item
                    ts = now
                age = now - ts
                life = HISTORY_LENGTH * SAMPLE_INTERVAL
                fade = clamp(1.0 - (age / max(0.0001, life)), 0.0, 1.0)
                disp_int = intensity * fade * TRAIL_OPACITY
                if disp_int < 0.02:
                    continue
                # choose character based on disp_int
                if disp_int > 0.6:
                    ch = self.glyphs.get(3, 'O')
                elif disp_int > 0.3:
                    ch = self.glyphs.get(2, 'o')
                else:
                    ch = self.glyphs.get(1, '.')
                # attempt to add with dim attribute according to fade
                attr = color
                try:
                    if fade < 0.35:
                        attr |= curses.A_DIM
                    elif fade > 0.85:
                        attr |= curses.A_BOLD
                    self.stdscr.addch(y, x, ch, attr)
                except:
                    pass
            # cleanup very old
            if len(dq) and now - self.last_sample_time > HISTORY_LENGTH * SAMPLE_INTERVAL:
                dq.clear()
        # draw pulsing current blips (most recent point) for better animation
        try:
            for ip, dq in list(self.history.items()):
                if not dq:
                    continue
                x, y, intensity, color, ts = dq[-1]
                age = now - ts
                pulse = 0.5 + 0.5 * math.sin(now * (1.0 + intensity * 6.0))
                pulse_val = clamp(intensity * (0.6 + 0.4 * pulse), 0.0, 1.0)
                if pulse_val > 0.66:
                    ch = self.glyphs.get(3, 'O')
                elif pulse_val > 0.33:
                    ch = self.glyphs.get(2, 'o')
                else:
                    ch = self.glyphs.get(1, '.')
                attr = color
                if pulse_val > 0.7:
                    attr |= curses.A_BOLD
                elif pulse_val < 0.2:
                    attr |= curses.A_DIM
                try:
                    self.stdscr.addch(y, x, ch, attr)
                except:
                    pass
        except Exception:
            pass

    def sample_data(self):
        """Collect sample from sniffer or scanner depending on mode."""
        if self.mode == 'SNIF' and self.sniffer and self.sniffer._supported:
            # snapshot from sniffer
            raw = self.sniffer.snapshot_and_reset()
            # raw: dict ip -> count in SAMPLE_INTERVAL
            # produce map ip -> rate_per_sec
            rates = {}
            for ip, cnt in raw.items():
                rates[ip] = cnt / max(0.0001, SAMPLE_INTERVAL)
            meta = {
                'pkt_delta': sum(raw.values()),
                'total_conns': len(raw),
                'ss_error': None,
                'collector': 'simulation' if getattr(self.sniffer, '_simulated', False) else 'sniffer',
                'sampled_hosts': len(raw),
            }
            if getattr(self.sniffer, '_simulated', False):
                protos = {ip: simulated_proto_for_ip(ip) for ip in rates}
            else:
                protos = {ip: self.proto_map.get(ip, 'UNK') for ip in rates}
            return rates, protos, meta
        else:
            # fallback scanner
            ip_stats, meta = self.scanner.snapshot()
            # distribute pkt_delta across ips proportionally to connections
            rates = {}
            protos = {}
            total_conns = meta.get('total_conns', 0) or 1
            for ip, details in ip_stats.items():
                c = details.get('connections', 0)
                # estimated packets per second for this ip (very rough)
                est = (c / total_conns) * (meta.get('pkt_delta', 0) / max(0.0001, SAMPLE_INTERVAL))
                rates[ip] = est
                protos[ip] = details.get('proto', 'UNK')
            meta['sampled_hosts'] = len(ip_stats)
            return rates, protos, meta

    def _smoothing_step(self, rates):
        # apply EMA smoothing to rates
        out = {}
        for ip, r in rates.items():
            prev = self.smoothing.get(ip, r)
            sm = prev * (1.0 - SMOOTH_ALPHA) + r * SMOOTH_ALPHA
            self.smoothing[ip] = sm
            out[ip] = sm
        # decay smoothing for ips no longer present
        for ip in list(self.smoothing.keys()):
            if ip not in rates:
                self.smoothing[ip] *= DECAY_RATE
                if self.smoothing[ip] < 0.01:
                    del self.smoothing[ip]
        return out

    def draw(self):
        # main draw loop body (single frame)
        h, w = self._get_term_size()
        if h < MIN_TERMINAL_SIZE[0] or w < MIN_TERMINAL_SIZE[1]:
            self.stdscr.clear()
            msg = "Terminal too small — resize to at least 80x24"
            try:
                self.stdscr.addstr(0, 0, msg, curses.A_BOLD)
            except:
                pass
            return
        cx = w // 2
        cy = h // 2
        radius = min(cx - 4, int((cy - 3) * 2))  # account for squish
        radius = max(6, radius)

        # clear frame and draw background
        try:
            self.stdscr.erase()
            self._draw_starfield()
        except Exception:
            try:
                self.stdscr.erase()
            except:
                pass

        # draw rings and legend
        self._draw_border_and_legend(cx, cy, radius, h, w)

        # draw sweep
        self._draw_sweep(cx, cy, radius, self.angle)

        # sample at SAMPLE_INTERVAL
        now = time.time()
        if now - self.last_sample_time >= SAMPLE_INTERVAL and not self.paused:
            rates_raw, protos, meta = self.sample_data()
            rates = self._smoothing_step(rates_raw)
            self.last_meta = meta
            # integrate into intensity/history and draw blips
            for ip, r in rates.items():
                proto = protos.get(ip, self.proto_map.get(ip, 'UNK'))
                self.proto_map[ip] = proto
                # intensity accumulation
                self.intensity[ip] = clamp(self.intensity.get(ip, 0.0) * DECAY_RATE + (r / 10.0), 0.0, 10.0)
                self._place_blip(cx, cy, radius, ip, r, proto=proto)
            # update timestamp
            self.last_sample_time = now

        # draw trails (decayed)
        self._decay_and_draw_trails()
        self._draw_status_panel(h, w)

        # additional top-talkers mini-list on right
        try:
            sorted_ips = sorted(self.smoothing.items(), key=lambda kv: kv[1], reverse=True)[:10]
            startx = w - 28
            starty = 2
            self.stdscr.addstr(starty-1, startx, " Top talkers ", curses.A_BOLD | curses.color_pair(6))
            for i, (ip, val) in enumerate(sorted_ips):
                proto = self.proto_map.get(ip, 'UNK')
                line = f"{i+1:2d}. {ip:15.15} {proto:3.3} {val:6.1f}"
                self.stdscr.addstr(starty + i, startx, line, curses.color_pair(6))
        except Exception:
            pass

    def handle_input(self):
        # non-blocking input
        try:
            ch = self.stdscr.getch()
        except:
            ch = -1
        if ch == -1:
            return
        if ch in (ord('q'), ord('Q')):
            self.running = False
        elif ch in (ord('p'), ord('P')):
            self.paused = not self.paused
        elif ch == ord('+'):
            self.scale *= 1.15
        elif ch == ord('-'):
            self.scale /= 1.15
        elif ch in (ord('r'), ord('R')):
            self.smoothing.clear()
            self.history.clear()
            self.intensity.clear()
            self.proto_map.clear()
        elif ch in (ord('h'), ord('H')):
            self._show_help()

    def _show_help(self):
        h, w = self._get_term_size()
        lines = [
            "NETWORK RADAR — HELP",
            "",
            "q: Quit",
            "p: Pause/Resume sampling",
            "+/-: Increase/Decrease scale (distance mapping)",
            "r: Reset data",
            "h: Show this help",
            "",
            "Modes:",
            " - SNIF: raw packet capture (requires root)",
            " - SS: fallback using ss + /proc/net/dev",
            "",
            "Tips:",
            " - Run as root for per-IP packet accuracy (sudo)",
            " - Resize terminal wide for better layout",
            " - Use --headless to test sampling without curses",
            "",
            "Press any key to close this help..."
        ]
        win_h = len(lines) + 2
        win_w = max(len(x) for x in lines) + 4
        sy = max(1, (h - win_h)//2)
        sx = max(1, (w - win_w)//2)
        # draw simple box
        try:
            for y in range(win_h):
                for x in range(win_w):
                    if y in (0, win_h-1) or x in (0, win_w-1):
                        self.stdscr.addch(sy+y, sx+x, '#', curses.A_DIM)
            for i, l in enumerate(lines):
                self.stdscr.addstr(sy+1+i, sx+2, l)
            self.stdscr.refresh()
            # wait for key
            self.stdscr.nodelay(False)
            self.stdscr.getch()
            self.stdscr.nodelay(True)
        except:
            pass

# ---------------------------
# Main loop
# ---------------------------

def main_curses(stdscr, args, sniffer=None, scanner=None):
    # setup
    stdscr.nodelay(True)
    curses.curs_set(0)
    if sniffer and sniffer._supported:
        sniffer.start()
    radar = Radar(stdscr, sniffer=sniffer, scanner=scanner, theme=getattr(args, 'theme', 'default'), bg_color=getattr(args, 'bg_color', None), fg_color=getattr(args, 'fg_color', None))
    radar.scale = args.scale
    # main loop
    last = time.time()
    try:
        while radar.running:
            now = time.time()
            # update sweep angle based on real time and sweep_speed
            dt = now - last
            radar.angle = (radar.angle + radar.sweep_speed * dt) % 360.0
            # draw frame
            radar.draw()
            radar.handle_input()
            stdscr.refresh()
            last = now
            time.sleep(REFRESH)
    except KeyboardInterrupt:
        pass
    finally:
        if sniffer:
            sniffer.stop()
        # final cleanup
        try:
            curses.endwin()
        except:
            pass

# ---------------------------
# Entrypoint / CLI
# ---------------------------


def parse_args():
    p = argparse.ArgumentParser(description='Network Radar - terminal visualization')
    p.add_argument('--iface', help='Network interface to bind raw sniffer')
    p.add_argument('--scale', type=float, default=DEFAULT_SCALE, help='Distance scale for mapping')
    p.add_argument('--interval', type=float, default=SAMPLE_INTERVAL, help='Sampling interval (s)')
    p.add_argument('--simulate', action='store_true', help='Run in simulated traffic mode')
    p.add_argument('--hosts', type=int, default=12, help='Number of simulated hosts')
    p.add_argument('--max-rate', type=int, default=200, help='Max simulated packet rate')
    p.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    p.add_argument('--theme', type=str, default='default', help='Color theme name (default, neon, solarized)')
    p.add_argument('--bg-color', type=str, default=None, help='Background color name (black, red, etc.)')
    p.add_argument('--fg-color', type=str, default=None, help='Foreground/text color name')
    p.add_argument('--headless', action='store_true', help='Run sampling loop without curses and print summaries')
    p.add_argument('--frames', type=int, default=5, help='Number of samples to print in headless mode')
    return p.parse_args()


def smooth_rates(smoothing, rates):
    out = {}
    for ip, r in rates.items():
        prev = smoothing.get(ip, r)
        sm = prev * (1.0 - SMOOTH_ALPHA) + r * SMOOTH_ALPHA
        smoothing[ip] = sm
        out[ip] = sm
    for ip in list(smoothing.keys()):
        if ip not in rates:
            smoothing[ip] *= DECAY_RATE
            if smoothing[ip] < 0.01:
                del smoothing[ip]
    return out


def collect_sample(mode, sniffer, scanner, smoothing, proto_map):
    if mode == 'SNIF' and sniffer and sniffer._supported:
        raw = sniffer.snapshot_and_reset()
        rates = {ip: cnt / max(0.0001, SAMPLE_INTERVAL) for ip, cnt in raw.items()}
        meta = {
            'pkt_delta': sum(raw.values()),
            'total_conns': len(raw),
            'ss_error': None,
            'collector': 'simulation' if getattr(sniffer, '_simulated', False) else 'sniffer',
            'sampled_hosts': len(raw),
        }
        if getattr(sniffer, '_simulated', False):
            protos = {ip: simulated_proto_for_ip(ip) for ip in rates}
        else:
            protos = {ip: proto_map.get(ip, 'UNK') for ip in rates}
    else:
        ip_stats, meta = scanner.snapshot()
        total_conns = meta.get('total_conns', 0) or 1
        rates = {}
        protos = {}
        for ip, details in ip_stats.items():
            connections = details.get('connections', 0)
            rates[ip] = (connections / total_conns) * (meta.get('pkt_delta', 0) / max(0.0001, SAMPLE_INTERVAL))
            protos[ip] = details.get('proto', 'UNK')
    smoothed = smooth_rates(smoothing, rates)
    for ip, proto in protos.items():
        proto_map[ip] = proto
    meta['sampled_hosts'] = len(rates)
    return smoothed, protos, meta


def run_headless(args, sniffer=None, scanner=None):
    mode = 'SNIF' if (sniffer and sniffer._supported) else 'SS'
    smoothing = {}
    proto_map = {}
    iface_state = get_iface_operstate(getattr(args, 'iface', None))
    if sniffer and isinstance(sniffer, threading.Thread) and sniffer._supported:
        sniffer.start()
    try:
        if args.iface and iface_state:
            print(f"iface={args.iface} state={iface_state}")
        elif args.iface and iface_state is None:
            print(f"iface={args.iface} state=unknown")
        for frame in range(max(1, args.frames)):
            rates, protos, meta = collect_sample(mode, sniffer, scanner, smoothing, proto_map)
            print(
                f"[sample {frame + 1}/{max(1, args.frames)}] "
                f"mode={mode} collector={meta.get('collector')} "
                f"hosts={meta.get('sampled_hosts', 0)} "
                f"pkt_delta={int(meta.get('pkt_delta', 0))} "
                f"conns={int(meta.get('total_conns', 0))}"
            )
            error = meta.get('ss_error')
            if error:
                print(f"  ss_error: {error}")
            top = sorted(rates.items(), key=lambda kv: kv[1], reverse=True)[:5]
            if not top:
                print("  no active hosts detected")
            for ip, rate in top:
                proto = protos.get(ip, proto_map.get(ip, 'UNK'))
                print(f"  {ip:39} {proto:3} {rate:8.1f} pkt/s")
            if frame < max(1, args.frames) - 1:
                time.sleep(max(0.05, args.interval))
    finally:
        if sniffer and hasattr(sniffer, 'stop'):
            sniffer.stop()


def main():
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(levelname)s: %(message)s')
    # override module-level sample interval and default scale
    global SAMPLE_INTERVAL
    SAMPLE_INTERVAL = args.interval
    global DEFAULT_SCALE
    DEFAULT_SCALE = args.scale

    if args.simulate:
        sniffer = SimulationCollector(hosts=args.hosts, max_rate=args.max_rate)
        scanner = sniffer
    else:
        sniffer = PacketSniffer(iface=args.iface) if is_root() else None
        scanner = ConnectionScanner(iface=args.iface)

    if args.headless:
        run_headless(args, sniffer=sniffer, scanner=scanner)
        return

    try:
        curses.wrapper(lambda s: main_curses(s, args, sniffer=sniffer, scanner=scanner))
    except Exception:
        logging.exception('ERROR initializing curses')
        print('Run with --simulate for non-root testing or run as root for sniffer mode')
        sys.exit(1)


if __name__ == "__main__":
    main()
