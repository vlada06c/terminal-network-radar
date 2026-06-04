import curses
import math
import random
import time
from collections import defaultdict, deque
from typing import Optional

from engine import collect_sample
from helpers import clamp, color_name_to_const, hash_ip_angle, is_root
from settings import RadarSettings


THEMES = {
    "default": {
        "sweep": ("green", "default"),
        "udp": ("cyan", "default"),
        "tcp": ("yellow", "default"),
        "high": ("red", "default"),
        "unknown": ("magenta", "default"),
        "text": ("white", "default"),
        "bg": "black",
    },
    "neon": {
        "sweep": ("green", "black"),
        "udp": ("cyan", "black"),
        "tcp": ("yellow", "black"),
        "high": ("magenta", "black"),
        "unknown": ("blue", "black"),
        "text": ("white", "black"),
        "bg": "black",
    },
    "solarized": {
        "sweep": ("blue", "black"),
        "udp": ("cyan", "black"),
        "tcp": ("yellow", "black"),
        "high": ("red", "black"),
        "unknown": ("magenta", "black"),
        "text": ("white", "black"),
        "bg": "black",
    },
}


class RadarDisplay:
    def __init__(
        self,
        stdscr,
        settings: RadarSettings,
        sniffer=None,
        scanner=None,
        theme: str = "default",
        bg_color: Optional[str] = None,
        fg_color: Optional[str] = None,
    ):
        self.stdscr = stdscr
        self.settings = settings
        self.sniffer = sniffer
        self.scanner = scanner
        self.running = True
        self.paused = False
        self.scale = settings.default_scale
        self.smoothing: dict[str, float] = {}
        self.proto_map: dict[str, str] = {}
        self.intensity = defaultdict(float)
        self.history = defaultdict(lambda: deque(maxlen=self.settings.history_length))
        self.last_sample_time = time.time()
        self.mode = "SNIF" if (sniffer and sniffer._supported) else "SS"
        self.last_meta = {
            "pkt_delta": 0,
            "total_conns": 0,
            "ss_error": None,
            "collector": "sniffer" if self.mode == "SNIF" else "ss",
            "sampled_hosts": 0,
        }
        self.angle = 0.0
        self.sweep_speed = 120.0
        self.sweep_length = settings.sweep_length_deg
        self.controls_text = "q:quit p:pause +/- scale r:reset h:help"
        curses.use_default_colors()
        curses.start_color()
        self._init_colors(theme, bg_color, fg_color)
        self.glyphs = self._build_glyphs()
        self.stars = self._build_stars()

    def _init_colors(self, theme: str, bg_color: Optional[str], fg_color: Optional[str]) -> None:
        palette = dict(THEMES.get(theme, THEMES["default"]))
        if bg_color:
            palette["bg"] = bg_color
        if fg_color:
            palette["text"] = (fg_color, palette["text"][1])

        def init_pair(pair_id: int, fg_name: str, bg_name: Optional[str]) -> None:
            fg = color_name_to_const(fg_name)
            bg = -1 if bg_name is None else color_name_to_const(bg_name)
            try:
                curses.init_pair(pair_id, fg, bg)
            except curses.error:
                try:
                    curses.init_pair(pair_id, fg, -1)
                except curses.error:
                    pass

        init_pair(1, palette["sweep"][0], palette.get("bg"))
        init_pair(2, palette["udp"][0], palette.get("bg"))
        init_pair(3, palette["tcp"][0], palette.get("bg"))
        init_pair(4, palette["high"][0], palette.get("bg"))
        init_pair(5, palette["unknown"][0], palette.get("bg"))
        init_pair(6, palette["text"][0], palette.get("bg"))

    def _build_glyphs(self) -> dict[int, str]:
        try:
            "•".encode("utf-8")
            return {1: "•", 2: "●", 3: "◉"}
        except UnicodeEncodeError:
            return {1: ".", 2: "o", 3: "O"}

    def _build_stars(self) -> list[list[int | float | str]]:
        height, width = self._get_term_size()
        star_count = max(20, min(200, (height * width) // 300))
        stars: list[list[int | float | str]] = []
        for _ in range(star_count):
            stars.append(
                [
                    random.randint(1, max(1, width - 2)),
                    random.randint(1, max(1, height - 3)),
                    random.choice([".", "+", "*"]),
                    random.random() * 2 * math.pi,
                ]
            )
        return stars

    def _get_term_size(self) -> tuple[int, int]:
        return self.stdscr.getmaxyx()

    def _draw_border_and_legend(self, cx: int, cy: int, radius: int, height: int, width: int) -> None:
        title = f" NETWORK RADAR  — mode: {self.mode}  scale:{self.scale:.2f}  (root={is_root()}) "
        try:
            self.stdscr.addstr(0, max(0, (width - len(title)) // 2), title, curses.A_BOLD | curses.color_pair(6))
        except curses.error:
            pass
        try:
            self.stdscr.addstr(height - 2, 1, self.controls_text, curses.color_pair(6))
        except curses.error:
            pass
        for ring in range(1, 4):
            self._draw_circle(cx, cy, int(radius * ring / 3), char=".", attr=curses.color_pair(6))

    def _draw_status_panel(self, height: int, width: int) -> None:
        sample_age = max(0.0, time.time() - self.last_sample_time)
        hosts = len(self.smoothing)
        panel_width = min(34, max(0, width - 4))
        if panel_width <= 0:
            return
        age_label = "<1s" if sample_age < 1 else f"{int(sample_age)}s"
        lines = [
            f"status: {'PAUSED' if self.paused else 'LIVE'}",
            f"sample age: {age_label}",
            f"tracked hosts: {hosts}",
            f"pkt delta: {int(self.last_meta.get('pkt_delta', 0))}",
            f"connections: {int(self.last_meta.get('total_conns', 0))}",
            f"collector: {self.last_meta.get('collector', self.mode.lower())}",
        ]
        error = self.last_meta.get("ss_error")
        if error:
            lines.append(f"ss: {str(error)[:28]}")
        try:
            for row in range(1, 2 + len(lines)):
                self.stdscr.addstr(row, 2, " " * panel_width, curses.color_pair(6))
            self.stdscr.addstr(1, 2, " Status ".ljust(panel_width), curses.A_BOLD | curses.color_pair(6))
            for index, line in enumerate(lines):
                self.stdscr.addstr(2 + index, 2, line[:panel_width].ljust(panel_width), curses.color_pair(6))
        except curses.error:
            return

    def _draw_circle(self, cx: int, cy: int, radius: int, char: str = ".", attr: int = 0) -> None:
        if radius <= 0:
            return
        step = max(6, int(6 * (radius / 6)))
        for angle in range(0, 360, step):
            radians = math.radians(angle)
            x = int(cx + radius * math.cos(radians))
            y = int(cy + radius * math.sin(radians) * 0.5)
            try:
                self.stdscr.addch(y, x, char, attr)
            except curses.error:
                pass

    def _draw_sweep(self, cx: int, cy: int, radius: int, angle_deg: float) -> None:
        center = math.radians(angle_deg)
        half_width = self.sweep_length / 2.0
        offset_step = max(1, int(half_width / 6) or 1)
        for radius_step in range(radius):
            for offset in range(-int(half_width), int(half_width) + 1, offset_step):
                radians = center + math.radians(offset)
                beam_fade = 1.0 - (abs(offset) / max(1.0, half_width))
                radial_fade = 1.0 - (radius_step / max(1, radius))
                intensity = clamp(beam_fade * radial_fade, 0.0, 1.0)
                char = "/" if intensity > 0.6 else "."
                attr = curses.color_pair(1)
                if intensity > 0.7:
                    attr |= curses.A_BOLD
                elif intensity < 0.25:
                    attr |= curses.A_DIM
                x = int(cx + radius_step * math.cos(radians))
                y = int(cy + radius_step * math.sin(radians) * 0.5)
                try:
                    self.stdscr.addch(y, x, char, attr)
                except curses.error:
                    pass

    def _draw_starfield(self) -> None:
        now = time.time()
        for star_x, star_y, char, phase in self.stars:
            value = 0.5 + 0.5 * math.sin(now * 3.0 + phase)
            if value > 0.66:
                attr = curses.A_BOLD | curses.color_pair(6)
                draw_char = char
            elif value > 0.33:
                attr = curses.color_pair(6)
                draw_char = char
            else:
                attr = curses.A_DIM | curses.color_pair(6)
                draw_char = "."
            try:
                self.stdscr.addch(int(star_y), int(star_x), str(draw_char), attr)
            except curses.error:
                pass

    def _place_blip(self, cx: int, cy: int, radius: int, ip: str, rate: float, proto: str = "UNK") -> None:
        angle = hash_ip_angle(ip)
        distance = clamp((math.log1p(rate + 1) * 1.8) * self.scale, 1.0, radius - 2)
        x = int(cx + distance * math.cos(angle))
        y = int(cy + distance * math.sin(angle) * 0.5)
        size = int(clamp(min(self.settings.max_blip_size, 1 + math.log1p(rate + 1)), 1, self.settings.max_blip_size))
        intensity = clamp(min(1.0, math.log1p(rate + 1) / 6.0), 0.01, 1.0)
        if proto == "UDP":
            color = curses.color_pair(2)
        elif proto == "TCP":
            color = curses.color_pair(3)
        else:
            color = curses.color_pair(5)
        if intensity > 0.75:
            color |= curses.A_BOLD
        try:
            self.stdscr.addch(y, x, self.glyphs.get(size, "●"), color)
        except curses.error:
            pass
        self.history[ip].append((x, y, intensity, color, time.time()))

    def _decay_and_draw_trails(self) -> None:
        now = time.time()
        for ip, trail in list(self.history.items()):
            for item in reversed(trail):
                x, y, intensity, color, timestamp = item
                age = now - timestamp
                lifetime = self.settings.history_length * self.settings.sample_interval
                fade = clamp(1.0 - (age / max(0.0001, lifetime)), 0.0, 1.0)
                visible = intensity * fade * self.settings.trail_opacity
                if visible < 0.02:
                    continue
                if visible > 0.6:
                    char = self.glyphs.get(3, "O")
                elif visible > 0.3:
                    char = self.glyphs.get(2, "o")
                else:
                    char = self.glyphs.get(1, ".")
                attr = color
                if fade < 0.35:
                    attr |= curses.A_DIM
                elif fade > 0.85:
                    attr |= curses.A_BOLD
                try:
                    self.stdscr.addch(y, x, char, attr)
                except curses.error:
                    pass
            if trail and now - self.last_sample_time > self.settings.history_length * self.settings.sample_interval:
                trail.clear()
        for trail in self.history.values():
            if not trail:
                continue
            x, y, intensity, color, timestamp = trail[-1]
            _ = timestamp
            pulse = 0.5 + 0.5 * math.sin(now * (1.0 + intensity * 6.0))
            visible = clamp(intensity * (0.6 + 0.4 * pulse), 0.0, 1.0)
            if visible > 0.66:
                char = self.glyphs.get(3, "O")
            elif visible > 0.33:
                char = self.glyphs.get(2, "o")
            else:
                char = self.glyphs.get(1, ".")
            attr = color
            if visible > 0.7:
                attr |= curses.A_BOLD
            elif visible < 0.2:
                attr |= curses.A_DIM
            try:
                self.stdscr.addch(y, x, char, attr)
            except curses.error:
                pass

    def draw(self) -> None:
        height, width = self._get_term_size()
        if height < self.settings.min_terminal_height or width < self.settings.min_terminal_width:
            self.stdscr.clear()
            try:
                self.stdscr.addstr(0, 0, "Terminal too small — resize to at least 80x24", curses.A_BOLD)
            except curses.error:
                pass
            return

        center_x = width // 2
        center_y = height // 2
        radius = max(6, min(center_x - 4, int((center_y - 3) * 2)))

        try:
            self.stdscr.erase()
            self._draw_starfield()
        except curses.error:
            self.stdscr.erase()

        self._draw_border_and_legend(center_x, center_y, radius, height, width)
        self._draw_sweep(center_x, center_y, radius, self.angle)

        now = time.time()
        if now - self.last_sample_time >= self.settings.sample_interval and not self.paused:
            rates, protos, meta = collect_sample(
                self.mode,
                self.sniffer,
                self.scanner,
                self.smoothing,
                self.proto_map,
                self.settings,
            )
            self.last_meta = meta
            for ip, rate in rates.items():
                proto = protos.get(ip, self.proto_map.get(ip, "UNK"))
                self.proto_map[ip] = proto
                self.intensity[ip] = clamp(
                    self.intensity.get(ip, 0.0) * self.settings.decay_rate + (rate / 10.0),
                    0.0,
                    10.0,
                )
                self._place_blip(center_x, center_y, radius, ip, rate, proto)
            self.last_sample_time = now

        self._decay_and_draw_trails()
        self._draw_status_panel(height, width)
        self._draw_top_talkers(width)

    def _draw_top_talkers(self, width: int) -> None:
        top_hosts = sorted(self.smoothing.items(), key=lambda item: item[1], reverse=True)[:10]
        start_x = width - 28
        start_y = 2
        try:
            self.stdscr.addstr(start_y - 1, start_x, " Top talkers ", curses.A_BOLD | curses.color_pair(6))
            for index, (ip, value) in enumerate(top_hosts):
                proto = self.proto_map.get(ip, "UNK")
                line = f"{index + 1:2d}. {ip:15.15} {proto:3.3} {value:6.1f}"
                self.stdscr.addstr(start_y + index, start_x, line, curses.color_pair(6))
        except curses.error:
            pass

    def handle_input(self) -> None:
        try:
            char = self.stdscr.getch()
        except curses.error:
            char = -1
        if char == -1:
            return
        if char in {ord("q"), ord("Q")}:
            self.running = False
        elif char in {ord("p"), ord("P")}:
            self.paused = not self.paused
        elif char == ord("+"):
            self.scale *= 1.15
        elif char == ord("-"):
            self.scale /= 1.15
        elif char in {ord("r"), ord("R")}:
            self.smoothing.clear()
            self.history.clear()
            self.intensity.clear()
            self.proto_map.clear()
        elif char in {ord("h"), ord("H")}:
            self._show_help()

    def _show_help(self) -> None:
        height, width = self._get_term_size()
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
            "Press any key to close this help...",
        ]
        window_height = len(lines) + 2
        window_width = max(len(line) for line in lines) + 4
        start_y = max(1, (height - window_height) // 2)
        start_x = max(1, (width - window_width) // 2)
        try:
            for offset_y in range(window_height):
                for offset_x in range(window_width):
                    if offset_y in {0, window_height - 1} or offset_x in {0, window_width - 1}:
                        self.stdscr.addch(start_y + offset_y, start_x + offset_x, "#", curses.A_DIM)
            for index, line in enumerate(lines):
                self.stdscr.addstr(start_y + 1 + index, start_x + 2, line)
            self.stdscr.refresh()
            self.stdscr.nodelay(False)
            self.stdscr.getch()
            self.stdscr.nodelay(True)
        except curses.error:
            pass


def main_curses(stdscr, args, settings: RadarSettings, sniffer=None, scanner=None) -> None:
    stdscr.nodelay(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    if sniffer and sniffer._supported and hasattr(sniffer, "start"):
        sniffer.start()
    radar = RadarDisplay(
        stdscr,
        settings,
        sniffer=sniffer,
        scanner=scanner,
        theme=getattr(args, "theme", "default"),
        bg_color=getattr(args, "bg_color", None),
        fg_color=getattr(args, "fg_color", None),
    )
    radar.scale = args.scale
    last_frame = time.time()
    try:
        while radar.running:
            now = time.time()
            radar.angle = (radar.angle + radar.sweep_speed * (now - last_frame)) % 360.0
            radar.draw()
            radar.handle_input()
            stdscr.refresh()
            last_frame = now
            time.sleep(settings.refresh)
    except KeyboardInterrupt:
        pass
    finally:
        if sniffer and hasattr(sniffer, "stop"):
            sniffer.stop()
