from dataclasses import dataclass


@dataclass(slots=True)
class RadarSettings:
    refresh: float = 0.05
    sample_interval: float = 0.5
    decay_rate: float = 0.88
    smooth_alpha: float = 0.4
    max_blip_size: int = 3
    default_scale: float = 1.0
    history_length: int = 40
    min_terminal_height: int = 24
    min_terminal_width: int = 80
    sweep_length_deg: int = 30
    trail_opacity: float = 0.9
