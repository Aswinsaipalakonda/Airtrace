"""Configuration parameters, constants, and defaults for Airtrace."""

from pathlib import Path

# Application paths
BASE_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = BASE_DIR / "assets"
CAPTURES_DIR = BASE_DIR / "captures"

# Ensure runtime directories exist
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

# Performance and buffer limits
MAX_PACKETS_HISTORY = 5000       # Maximum records kept in in-memory ring buffer
QUEUE_MAX_SIZE = 10000           # Maximum unconsumed packets in capture queue
BATCH_DRAIN_LIMIT = 200          # Maximum packets drained per UI update tick
RATE_WINDOW_SECONDS = 5.0        # Time window for rolling PPS and BPS calculations
SLICED_SNIFF_TIMEOUT = 0.5       # Scapy sniff loop slice timeout in seconds

# Supported Protocols
PROTOCOLS = ["ALL", "TCP", "UDP", "ICMP", "OTHER"]

# Design / Color Tokens
COLOR_PALETTE = {
    "bg_canvas": "#0B0F19",
    "surface_card": "#151C2C",
    "border": "#232F48",
    "accent_cyan": "#00C8FF",
    "accent_blue": "#0066FF",
    "text_primary": "#F8FAFC",
    "text_secondary": "#94A3B8",
    "status_capturing": "#00E676",
    "status_idle": "#64748B",
    "status_stopping": "#FFB300",
    "status_error": "#FF5252",
    "proto_tcp": "#00D2FF",
    "proto_udp": "#00E676",
    "proto_icmp": "#B388FF",
    "proto_other": "#90A4AE",
}
