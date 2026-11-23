# Airtrace — Implementation Plan & Engineering Architecture

**Document Version:** 1.0.0  
**Target Platform:** Windows 10/11 (Python 3.11+)  
**Repository:** `https://github.com/Aswinsaipalakonda/Airtrace.git`  
**Status:** Approved for Implementation Planning (Pre-Coding Phase)

---

## 1. Executive Summary & Project Understanding

Airtrace is a high-precision, passive network traffic analyzer engineered for wireless and systems engineering analysis, educational exploration, and technical portfolio demonstration. The core mission of Airtrace is: **Inspect. Understand. Analyze.**

Airtrace captures network frames from user-selected network interfaces, parses IPv4 and transport-layer protocols (TCP, UDP, ICMP, and OTHER), computes rolling real-time traffic statistics (PPS, BPS, protocol distribution, top talkers), and visualizes the results on a high-density, professional local dashboard built with Streamlit.

### Core Tenets
1. **Separation of Concerns:** The packet decoding engine, statistics aggregator, and capture worker must remain 100% decoupled from the Streamlit presentation layer.
2. **Reliable Capture Lifecycle:** Prevent hanging background sniffers and duplicate capture threads across Streamlit UI reruns.
3. **Deterministic, Testable Core:** Every decoding, statistical, and export routine must be verifiable offline via synthetic Scapy packets without requiring root/admin privileges or active internet connections.
4. **Professional Engineering UI (Anti-"AI-Slop"):** Provide a high-contrast, technical, dark-mode cockpit designed around information density, tabular clarity, and sub-second feedback, strictly avoiding decorative clutter.
5. **Windows & Wi-Fi Pragmatism:** Accurately represent Windows packet capture capabilities (Ethernet frame emulation over Wi-Fi via Npcap) without making false claims about raw 802.11 monitor mode without supported hardware.

---

## 2. Recommended System Architecture

Airtrace follows a decoupled, unidirectional data-flow architecture:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Streamlit UI Presentation                       │
│  ┌──────────────┐  ┌───────────────────┐  ┌───────────┐  ┌───────────┐ │
│  │ Controls Bar │  │ Real-time Metrics │  │ Charts    │  │ Explorer  │ │
│  └──────┬───────┘  └─────────▲─────────┘  └─────▲─────┘  └─────▲─────┘ │
└─────────┼────────────────────┼──────────────────┼──────────────┼───────┘
          │ User Actions       │ Read Snapshots   │ Read Data    │ Search
          ▼                    │                  │              │
┌──────────────────────────────┴──────────────────┴──────────────┴───────┐
│                        Capture Controller (Singleton)                  │
│   - State Machine: IDLE | CAPTURING | STOPPING | ERROR                 │
│   - Atomic Re-entrancy Lock & Thread Safety Guard                      │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Coordinates
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Background Capture Worker (Thread)                  │
│   - Scapy sniff() bounded slice loop / AsyncSniffer                    │
│   - threading.Event (stop_event) for deterministic termination         │
│   - store=False (zero raw packet memory retention)                     │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Raw Packet (Wire bytes)
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          Packet Decoder Engine                         │
│   - Pure functional parser: IPv4 -> (TCP | UDP | ICMP | OTHER)        │
│   - Produces immutable, lightweight PacketRecord dataclasses           │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Normalized PacketRecord
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                  Thread-Safe FIFO Queue (maxsize=10,000)               │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Dequeue / Drain batches
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       Statistics & Aggregation Engine                  │
│   - Bounded Ring Buffer (collections.deque(maxlen=5,000))              │
│   - Rolling Rate Windows (5-second monotonic window for PPS & BPS)     │
│   - Counters: Total Packets, Bytes, Protocols, Top IPs                 │
│   - Thread-safe snapshot generator for UI ingestion                    │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │ Export trigger
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          Metadata CSV Exporter                         │
│   - ISO 8601 timestamps, strict header format, zero payload leakage    │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module Responsibilities & File Structure

```
Airtrace/
├── app.py                      # Main Streamlit entry point and layout coordinator
├── requirements.txt            # Pinned Python package dependencies
├── README.md                   # Project documentation and user guide
├── IMPLEMENTATION_PLAN.md      # This architectural plan
├── .gitignore                  # Git exclusion rules
├── logo.png                    # Brand mark and header logo
│
├── airtrace/                   # Pure Python Core Package (Independent of Streamlit)
│   ├── __init__.py             # Package exports and version metadata
│   ├── models.py               # Dataclasses: PacketRecord, CaptureStats, ProtocolType
│   ├── config.py               # Constants, default buffer sizes, theme tokens
│   ├── interfaces.py           # Scapy / Windows network interface discovery & mapping
│   ├── decoder.py              # Pure-function packet parser (IPv4, TCP, UDP, ICMP)
│   ├── statistics.py           # Rolling rates, metrics, counters, and bounded history
│   ├── capture.py              # CaptureWorker, thread lifecycle, and Singleton Controller
│   ├── filters.py              # Post-capture filtering, search predicates, BPF validation
│   └── exporter.py             # CSV serialization service (metadata only)
│
├── components/                 # Streamlit UI Components (Pure Presentation)
│   ├── __init__.py             # Component registry
│   ├── header.py               # Brand banner, status pill, and session info
│   ├── capture_controls.py     # Interface selector, filter input, start/stop buttons
│   ├── metric_cards.py         # KPI tiles (Packets, Bytes, Rates, Avg Size)
│   ├── protocol_charts.py      # Altair/Plotly protocol split & traffic-over-time charts
│   ├── packet_table.py         # Searchable, filterable, sortable packet grid
│   └── packet_details.py       # Expanded inspector view for single packet inspection
│
├── tests/                      # Pytest Test Suite (100% Offline Synthetic Tests)
│   ├── __init__.py
│   ├── conftest.py             # Synthetic packet fixtures (TCP, UDP, ICMP, Fragments)
│   ├── test_decoder.py         # Header decoding and protocol classification tests
│   ├── test_statistics.py      # Counter math, rolling rates, and ring buffer limits
│   ├── test_filters.py         # In-memory protocol filter and IP/port text search
│   └── test_exporter.py        # CSV format validation, empty-value handling, security
│
└── assets/
    └── logo.png                # Standardized application asset
```

### Module Breakdown:

1. **`airtrace/models.py`:**
   - Defines `ProtocolType` (Enum: `TCP`, `UDP`, `ICMP`, `OTHER`).
   - Defines `CaptureState` (Enum: `IDLE`, `CAPTURING`, `STOPPING`, `ERROR`).
   - Defines `PacketRecord` (Python `@dataclass(slots=True)`):
     - `packet_number: int`
     - `timestamp: str` (ISO 8601, microsecond precision)
     - `epoch_time: float` (Monotonic / epoch timestamp for rate calculation)
     - `protocol: str` (`"TCP"`, `"UDP"`, `"ICMP"`, `"OTHER"`)
     - `source_ip: str`
     - `destination_ip: str`
     - `source_port: int | None`
     - `destination_port: int | None`
     - `packet_size_bytes: int` (Wire length captured by pcap)
     - `ip_total_length: int | None` (IPv4 header field length)
     - `ttl: int | None`
     - `ip_identification: int | None`
     - `ip_flags: str | None` (DF, MF)
     - `fragment_offset: int | None`
     - `tcp_flags: str | None` (Human-readable comma list: e.g. `"SYN, ACK"`)
     - `tcp_sequence: int | None`
     - `tcp_acknowledgment: int | None`
     - `tcp_window: int | None`
     - `udp_length: int | None`
     - `udp_checksum: int | None`
     - `icmp_type: int | None`
     - `icmp_code: int | None`
     - `icmp_checksum: int | None`

2. **`airtrace/decoder.py`:**
   - `decode_packet(scapy_pkt, packet_number: int) -> PacketRecord | None`
   - Zero side-effects; handles malformed, truncated, or non-IP frames safely.
   - Strict classification sequence:
     1. Check for `scapy.layers.inet.IP`. If absent, classify as non-IPv4 or discard if strictly filtering IPv4.
     2. If `scapy.layers.inet.TCP` is present -> `ProtocolType.TCP`.
     3. Else if `scapy.layers.inet.UDP` is present -> `ProtocolType.UDP`.
     4. Else if `scapy.layers.inet.ICMP` is present -> `ProtocolType.ICMP`.
     5. Else -> `ProtocolType.OTHER` (e.g., IGMP, ESP, OSPF).
   - Format TCP flags using standard bitmask decomposition: `F` (FIN), `S` (SYN), `R` (RST), `P` (PSH), `A` (ACK), `U` (URG), `E` (ECE), `C` (CWR).

3. **`airtrace/statistics.py`:**
   - `StatisticsEngine`:
     - Tracks cumulative `total_packets`, `total_bytes`, `protocol_counts: Counter`.
     - Maintains a sliding time-window deque: `deque[tuple[float, int]](maxlen=50000)` holding `(timestamp, bytes)` over the last 5.0 seconds.
     - Accurate rate computation: $\text{PPS} = \frac{N_{\text{packets in window}}}{\Delta t}$, $\text{BPS} = \frac{\sum \text{Bytes in window}}{\Delta t}$.
     - Maintains top talker `Counter` for `source_ip` and `destination_ip`.
     - Packet size histogram binning.
     - Bounded historical `deque[PacketRecord](maxlen=config.MAX_PACKETS_HISTORY)`.
     - All read/write operations guarded by a re-entrant `threading.RLock`.

4. **`airtrace/interfaces.py`:**
   - `get_available_interfaces() -> list[InterfaceInfo]`:
     - Queries Scapy `get_windows_if_list()` on Windows.
     - Cross-references with `conf.ifaces` to build user-friendly descriptors:
       e.g., `"[Wi-Fi] Intel(R) Wi-Fi 6 AX201 - 192.168.1.15 (\Device\NPF_{...})"`.
     - Detects whether Npcap is functional. If not, returns clear diagnostic warnings.
   - `check_npcap_status() -> tuple[bool, str]`: Checks driver presence and API availability.

5. **`airtrace/capture.py`:**
   - Solves the critical lifecycle and rerun duplication problem.
   - `CaptureController` (Singleton):
     - Holds reference to single background thread, `stop_event: threading.Event`, packet `queue.Queue`.
     - Atomic `start_capture(interface, bpf_filter, limit_packets, limit_duration)`:
       - Checks `self.state`. If already `CAPTURING`, immediately ignores command.
       - Initializes or resets statistics and packet queue.
       - Spawns daemon `threading.Thread(target=self._worker_loop)`.
     - Atomic `stop_capture()`:
       - Signals `self.stop_event.set()`.
       - Sets `state = CaptureState.STOPPING`.
       - Joins worker thread with 2.0s timeout.
       - Sets `state = CaptureState.IDLE`.
   - `CaptureWorker` implementation:
     - Uses sliced `sniff(iface=..., prn=self._on_packet, store=False, timeout=0.5, filter=...)` inside a `while not self.stop_event.is_set():` loop.
     - Slicing ensures that even if zero packets arrive on the wire, the worker checks `stop_event` every 500ms and exits reliably without locking up.

6. **`airtrace/filters.py`:**
   - Non-destructive post-capture filtering:
     - `filter_packets(records: list[PacketRecord], protocol: str, search_query: str) -> list[PacketRecord]`
     - Protocol matching: `"ALL"`, `"TCP"`, `"UDP"`, `"ICMP"`, `"OTHER"`.
     - Substring search against `source_ip`, `destination_ip`, `source_port`, `destination_port`.
   - Pre-capture BPF validation: test-compiles BPF strings with Scapy before starting capture.

7. **`airtrace/exporter.py`:**
   - `export_to_csv(records: list[PacketRecord], filepath: Path) -> Path`:
     - Generates timestamped file: `captures/airtrace_capture_YYYYMMDD_HHMMSS.csv`.
     - Explicit columns: `packet_number,timestamp,protocol,source_ip,source_port,destination_ip,destination_port,packet_size_bytes,ip_total_length,ttl,tcp_flags,icmp_type,icmp_code`.
     - Guarantees zero application-layer payload bytes are saved.

---

## 4. Deep-Dive: Capture Lifecycle & Streamlit Rerun Safety

### The Problem
Streamlit re-executes the entire script (`app.py`) from top to bottom on every user interaction (e.g., clicking a button, selecting a dropdown item, filtering text, or auto-refresh timer firing).

If a capture thread were initiated naively in `app.py`:
1. Every click on the UI would spawn another background thread.
2. Multiple threads would hook the same Npcap interface simultaneously.
3. Packet counts would multiply by $N$ threads, corrupting statistics.
4. Stopping one thread would leave phantom threads running in the background.

### The Solution: Multi-Tiered Singleton Protection

```
Streamlit app.py (Reruns continuously on interaction / tick)
       │
       ▼
Check st.session_state["capture_controller"]
       │
       ├─► Not Present? -> Instantiate CaptureController() & store in session_state
       │
       └─► Present? -> Reuse existing CaptureController instance
                           │
       ┌───────────────────┴───────────────────┐
       ▼                                       ▼
User clicks "Start Capture"             User clicks "Stop Capture"
       │                                       │
controller.start()                      controller.stop()
       │                                       │
with self._lock:                        with self._lock:
  if self.is_running:                     self.stop_event.set()
    return (NO-OP / Ignore)               self.thread.join(timeout=2.0)
  self.is_running = True                  self.is_running = False
  spawn single worker thread              self.state = IDLE
```

### Why Scapy's Standard `AsyncSniffer.stop()` can hang on Windows
On Windows with Npcap, `sniff()` can block on the underlying kernel buffer if no packet arrives. Using `stop_filter` in Scapy does not help because `stop_filter` only executes *when a packet is received*. If the network is quiet, the thread hangs indefinitely!

**Airtrace's Sliced Sniffing Pattern:**
```python
def _worker_loop(self):
    while not self._stop_event.is_set():
        try:
            # Sniff in small slices (timeout=0.5s) with store=False
            sniff(
                iface=self.selected_iface,
                prn=self._handle_raw_packet,
                store=False,
                timeout=0.5,
                filter=self.bpf_filter or ""
            )
        except Exception as e:
            self._handle_error(e)
            break
```
- When `stop_event.set()` is called, the current 500ms slice completes and the loop terminates cleanly within 0.5 seconds.
- `store=False` guarantees Scapy never accumulates raw packet instances in internal lists.

---

## 5. Windows Packet-Capture Compatibility & Wi-Fi Realities

### Npcap Requirements
- Windows requires Npcap to capture raw network packets.
- Npcap must be installed in **WinPcap API-compatible mode**.
- Airtrace will implement an upfront hardware/driver diagnostic check in `airtrace/interfaces.py`:
  1. Detect if `scapy.arch.windows.get_windows_if_list()` succeeds.
  2. If Npcap is missing or unprivileged, Airtrace will display an actionable notification banner with a download link and command guide.
  3. **Built-in Synthetic Simulation Mode:** Airtrace will provide a toggleable "Demo / Synthetic Mode" that generates realistic simulated TCP, UDP, and ICMP traffic internally. This allows developers, mentors, and interviewers to run, test, and inspect Airtrace on any Windows machine without requiring admin installation of Npcap!

### Windows Wi-Fi Constraints
- **Ethernet Emulation:** On Windows, standard Wi-Fi adapters hand packets to Npcap as simulated Ethernet (DIX) frames (`0x0800` for IPv4).
- **Monitor Mode Limitations:** Normal Windows Wi-Fi drivers do not expose raw 802.11 Radiotap frames, 802.11 Management Beacons, Probe Requests, or accurate RSSI signals. Monitor mode on Windows requires specific supported wireless chipsets and Npcap OEM monitor mode.
- **Engineering Transparency:** Airtrace will clearly label captured Wi-Fi frames as "Ethernet-encapsulated IPv4 (Layer 3 over Layer 2 802.3 emulation)" and will not claim raw 802.11 frame capture unless native Radiotap headers are explicitly detected.

---

## 6. Dashboard UI Design (Anti-"AI-Slop" Principles)

The user explicitly required: **"dont make it as AI slop, make it attractive and easy to understand"**.

### Design Philosophy: High-Density Technical Cockpit
- **Tone:** Resembles high-end hardware diagnostic tooling (like Rohde & Schwarz or Wireshark Dark Mode), not a SaaS template with generic stock illustrations.
- **Palette (Derived from Airtrace Logo):**
  - **Base Canvas:** Deep Obsidian Navy (`#0B0F19`)
  - **Card Surfaces:** Dark Slate Navy (`#151C2C`) with 1px border (`#232F48`)
  - **Primary Brand / Accents:** Cyan Blue (`#00C8FF`) & Signal Blue (`#0066FF`)
  - **Semantic Indicators:**
    - Active / Capturing: Terminal Green (`#00E676`)
    - Warning / Paused: Amber (`#FFB300`)
    - Error / Drop: Coral Red (`#FF5252`)
    - Protocol Colors: TCP = Cyan (`#00D2FF`), UDP = Emerald (`#00E676`), ICMP = Violet (`#B388FF`), OTHER = Slate (`#90A4AE`)
- **Typography:**
  - Headers / Titles: Clean sans-serif (Inter / Segoe UI)
  - Data, IPs, Ports, Timestamps, Flags, Metrics: Monospace font (`JetBrains Mono`, `Consolas`, `Roboto Mono`)
- **Layout & Interaction:**
  1. **Top Header:** Airtrace logo, live pulsing status beacon (Idle / Capturing / Error), current capture duration, interface pill.
  2. **Control Strip:** Quick interface dropdown, BPF filter input with syntax validator, Start (Green), Stop (Red), Clear (Subtle Slate), Demo Mode Toggle.
  3. **KPI Ribbon (4 compact metric cards):**
     - Total Packets (formatted integer, e.g. `14,820`)
     - Total Volume (human-readable bytes, e.g. `18.4 MB`)
     - Instantaneous Throughput (`342 pkt/s` | `4.2 Mbps`)
     - Average Frame Size (`1,280 bytes`)
  4. **Analytics Split (2 Columns):**
     - Left: Protocol distribution donut chart with exact count & percentage badges.
     - Right: 60-second rolling traffic rate timeline (PPS / BPS).
  5. **Packet Explorer (Primary Workspace):**
     - Filter toolbar: Quick-select chips (`ALL`, `TCP`, `UDP`, `ICMP`, `OTHER`) + Fast text search box.
     - High-density data grid: Packet #, Time (HH:MM:SS.mmm), Proto, Source IP:Port, Dest IP:Port, Size, TTL, Flags/Details.
     - Click-to-inspect drawer / expansion panel showing full decoded header fields in structured key-value pairs.
  6. **Export Bar:** One-click CSV export button generating timestamped metadata files with download confirmation.

---

## 7. Testing & Wireshark Validation Strategy

### 1. 100% Offline Pytest Suite
Using Scapy's packet generation primitives, unit tests will verify all components without live network dependency:

```python
# Example Synthetic Test Fixtures:
tcp_packet = IP(src="192.168.1.100", dst="93.184.216.34", ttl=64, id=1024)/TCP(sport=54321, dport=443, flags="SA", seq=100, ack=200, window=65535)
udp_packet = IP(src="10.0.0.1", dst="1.1.1.1", ttl=128)/UDP(sport=61234, dport=53)
icmp_packet = IP(src="192.168.1.1", dst="192.168.1.254")/ICMP(type=8, code=0)
other_packet = IP(src="192.168.1.1", dst="224.0.0.1", proto=2) # IGMP
```

- **Decoder Tests (`test_decoder.py`):**
  - Verify exact IP header field extraction (src, dst, ttl, proto, len, id, flags).
  - Verify TCP port mapping, sequence/ack extraction, and flag string representation (`SYN, ACK`, `PSH, ACK`, `FIN, ACK`, etc.).
  - Verify UDP port and length extraction.
  - Verify ICMP type, code, and checksum extraction.
  - Verify graceful handling of malformed or non-IP packets (return `None` or `OTHER` without throwing exceptions).
- **Statistics Tests (`test_statistics.py`):**
  - Verify packet and byte increment accuracy.
  - Test rolling rate window calculation under simulated time deltas.
  - Test zero-time delta handling (avoid division by zero).
  - Test ring buffer truncation when reaching `MAX_PACKETS_HISTORY`.
- **Filtering Tests (`test_filters.py`):**
  - Test protocol filter (`TCP`, `UDP`, `ICMP`, `OTHER`).
  - Test case-insensitive IP substring search and port search.
- **Exporter Tests (`test_exporter.py`):**
  - Verify CSV column header matches PRD specification.
  - Verify row values, ISO 8601 timestamps, and empty-string placeholders for missing optional fields.
  - Verify that no raw payload data exists in CSV output.

### 2. Wireshark Cross-Validation Procedure
1. Configure Wireshark and Airtrace to capture on the identical interface (e.g. Wi-Fi adapter).
2. Set matching capture filters (e.g., `ip and host 1.1.1.1`).
3. Execute controlled traffic:
   - `ping -n 4 1.1.1.1` (ICMP validation)
   - `nslookup cloudflare.com 1.1.1.1` (UDP/TCP DNS validation)
   - `curl -I https://example.com` (TCP SYN/ACK/TLS handshake validation)
4. Compare packet counts, IP total length, TTL, and TCP sequence/ack numbers between Airtrace and Wireshark.

---

## 8. Technical Risks & Mitigations

| Risk | Probability | Severity | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **Npcap Not Installed on Windows** | High | High | Detect Npcap on launch; display clear setup instructions and provide an instant **Synthetic Demo Mode** so the app remains fully functional and testable. |
| **Streamlit Reruns Spawn Duplicate Workers** | High | High | Implement thread re-entrancy lock and session state singleton controller. If already capturing, ignore subsequent start signals. |
| **Scapy `sniff()` Hangs on Stop** | High | High | Implement sliced sniffing (`timeout=0.5s`) inside a `while not stop_event.is_set():` loop instead of unbounded blocking sniff. |
| **Memory Exhaustion Under Heavy Traffic** | Medium | Medium | Set `store=False` in Scapy to avoid holding raw packets. Use fixed-capacity ring buffer (`deque(maxlen=5000)`) for packet records. |
| **High Queue Latency / UI Freezing** | Medium | Medium | Drain packet queue in bounded batches (e.g., up to 100 packets per UI tick). Separate packet capture thread from UI thread. |
| **Missing Windows Administrator Rights** | Medium | Medium | Catch permissions errors gracefully, displaying a user-friendly error dialog instructing how to run terminal as Administrator or check Npcap security settings. |
| **False Claims of 802.11 Monitor Mode** | Low | High | Explicitly document and label Windows Wi-Fi capture as Ethernet-emulated IPv4 frames. Scope raw 802.11 frame analysis for Phase 3 on compatible hardware. |

---

## 9. Phased Implementation Roadmap

### Phase 1: Environment Setup & Core Foundations
- Setup project structure, `.gitignore`, and `requirements.txt`.
- Initialize `airtrace/models.py` with immutable, typed dataclasses.
- Implement `airtrace/decoder.py` for IPv4, TCP, UDP, ICMP, and OTHER.
- Implement offline synthetic packet generator and complete `test_decoder.py`.

### Phase 2: Interface Discovery & Capture Engine
- Implement `airtrace/interfaces.py` with Windows Npcap discovery and friendly name resolution.
- Implement `airtrace/capture.py` featuring the Sliced Sniffing Worker and `CaptureController` singleton with thread re-entrancy protection.
- Implement synthetic traffic generator for offline demo mode.
- Add lifecycle unit tests.

### Phase 3: Statistics Engine, Filters, & Exporter
- Implement `airtrace/statistics.py` with 5-second sliding rate windows and bounded history.
- Implement `airtrace/filters.py` for in-memory protocol filtering and IP/port search.
- Implement `airtrace/exporter.py` for sanitized CSV export.
- Write unit tests for statistics, filters, and exporter (`test_statistics.py`, `test_filters.py`, `test_exporter.py`).

### Phase 4: Streamlit Dashboard & UI Components
- Build `components/header.py` with Airtrace logo and live status pill.
- Build `components/capture_controls.py` for interface selection and start/stop/demo toggles.
- Build `components/metric_cards.py` for high-precision KPI metrics.
- Build `components/protocol_charts.py` for protocol distribution and rate timelines.
- Build `components/packet_table.py` and `components/packet_details.py` for packet inspection.
- Assemble into `app.py` with auto-refresh mechanism and clean, dark-mode styling.

### Phase 5: Verification, Documentation, & Git Delivery
- Run full pytest test suite and achieve 100% test pass rate.
- Conduct live/simulated capture verification.
- Document Wireshark equivalence testing in README.
- Commit clean codebase and push to GitHub repository (`origin/main`).

---

## 10. Acceptance Criteria Checklist

- [ ] Interface discovery lists readable Windows interfaces and detects Npcap status.
- [ ] Synthetic demo mode allows full functionality without Npcap.
- [ ] Start and Stop controls operate reliably without freezing or spawning duplicate threads on rerun.
- [ ] IPv4 packets are classified correctly in order: TCP -> UDP -> ICMP -> OTHER.
- [ ] Header fields (IP, TCP flags, sequence numbers, UDP ports, ICMP codes) are decoded accurately.
- [ ] Dashboard displays Total Packets, Total Bytes, Rolling PPS, Rolling BPS, and protocol breakdown.
- [ ] Packet Explorer supports protocol filtering and IP/port text search.
- [ ] CSV export produces valid, uncorrupted metadata without raw packet payloads.
- [ ] All unit tests pass cleanly with `pytest`.
- [ ] Git repository is synchronized with `main` on GitHub.
