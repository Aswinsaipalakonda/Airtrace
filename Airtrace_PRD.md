# Airtrace --- Product Requirements Document (PRD)

**Product:** Airtrace\
**Document type:** Product Requirements Document\
**Version:** 1.0\
**Status:** Ready for implementation planning\
**Primary platform:** Windows 10/11 (initial target)\
**Project category:** Network traffic analysis / wireless systems
engineering portfolio project

------------------------------------------------------------------------

## 1. Product Summary

Airtrace is a Python-based network traffic analyzer that captures
packets from a user-selected network interface, decodes supported
protocol headers, calculates traffic statistics, and presents the
results through a local dashboard.

The initial release focuses on IPv4 TCP, UDP, and ICMP traffic. It
should help a user understand what is happening on a network by showing
packet metadata such as timestamps, source and destination IP addresses,
ports, protocol, packet size, TTL, and TCP flags.

Airtrace is intended as an educational and engineering portfolio
project. It is not intended to replace Wireshark, perform intrusion
prevention, decrypt encrypted traffic, or monitor networks without
authorization.

### Product positioning

**Airtrace --- Inspect. Understand. Analyze.**

The product should prioritize correct packet capture and protocol
interpretation over visual effects. The dashboard is a presentation
layer over a reliable packet-processing core.

------------------------------------------------------------------------

## 2. Problem Statement

Network traffic is difficult to understand when it is represented only
as raw packets or command-line output. Students and junior engineers
need a practical tool to observe protocol behavior, inspect packet
headers, compare traffic patterns, and understand the relationship
between TCP/IP and wireless networking.

Airtrace addresses this by providing:

-   Live packet capture from a selected interface.
-   Readable decoding of supported protocol headers.
-   Protocol distribution and traffic-rate statistics.
-   Searchable packet metadata.
-   CSV export for further analysis.
-   A foundation for later IEEE 802.11 frame analysis.

------------------------------------------------------------------------

## 3. Goals and Success Criteria

### 3.1 Goals

1.  Capture IPv4 packets from a selected network interface.
2.  Identify and count TCP, UDP, ICMP, and other IPv4 traffic.
3.  Decode relevant IP and transport-layer header fields.
4.  Present packet activity in a responsive local dashboard.
5.  Export captured metadata to CSV.
6.  Validate results against Wireshark during development.
7.  Keep the code modular, testable, and explainable in a technical
    interview.

### 3.2 MVP success criteria

The MVP is accepted when:

-   The user can see available interfaces and select one.
-   The user can start and stop a capture without restarting the
    application.
-   Captured IPv4 packets are classified correctly as TCP, UDP, ICMP, or
    OTHER.
-   Packet rows show timestamp, source/destination IP, protocol, packet
    length, and applicable ports.
-   TCP rows show source/destination ports and TCP flags.
-   The dashboard shows total packets, total bytes, protocol counts,
    packets per second, and bytes per second.
-   The user can filter the visible packet list by protocol and search
    IP addresses or ports.
-   The user can export the current capture metadata to CSV.
-   Capture errors, missing permissions, and unavailable interfaces are
    shown clearly.
-   Unit tests cover protocol classification, field extraction, and
    statistics calculations.

------------------------------------------------------------------------

## 4. Target Users

### Primary user

A student, networking learner, or junior engineer who wants to inspect
traffic on their own computer or an authorized test network.

### Secondary user

An interviewer, mentor, or reviewer evaluating the developer's
understanding of packet capture, TCP/IP, protocol headers, and wireless
networking fundamentals.

------------------------------------------------------------------------

## 5. Scope

### 5.1 MVP --- Must Have

  -------------------------------------------------------------------------
  ID                      Feature                 Description
  ----------------------- ----------------------- -------------------------
  MVP-01                  Interface discovery     List capture interfaces
                                                  and allow selection

  MVP-02                  Capture controls        Start and stop packet
                                                  capture

  MVP-03                  IPv4 decoding           Extract source IP,
                                                  destination IP, TTL,
                                                  protocol number, and IP
                                                  length

  MVP-04                  TCP decoding            Extract ports,
                                                  sequence/acknowledgment
                                                  numbers, and flags

  MVP-05                  UDP decoding            Extract
                                                  source/destination ports,
                                                  length, and checksum

  MVP-06                  ICMP decoding           Extract type, code, and
                                                  checksum

  MVP-07                  Protocol classification Count TCP, UDP, ICMP, and
                                                  OTHER packets

  MVP-08                  Packet table            Display captured packet
                                                  metadata

  MVP-09                  Statistics              Display packet count,
                                                  bytes, protocol
                                                  distribution, and traffic
                                                  rates

  MVP-10                  Filtering               Filter by protocol and
                                                  search IP/port values

  MVP-11                  CSV export              Export packet metadata
                                                  without payload contents

  MVP-12                  Error handling          Explain common capture
                                                  and permission errors
  -------------------------------------------------------------------------

### 5.2 Phase 2 --- Recommended Enhancements

-   DNS query/response metadata (when DNS is visible and decodable).
-   TCP flag distribution (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR).
-   Top source and destination IP addresses.
-   Packet-size distribution.
-   Traffic timeline chart.
-   Configurable capture filter.
-   Capture duration and packet limit.
-   Save and reload metadata capture sessions.
-   IPv6 support, with clearly separated IPv6 decoding and tests.
-   Optional PCAP export for opening captures in Wireshark. PCAP export
    must be explicitly enabled because packet captures can contain
    sensitive data.

### 5.3 Phase 3 --- Wireless Analysis Extension

This is a separate extension, not a promise of the MVP.

Potential capabilities:

-   IEEE 802.11 management, control, and data frame identification.
-   Beacon and probe request/response inspection.
-   BSSID and transmitter/receiver MAC address extraction.
-   Channel and signal information when available from Radiotap
    metadata.
-   RSSI display when the adapter and driver provide it.

**Hardware and operating-system limitation:** Normal Windows Wi-Fi
capture usually exposes traffic in an Ethernet-like representation and
does not guarantee raw 802.11 frames. Monitor mode requires a compatible
wireless adapter, driver, and capture stack. Npcap support varies by
adapter and driver. For reliable 802.11 monitor-mode experimentation, a
supported Linux environment and compatible USB Wi-Fi adapter may be
required. Do not represent ordinary Wi-Fi packet capture as full
over-the-air 802.11 analysis.

------------------------------------------------------------------------

## 6. Out of Scope

The following are explicitly excluded from the initial release:

-   Capturing traffic on networks without permission.
-   Decrypting HTTPS, TLS, WPA, or other encrypted communications.
-   Password collection, credential interception, or payload harvesting.
-   Active packet injection, spoofing, deauthentication, or network
    disruption.
-   Intrusion prevention or automatic blocking.
-   Deep packet inspection of application payloads.
-   Cloud accounts, user registration, remote telemetry, or a hosted
    backend.
-   Claims of full wireless spectrum analysis.
-   Claims that the application can see every device's traffic on a
    switched network.

Airtrace should operate as a local, passive analysis tool.

------------------------------------------------------------------------

## 7. Functional Requirements

### 7.1 Interface selection

-   On launch, discover interfaces using Scapy.
-   Display a readable interface label and its underlying interface
    identifier.
-   Allow the user to refresh the interface list.
-   Require an explicit interface selection before starting capture.
-   Show a helpful message if no interfaces are available.
-   Do not silently choose an interface.

### 7.2 Capture lifecycle

The capture engine must support:

-   Start capture.
-   Stop capture.
-   Current capture status: Idle, Capturing, Stopping, or Error.
-   Capture start time and elapsed duration.
-   Optional packet limit and capture duration.
-   Graceful shutdown when the user stops capture or closes the
    application.

Capture must not run on the dashboard's main UI thread. Use a background
worker/thread and a thread-safe queue or equivalent controlled data
handoff.

Avoid starting duplicate capture workers when the user clicks Start
repeatedly. Ensure Stop actually stops the underlying sniffing process.

### 7.3 Packet decoding

For every captured IPv4 packet, extract:

**IP layer** - Source IPv4 address. - Destination IPv4 address. - TTL. -
IP protocol number. - IP total length. - Identification field. -
Fragment offset and flags, where available.

**TCP layer** - Source port. - Destination port. - Sequence number. -
Acknowledgment number. - Header length. - Flags. - Window size.

**UDP layer** - Source port. - Destination port. - UDP length. -
Checksum.

**ICMP layer** - Type. - Code. - Checksum. - Identifier and sequence
number when present.

If a field does not apply or is unavailable, show `—` or a null value.
Do not fabricate values.

Classify packets in this order: 1. TCP 2. UDP 3. ICMP 4. OTHER

Only classify a packet as TCP, UDP, or ICMP when the corresponding
decoded layer is present.

### 7.4 Packet table

The packet table should support these columns:

-   Packet number.
-   Timestamp.
-   Protocol.
-   Source IP.
-   Source port.
-   Destination IP.
-   Destination port.
-   Packet length in bytes.
-   TTL.

Selecting a row should open a packet-details panel with the decoded IP
and transport-layer fields.

Do not display raw payload bytes by default. The default product
experience should be metadata-focused.

### 7.5 Statistics

Calculate and display:

-   Total packets captured.
-   Total captured bytes.
-   TCP packet count.
-   UDP packet count.
-   ICMP packet count.
-   OTHER packet count.
-   Packets per second.
-   Bytes per second.
-   Average packet size.
-   Top source IPs.
-   Top destination IPs.

Use a clearly defined time window for traffic-rate calculations (for
example, a rolling 1-second or 5-second window). Label the chosen window
in the UI.

Do not confuse packet count with byte count. Use the captured frame
length for total captured bytes and separately expose the IPv4
total-length field if useful.

### 7.6 Filters and search

-   Protocol filter: All, TCP, UDP, ICMP, OTHER.
-   Search by source IP, destination IP, source port, or destination
    port.
-   Filters must affect the displayed table, not silently alter
    historical capture statistics.
-   Provide a clear/reset filters action.

### 7.7 CSV export

Export one row per captured packet with metadata fields:

`packet_number, timestamp, protocol, source_ip, source_port, destination_ip, destination_port, packet_size_bytes, ip_total_length, ttl, tcp_flags, icmp_type, icmp_code`

-   Use an unambiguous timestamp format, preferably ISO 8601.
-   Keep unavailable fields empty.
-   Do not include application payload data.
-   Use a timestamped filename such as
    `airtrace_capture_YYYYMMDD_HHMMSS.csv`.

------------------------------------------------------------------------

## 8. User Experience and Interface Requirements

### 8.1 Design direction

Create a clean, professional engineering dashboard. The interface should
feel like a serious network diagnostic tool, not a generic admin
template.

-   Dark navy/charcoal foundation.
-   Cyan and blue as primary accent colors.
-   Green, amber, and red only for meaningful status or alert states.
-   Clear typography and compact data presentation.
-   Consistent spacing and restrained rounded corners.
-   Avoid excessive gradients, glow effects, animations, and decorative
    cards.
-   Prioritize readability of packet tables and technical values.

### 8.2 Main dashboard layout

**A. Header** - Airtrace logo. - Product name: Airtrace. - Current
capture status indicator. - Theme may be dark-only for MVP.

**B. Capture toolbar** - Interface selector. - Refresh interfaces. -
Optional BPF capture filter input. - Start Capture button. - Stop
Capture button. - Capture duration / status.

**C. Overview metrics** - Total Packets. - Total Data. - Packets/sec. -
Bytes/sec.

**D. Protocol analytics** - Protocol distribution chart. - Traffic over
time chart. - TCP flags distribution (Phase 2).

**E. Packet explorer** - Protocol filter. - Search field. - Packet
table. - Selected packet details panel.

**F. Export** - Export CSV action. - Clear current session action, with
confirmation.

### 8.3 Empty and error states

Provide clear states for:

-   No interface selected.
-   No packets captured yet.
-   Capture in progress.
-   Capture stopped.
-   Permission denied.
-   Npcap not installed or unavailable.
-   Selected interface disappeared.
-   Invalid capture filter.
-   Export failure.

Never leave the user with a blank dashboard when an operation fails.

------------------------------------------------------------------------

## 9. Technical Architecture

### 9.1 Recommended stack

  -----------------------------------------------------------------------
  Layer                   Technology              Responsibility
  ----------------------- ----------------------- -----------------------
  Language                Python 3.11+            Application logic

  Packet capture          Scapy                   Capture and decode
                                                  packets

  Windows capture driver  Npcap                   Packet capture support
                                                  on Windows

  Dashboard               Streamlit               Local web-based UI

  Data handling           Python dataclasses /    Packet records and
                          standard library        state

  Statistics              collections, deque,     Counters and rolling
                          statistics              rates

  Export                  Python csv module or    CSV generation
                          pandas                  

  Charts                  Plotly or Streamlit     Protocol and traffic
                          charts                  charts

  Testing                 pytest                  Unit and integration
                                                  tests

  Validation              Wireshark               Independent
                                                  packet-capture
                                                  comparison
  -----------------------------------------------------------------------

Use stable, compatible package versions and pin them in
`requirements.txt` after testing.

### 9.2 Architecture overview

``` text
┌──────────────────────────────────────────────┐
│                Streamlit UI                  │
│  Interface | Start/Stop | Metrics | Charts   │
│               Packet Explorer                │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│              Capture Controller              │
│ Lifecycle | Interface | Filter | Shutdown    │
└──────────────────────┬───────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────┐
│              Scapy Capture Worker             │
│              sniff / AsyncSniffer             │
└──────────────────────┬───────────────────────┘
                       │ packets
                       ▼
┌──────────────────────────────────────────────┐
│               Packet Decoder                 │
│ IPv4 | TCP | UDP | ICMP | OTHER              │
└──────────────────────┬───────────────────────┘
                       │ normalized records
                       ▼
┌──────────────────────────────────────────────┐
│              Statistics Engine               │
│ Counters | Rates | Top IPs | Histograms      │
└──────────────────────┬───────────────────────┘
                       │
             ┌─────────┴─────────┐
             ▼                   ▼
┌──────────────────────┐  ┌────────────────────┐
│ Dashboard / Explorer │  │ CSV Export Service │
└──────────────────────┘  └────────────────────┘
```

### 9.3 Suggested project structure

``` text
airtrace/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── airtrace/
│   ├── __init__.py
│   ├── config.py
│   ├── models.py
│   ├── interfaces.py
│   ├── capture.py
│   ├── decoder.py
│   ├── statistics.py
│   ├── filters.py
│   └── exporter.py
│
├── components/
│   ├── header.py
│   ├── capture_controls.py
│   ├── metric_cards.py
│   ├── protocol_charts.py
│   ├── packet_table.py
│   └── packet_details.py
│
├── tests/
│   ├── test_decoder.py
│   ├── test_statistics.py
│   ├── test_filters.py
│   └── test_exporter.py
│
├── assets/
│   └── airtrace-logo.png
│
└── captures/
    └── .gitkeep
```

Keep packet decoding and statistics independent from Streamlit. This
makes the core testable and prevents UI reruns from creating duplicate
capture workers.

### 9.4 Data model

Create a normalized packet record, preferably using a Python dataclass.

Suggested fields:

``` python
@dataclass
class PacketRecord:
    packet_number: int
    timestamp: str
    protocol: str
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    packet_size_bytes: int
    ip_total_length: int | None
    ttl: int | None
    tcp_flags: str | None
    tcp_sequence: int | None
    tcp_acknowledgment: int | None
    udp_length: int | None
    icmp_type: int | None
    icmp_code: int | None
```

The implementation may extend this model if needed, but keep field names
consistent across the decoder, UI, tests, and CSV exporter.

### 9.5 Capture implementation guidance

-   Prefer Scapy's `AsyncSniffer` or a carefully managed background
    worker.
-   Set `store=False` to avoid retaining duplicate Scapy packet objects
    in memory.
-   Use a callback to decode each packet and pass normalized records to
    a thread-safe queue.
-   Do not perform expensive chart rendering or CSV disk writes directly
    inside the packet callback.
-   Drain the queue in controlled batches from the UI/application layer.
-   Protect shared counters and session state from concurrent
    modification.
-   Implement a bounded in-memory packet history to prevent unlimited
    memory growth.
-   Track dropped/omitted UI records if the queue or display limit is
    reached.
-   Ensure the capture worker can be stopped and joined cleanly.
-   Do not use a hard-coded interface name.

------------------------------------------------------------------------

## 10. Security, Privacy, and Responsible Use

Airtrace is a passive educational analyzer.

1.  Display a notice that users must capture only traffic they own or
    are authorized to inspect.
2.  Do not capture or store payload contents by default.
3.  Do not collect passwords, cookies, tokens, or credentials.
4.  Do not transmit captured data to external services.
5.  Keep capture files local.
6.  Make PCAP export an optional, explicit feature if added later.
7.  Do not run with elevated privileges unless the capture driver
    requires it.
8.  Explain that packet metadata can still reveal sensitive information.
9.  Add generated captures and local exports to `.gitignore`.
10. Do not commit real packet captures to GitHub.

------------------------------------------------------------------------

## 11. Performance and Reliability Requirements

-   The UI must remain responsive while capture is active.
-   Capture callbacks should perform minimal work.
-   Packet history must have a configurable maximum size.
-   Statistics should update at a controlled interval rather than on
    every packet.
-   The application should handle bursts of traffic without crashing.
-   Stop Capture must stop the capture worker reliably.
-   Exceptions must be logged and surfaced in a user-friendly way.
-   The application should work on a normal personal computer for
    learning-scale traffic.
-   Do not promise line-rate capture or production-grade performance
    without benchmarking.

------------------------------------------------------------------------

## 12. Testing and Validation Plan

### 12.1 Unit tests

Test decoder behavior using synthetic Scapy packets. Do not require live
network access for unit tests.

Test cases:

-   TCP packet is classified as TCP.
-   UDP packet is classified as UDP.
-   ICMP packet is classified as ICMP.
-   IPv4 packet with another transport protocol is classified as OTHER.
-   Source/destination addresses are extracted correctly.
-   Ports are extracted correctly for TCP and UDP.
-   TCP flags are decoded correctly.
-   ICMP type and code are extracted correctly.
-   Missing optional fields are handled safely.
-   Packet and byte counters increment correctly.
-   Traffic-rate calculations handle zero elapsed time.
-   CSV output contains the expected columns and values.

### 12.2 Manual test plan

  ------------------------------------------------------------------------
  Test                    Action                   Expected result
  ----------------------- ------------------------ -----------------------
  T-01                    Launch app               Interfaces are listed

  T-02                    Start without selecting  Clear validation
                          interface                message

  T-03                    Select interface and     Capture status becomes
                          start                    Capturing

  T-04                    Run `ping 1.1.1.1`       ICMP packets appear
                                                   when visible

  T-05                    Run                      DNS traffic may appear
                          `nslookup example.com`   as UDP or TCP depending
                                                   on resolver behavior

  T-06                    Browse an HTTPS website  TCP traffic appears
                                                   when visible; UDP may
                                                   also appear due to QUIC

  T-07                    Stop capture             Worker stops and
                                                   statistics remain
                                                   visible

  T-08                    Filter TCP               Only TCP rows remain in
                                                   the displayed table

  T-09                    Search an IP address     Matching rows are
                                                   displayed

  T-10                    Export CSV               A valid CSV file is
                                                   generated

  T-11                    Compare with Wireshark   Matching packets/fields
                                                   agree when interface,
                                                   filters, and capture
                                                   window are equivalent

  T-12                    Run without capture      Helpful error message
                          permissions              appears
  ------------------------------------------------------------------------

Do not expect browsing to generate only TCP. Modern browsers may use
QUIC over UDP.

### 12.3 Wireshark validation

Use Wireshark as an independent reference tool. Compare a controlled
capture using the same interface, filter, and time window. Differences
can occur because of capture timing, offloading, filtering, driver
behavior, and packets captured before or after the application starts.

------------------------------------------------------------------------

## 13. Development Milestones

### Milestone 1 --- Environment and capture proof

-   Create the Python virtual environment.
-   Install Scapy and Npcap.
-   Enumerate interfaces.
-   Capture a small number of packets.
-   Verify that capture works with the selected adapter.

**Exit criteria:** A minimal script captures packets and stops cleanly.

### Milestone 2 --- Decoder and tests

-   Implement normalized packet model.
-   Decode IPv4, TCP, UDP, and ICMP.
-   Add protocol classification.
-   Add unit tests using synthetic packets.

**Exit criteria:** Decoder tests pass and output fields are correct.

### Milestone 3 --- Capture controller and statistics

-   Implement start/stop lifecycle.
-   Add background capture worker and queue.
-   Implement packet/byte counters and traffic rates.
-   Add bounded packet history.

**Exit criteria:** Capture runs without freezing the UI or creating
duplicate workers.

### Milestone 4 --- Dashboard

-   Build capture controls.
-   Build overview metrics.
-   Build protocol charts.
-   Build packet explorer and details panel.
-   Add filtering and search.

**Exit criteria:** A user can operate and inspect a live capture from
the dashboard.

### Milestone 5 --- Export, validation, and documentation

-   Implement CSV export.
-   Validate with Wireshark.
-   Add screenshots and sample synthetic data.
-   Write README setup and usage instructions.
-   Document Windows capture limitations.

**Exit criteria:** Another developer can install, run, test, and
understand the project.

### Milestone 6 --- Wireless extension (after MVP)

-   Evaluate adapter and driver monitor-mode support.
-   Set up a compatible test environment.
-   Capture authorized 802.11 traffic.
-   Decode management frame subtypes and Radiotap metadata where
    available.
-   Clearly label unavailable signal/channel fields.

**Exit criteria:** Demonstrate actual 802.11 frame analysis with
documented hardware and test conditions.

------------------------------------------------------------------------

## 14. Documentation Requirements

The GitHub README must include:

1.  Project overview and objective.
2.  Feature list.
3.  Architecture diagram.
4.  Technology stack.
5.  Installation instructions for Windows.
6.  Npcap installation and permissions guidance.
7.  How to identify and select an interface.
8.  How to start and stop capture.
9.  Example screenshots.
10. Unit test instructions.
11. Wireshark validation method.
12. Known limitations.
13. Privacy and authorized-use notice.
14. Future wireless-analysis roadmap.

Do not claim that a feature is implemented unless it is present and
tested.

------------------------------------------------------------------------

## 15. Risks and Mitigations

  -----------------------------------------------------------------------
  Risk                    Impact                  Mitigation
  ----------------------- ----------------------- -----------------------
  Npcap or driver         Capture may fail        Check installation and
  incompatibility                                 show actionable
                                                  diagnostics

  Wrong interface         Little or no traffic    Show interface details
  selected                appears                 and allow refresh

  Missing administrator   Capture may fail        Explain required
  permissions                                     permissions without
                                                  silently escalating

  UI reruns create        Duplicate captures and  Centralize capture
  duplicate workers       incorrect statistics    lifecycle outside UI
                                                  rendering

  High packet volume      UI lag or memory growth Queue batching, bounded
                                                  history, minimal
                                                  callback

  Capture results differ  Confusing validation    Match interface,
  from Wireshark                                  filters, and capture
                                                  time window

  Wi-Fi monitor mode      No raw 802.11 frames    Treat wireless
  unavailable                                     extension separately
                                                  and document hardware
                                                  requirements

  Sensitive metadata is   Privacy risk            Local-only storage,
  exported                                        metadata-only default,
                                                  clear export action
  -----------------------------------------------------------------------

------------------------------------------------------------------------

## 16. Definition of Done

The MVP is complete only when:

-   All MVP requirements are implemented.
-   The application starts using documented commands.
-   Interface selection and capture lifecycle work.
-   TCP, UDP, ICMP, and OTHER classification is tested.
-   Packet details and statistics are correct for test packets.
-   Filtering and CSV export work.
-   Unit tests pass.
-   Wireshark validation has been performed and documented.
-   No real packet captures or sensitive data are committed to the
    repository.
-   README explains setup, usage, limitations, and authorized-use
    requirements.

------------------------------------------------------------------------

## 17. Instructions for the Antigravity Development Agent

Treat this PRD as the source of truth. Do not begin by generating the
entire application in one pass.

### First task: planning only

1.  Inspect the workspace and existing files before changing anything.
2.  Review this PRD and identify ambiguities, technical risks, and
    Windows-specific capture constraints.
3.  Produce a detailed implementation plan with:
    -   Architecture and module responsibilities.
    -   Data flow and thread-safety approach.
    -   Dependency list and version strategy.
    -   Capture lifecycle design.
    -   UI component plan.
    -   Unit and manual test plan.
    -   Milestones and acceptance criteria.
4.  Explain how Streamlit reruns will be prevented from starting
    duplicate capture workers.
5.  Explain how the capture worker will stop reliably.
6.  Explain the exact approach for testing packet decoding without live
    network access.
7.  Identify what can and cannot be captured on Windows using the
    selected Wi-Fi adapter.
8.  Do not claim 802.11 monitor-mode support until hardware and driver
    compatibility have been verified.

### Implementation rules

After the plan is reviewed and implementation is authorized:

-   Implement one milestone at a time.
-   Keep packet decoding independent from the UI.
-   Write tests alongside each core module.
-   Run tests after every milestone and fix failures before proceeding.
-   Do not hard-code network interface identifiers.
-   Do not store raw packet payloads by default.
-   Do not add a backend, database, authentication, or cloud service
    unless separately justified and approved.
-   Avoid unnecessary abstractions and dependencies.
-   Keep the UI professional, compact, and technically readable.
-   Update README and requirements as implementation evolves.
-   Do not mark a feature complete until it has been run and verified.
-   At each milestone, report files changed, commands executed, test
    results, known issues, and the next milestone.

**Initial deliverable:** A planning document and implementation
sequence. Do not write application code until the plan is complete.
