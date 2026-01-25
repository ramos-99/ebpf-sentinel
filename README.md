# eBPF-Sentinel

![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat-square&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![eBPF](https://img.shields.io/badge/eBPF-FF6600?style=flat-square&logo=linux&logoColor=white)

**Kernel-level security monitor with self-supervised ML anomaly detection.**

## Overview

eBPF-Sentinel is a high-performance security monitoring tool designed to detect behavioral anomalies in real-time. By leveraging eBPF (Extended Berkeley Packet Filter), it collects deep kernel telemetry with minimal system overhead. The system is designed to learn baseline behavior patterns through self-supervised machine learning, enabling it to flag deviations without reliance on external signature databases.

## Key Features

*   **Process Execution Monitoring:** Intercepts `execve` syscalls via tracepoints to track all process spawning events.
*   **Network Traffic Visibility:** Monitors TCP connections (both connect and accept) with full IPv4/IPv6 dual-stack support.
*   **Kernel-Level Introspection:** Utilizes eBPF kprobes and tracepoints for zero-overhead observability.
*   **User Space Implementation:** Runs entirely in user space without requiring custom kernel modules.
*   **Self-Supervised Learning:** Learns system-specific baseline behavior to detect zero-day anomalies.

## Implementation Status

| Phase | Component | Status | Description |
|-------|-----------|--------|-------------|
| **1** | Process Monitor | ✅ Complete | `sys_execve` tracepoint integration |
| **2** | Network Monitor | ✅ Complete | TCP connect/accept, IPv6 support |
| **3** | File Monitor | 🚧 Planned | `sys_openat` monitoring |
| **4** | ML Detection | 🚧 Planned | Anomaly detection engine |

## Architecture & Design

### Core Components
1.  **eBPF Probes:** C programs compiled and loaded into the kernel to capture events at the source (kprobes/tracepoints).
2.  **Perf Buffer:** High-performance ring buffer for transferring data from kernel to user space.
3.  **Python Consumer:** User-space application that processes events, manages state, and renders the TUI.
4.  **Process Cache:** In-memory O(1) cache for tracking process ancestry and filtering system noise.

### Machine Learning Strategy
The anomaly detection engine employs a self-supervised approach:
*   **Data Collection:** Continuous aggregation of process executions and network flows.
*   **Baseline Learning:** Utilization of Isolation Forests and Autoencoders to model "normal" system behavior.
*   **Anomaly Detection:** Real-time scoring of events against the learned baseline to identify outliers.

## Prerequisites

*   Linux Kernel 5.8+ (Required for CO-RE features)
*   BCC (BPF Compiler Collection)
*   Python 3.10+
*   Root privileges (for loading eBPF programs)

## Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/ebpf-sentinel.git
    cd ebpf-sentinel
    ```

2.  **Setup environment:**
    ```bash
    make setup
    ```
    This command installs necessary system dependencies (`bcc`, `linux-headers`) and sets up the Python virtual environment.

3.  **Run the monitor:**
    ```bash
    make run
    ```
    *Note: Sudo privileges are required to load eBPF programs.*

## Project Structure

```
ebpf-sentinel/
├── src/
│   ├── main.py              # Application entry point & TUI
│   ├── probes/
│   │   ├── process.py       # eBPF process monitor implementation
│   │   ├── network.py       # eBPF network monitor (IPv4/IPv6)
│   │   └── cache.py         # Process ancestry cache
│   └── config.py            # Configuration & filtering rules
├── docs/                    # Architecture Decision Records (ADR)
├── Makefile                 # Build automation
└── requirements.txt         # Python dependencies
```

## License

MIT License. See [LICENSE](LICENSE) for details.
