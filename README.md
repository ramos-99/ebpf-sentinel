# ebpf-sentinel

<div align="center">

![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![eBPF](https://img.shields.io/badge/eBPF-FF6600?style=for-the-badge&logo=linux&logoColor=white)

**Kernel-level security monitor with self-supervised ML anomaly detection**

</div>

---

## 🎯 Overview

**ebpf-sentinel** is a process and network monitor built on eBPF technology. It collects kernel-level telemetry and uses machine learning to detect behavioral anomalies — learning what's "normal" for your specific system and alerting on deviations.

## ✨ Features

- **Real-time Process Monitoring** — Intercepts `execve` syscalls to track all process executions
- **Kernel-Level Visibility** — Uses eBPF kprobes for zero-overhead introspection
- **Lightweight** — No kernel modules required, runs entirely in user space
- **Self-Supervised ML** — Learns your system's baseline behavior, no external datasets needed

## 📋 Roadmap

- [x] **Phase 1**: Process execution monitoring (`sys_execve`)
- [ ] **Phase 2**: Network monitoring (TCP connect/accept)
- [ ] **Phase 3**: File access monitoring (`sys_openat`)
- [ ] **Phase 3.5**: Data persistence (SQLite/Parquet for ML training)
- [ ] **Phase 4**: ML-based anomaly detection & alerting

## 🧠 Phase 4: Machine Learning Strategy

The anomaly detection system uses a **self-supervised learning** approach:

### Data Collection
```
1 week × 24h × ~1000 events/hour = ~168,000+ training samples
```

### Learning Mode
| Phase | Mode | Description |
|-------|------|-------------|
| Week 1 | **Learning** | Collect baseline data, no alerts |
| After | **Detection** | Compare against learned patterns, alert on anomalies |

### What the Model Learns
- **Temporal patterns** — which processes run at what times (cron jobs, backups)
- **Process graphs** — parent-child relationships (`bash` → `nvim` → `rg` = normal)
- **Frequency baselines** — how often each binary is called per hour/day
- **Network context** — which processes make TCP connections (Phase 2 data)

### Techniques
| Algorithm | Use Case |
|-----------|----------|
| **Isolation Forest** | Detect outlier behavior with low overhead |
| **Autoencoder** | Learn compressed representation of "normal" and flag deviations |
| **LSTM** | Sequence anomaly detection for process chains |

> 💡 **Key Insight**: Your own system's behavior becomes the training data. No external datasets needed—the monitor runs 24/7 and learns what's "normal" for *your* machine.

## 🔧 Requirements

- Linux (tested on Arch, works on Ubuntu/Debian/Fedora with BCC)
- Linux kernel headers
- BCC (BPF Compiler Collection)
- Python 3.8+

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/ebpf-sentinel.git
cd ebpf-sentinel
```

### 2. Run Setup

```bash
make setup
```

This will:
- Install system dependencies (`bcc`, `bcc-tools`, `python-bcc`, `linux-headers`)
- Create a hybrid Python virtual environment
- Install Python dependencies

### 3. Start Monitoring

```bash
make run
```

> ⚡ **Note**: eBPF requires root privileges. The command will prompt for sudo.

### Example Output

```
⚡ Process Monitor Active... (Ctrl+C to exit)
PID: 12345  | UID: 1000   | Process: bash            -> Executed: /usr/bin/ls
PID: 12346  | UID: 1000   | Process: ls              -> Executed: /usr/bin/grep
PID: 12347  | UID: 0      | Process: sudo            -> Executed: /usr/bin/pacman
```

## 📁 Project Structure

```
ebpf-sentinel/
├── src/
│   ├── __init__.py
│   ├── main.py              # Entry point
│   └── probes/
│       ├── __init__.py
│       └── process.py       # eBPF process monitor
├── Makefile                 # Build & run automation
├── requirements.txt         # Python dependencies
└── README.md
```

## 🛠️ Development

### Clean Environment

```bash
make clean
```

### Manual Run (without Make)

```bash
sudo PYTHONPATH=. ./venv/bin/python src/main.py
```

## ⚙️ How It Works

1. **eBPF Program** — A small C program is compiled and loaded into the kernel
2. **Kprobe Attachment** — The program attaches to `sys_execve` syscall
3. **Event Capture** — Every process execution triggers the probe
4. **Perf Buffer** — Events are sent to user space via a high-performance ring buffer
5. **Python Processing** — The Python app decodes and displays events in real-time

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

---

<div align="center">
<sub>Built with ⚡ for learning and security research</sub>
</div>
