# Architecture Decision Records (ADR)

This document records the key architectural decisions made during the development of ebpf-sentinel.

---

## ADR-001: Process Monitoring - Tracepoints vs Kprobes

**Date:** 2025-01-XX  
**Status:** Accepted

### Context
Initially, `kprobe` was used on `sys_execve` to detect new process executions.

### Problem
On recent kernels (Arch Linux 6.12+), *Syscall Wrappers* altered the CPU register order. The code was reading garbage memory instead of the filename.

### Decision
Migrate to **Tracepoints** (`tracepoint:syscalls:sys_enter_execve`).

### Consequences
- ✅ Direct access to `args->filename` guaranteed by Kernel API
- ✅ Works regardless of underlying architecture
- ✅ More stable across kernel versions

---

## ADR-002: Network Monitoring - Kprobes on tcp_v4_connect

**Date:** 2025-01-XX  
**Status:** Accepted

### Context
Requirement to capture outbound TCP traffic.

### Decision
Use **Kprobe** on `tcp_v4_connect` instead of tracepoint on `sys_enter_connect`.

### Justification
`tcp_v4_connect` provides direct access to `struct sock`, simplifying extraction of destination IP and port. Using a syscall tracepoint would require complex parsing of userspace `sockaddr` structures.

---

## ADR-003: Concurrency - Multiprocessing vs Threading

**Date:** 2025-01-XX  
**Status:** Accepted

### Decision
Use `multiprocessing.Process` (fork) instead of `threading`.

### Justification
Python's Global Interpreter Lock (GIL) prevents true parallel CPU execution. eBPF generates high-volume events requiring Process Monitor and Network Monitor to run on distinct CPU cores to prevent latency.

---

## ADR-004: Process Ancestry Cache

**Date:** 2025-01-XX  
**Status:** Accepted

### Problem
To filter noisy system services, we need to know the *root ancestor* of each process (e.g., `auto-cpufreq -> bash -> bash -> expr`). Walking `/proc` on every event is slow and has race conditions.

### Decision
Implement an **in-memory cache** (`ProcessCache`):
1. Populate from `/proc` at startup
2. Update on each `exec` event
3. Walk ancestry in O(1) memory lookups

### Structure
```python
{pid: {'ppid': int, 'name': str}}
```

### Consequences
- ✅ O(1) ancestry lookups
- ✅ No race conditions with dying processes
- ✅ Captures short-lived processes that `/proc` would miss

---

## ADR-005: TUI Interface - Rich Library

**Date:** 2025-01-XX  
**Status:** Accepted

### Problem
Multiple `print()` statements from concurrent monitors created messy, interleaved output.

### Decision
Migrate to **Producer-Consumer pattern** with `rich` TUI:
- Monitors push events to `multiprocessing.Queue`
- Main process consumes queue and updates `rich.Live` dashboard
- Split-panel layout: Process | Network | (placeholders for File, ML)

### Consequences
- ✅ Clean, organized real-time dashboard
- ✅ Scalable to future monitors (File, ML alerts)
- ✅ Separation of concerns (probes don't handle display)

---

## ADR-006: IPv6 Dual-Stack Support

**Date:** 2025-01-XX  
**Status:** Accepted

### Problem
IPv4-only monitoring creates a **security blind spot**. Modern services listen on both protocols; attackers can use IPv6 to evade detection.

### Decision
Implement dual-stack monitoring:
- Generic 16-byte address array (`unsigned char addr[16]`)
- `version` field (4 or 6)
- Add `kprobe__tcp_v6_connect`
- Update `inet_csk_accept` to detect address family

### Address Storage
| Version | Storage |
|---------|---------|
| IPv4 | `addr[0:4]`, rest zeroed |
| IPv6 | Full `addr[0:16]` |

### Why Not Separate Structs?
Single struct with generic container allows unified data pipeline. Avoids duplicate code and multiple perf buffers.

### Python Handling
```python
if version == 4:
    socket.inet_ntop(AF_INET, addr[:4])
else:
    socket.inet_ntop(AF_INET6, addr)
```

---

## ADR-007: TCP Accept Monitoring (Inbound)

**Date:** 2025-01-XX  
**Status:** Accepted

### Problem
`tcp_v4_connect` only captures *outbound* connections. We're blind to *inbound* connections (e.g., SSH clients connecting to us).

### Decision
Add `kretprobe__inet_csk_accept`:
- **kretprobe** (not kprobe) because the socket is only valid at function return
- Access via `PT_REGS_RC(ctx)` to get returned socket
- Check `skc_family` to determine IPv4 vs IPv6

### Event Structure
Unified struct with `direction` field:
- `0` = Outbound (connect)
- `1` = Inbound (accept)

---

## ADR-008: Noisy Service Filtering

**Date:** 2025-01-XX  
**Status:** Accepted

### Problem
System services like `auto-cpufreq`, `waybar` constantly spawn processes, flooding logs with noise.

### Decision
Maintain configurable list in `src/config.py`:
```python
NOISY_SERVICES = {'auto-cpufreq', 'waybar', ...}
SHELL_NAMES = {'bash', 'sh', 'zsh', ...}
```

Filter by **root ancestor** (first non-shell parent), not by `comm`.

### Consequences
- ✅ Centralized, easy to modify
- ✅ Filters accurately by true parent
- ✅ User can customize per-system
