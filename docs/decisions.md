# Architecture Decision Records (ADR)

## 001. Process Monitoring: Tracepoints vs. Kprobes
* **Date:** 2025-XX-XX
* **Context:** Initially, `kprobe` was used on `sys_execve` to detect new process executions.
* **Problem:** On recent Kernels (Arch Linux 6.12+), the introduction of *Syscall Wrappers* altered the CPU register order. The code was reading garbage memory instead of the filename, resulting in empty or corrupted logs.
* **Decision:** Migrate to **Tracepoints** (`tracepoint:syscalls:sys_enter_execve`).
* **Consequence:** We gained direct access to the `args->filename` structure guaranteed by the Kernel API, resolving the argument reading issue regardless of the underlying architecture.

## 002. Network Monitoring: Use of Kprobes
* **Date:** 2025-XX-XX
* **Context:** Requirement to capture outbound TCP traffic (IPv4).
* **Decision:** Use **Kprobe** on the `tcp_v4_connect` function.
* **Justification:** Although Tracepoints are generally more stable, `tcp_v4_connect` provides direct access to the Kernel's `struct sock`. This drastically simplifies the extraction of Destination IP and Port, avoiding the complex parsing of User Space memory structures (`sockaddr`) that would be required by a syscall Tracepoint (`sys_enter_connect`).

## 003. Concurrency Architecture
* **Date:** 2025-XX-XX
* **Decision:** Use `multiprocessing.Process` (Fork) instead of `threading`.
* **Justification:** Python has a Global Interpreter Lock (GIL) that limits true parallel CPU execution. Since eBPF generates a high volume of events, we require the Process Monitor and Network Monitor to run on distinct CPU cores to prevent latency or event loss.
