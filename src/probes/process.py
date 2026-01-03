# src/probes/process.py
"""
Process Monitor Probe
Monitors process executions using eBPF tracepoint on sys_enter_execve.
Uses tracepoints instead of kprobes for better compatibility with modern kernels.
"""
from bcc import BPF
import os


class ProcessMonitor:
    """
    eBPF-based process execution monitor.
    
    Attaches to the syscalls:sys_enter_execve tracepoint to intercept
    all process executions and reports them via perf buffer.
    
    Why tracepoint instead of kprobe?
    - Stable API: tracepoints are guaranteed to be stable across kernel versions
    - Structured data: access to syscall args via args->field instead of PT_REGS
    - Works reliably on modern kernels (5.x, 6.x)
    """
    
    # =========================================================
    # Noisy services to filter (TRUE parents, not comm)
    # These are system services that constantly spawn processes
    # =========================================================
    NOISY_PARENTS = {
        'auto-cpufreq',
        'cpufreqctl.aut',  # truncated to 16 chars
        'tlp',
        'waybar',
        'hyprsunset',
        'hyprland',
        'cpu-x',
    }
    
    def __init__(self):
        """Initialize and compile the eBPF program."""
        self.running = False
        
        # =========================================================
        # eBPF C program using TRACEPOINT
        # Now captures PPID (Parent PID) for true parent tracking
        # =========================================================
        self.bpf_program_text = """
        #include <linux/sched.h>
        
        // Data structure to send events to userspace
        struct data_t {
            u32 pid;         // Process ID
            u32 ppid;        // Parent Process ID (NEW!)
            u32 uid;         // User ID
            char comm[16];   // Process name (before exec)
            char fname[256]; // Filename being executed
        };

        // Perf buffer for sending events to Python
        BPF_PERF_OUTPUT(events);

        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
            struct data_t data = {};

            // Get current user ID
            data.uid = bpf_get_current_uid_gid();
            
            // Get PID (TGID)
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;

            // =========================================================
            // NEW: Get PPID (Parent Process ID)
            // 
            // bpf_get_current_task() returns the current task_struct
            // task->real_parent points to the true parent process
            // real_parent->tgid is the parent's PID
            // =========================================================
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);

            // Get process name (before exec)
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Read the filename from tracepoint args
            bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

            // Send event to userspace via perf buffer
            events.perf_submit(args, &data, sizeof(data));
            return 0;
        }
        """
        
        # Compile the eBPF program
        self.bpf = BPF(text=self.bpf_program_text)
    
    def _get_parent_name(self, ppid):
        """
        Resolve parent process name from /proc/{ppid}/comm.
        
        Args:
            ppid: Parent process ID
            
        Returns:
            Parent process name or "<unknown>" if not found
        """
        try:
            with open(f"/proc/{ppid}/comm", "r") as f:
                return f.read().strip()
        except (FileNotFoundError, PermissionError):
            return "<unknown>"
    
    def _handle_event(self, cpu, data, size):
        """
        Callback for processing perf buffer events.
        
        Args:
            cpu: CPU that generated the event
            data: Raw event data
            size: Size of the event data
        """
        event = self.bpf["events"].event(data)
        
        # Get the TRUE parent name via /proc
        parent_name = self._get_parent_name(event.ppid)
        
        # Filter by TRUE parent (not by comm!)
        if parent_name in self.NOISY_PARENTS:
            return
        
        comm = event.comm.decode('utf-8', 'replace')
        fname = event.fname.decode('utf-8', 'replace')
        
        # New format: shows parent -> current -> what's executed
        print(f"[PROCESS] PID: {event.pid:<6} | PPID: {event.ppid:<6} | "
              f"{parent_name:<15} -> {comm:<15} -> {fname}")
    
    def start(self):
        """Start the monitoring loop."""
        print("[PROCESS] ⚡ Monitor Active (tracepoint: sys_enter_execve)")
        
        # Attach the callback to the perf buffer
        self.bpf["events"].open_perf_buffer(self._handle_event)
        
        self.running = True
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break
    
    def stop(self):
        """Stop the monitoring loop gracefully."""
        self.running = False
        print("[PROCESS] ✅ Stopped cleanly.")