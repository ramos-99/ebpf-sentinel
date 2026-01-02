# src/probes/process.py
"""
Process Monitor Probe
Monitors process executions using eBPF tracepoint on sys_enter_execve.
Uses tracepoints instead of kprobes for better compatibility with modern kernels.
"""
from bcc import BPF


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
    
    def __init__(self):
        """Initialize and compile the eBPF program."""
        self.running = False
        
        # =========================================================
        # eBPF C program using TRACEPOINT instead of kprobe
        # =========================================================
        self.bpf_program_text = """
        #include <linux/sched.h>
        
        // Data structure to send events to userspace
        struct data_t {
            u32 pid;        // Process ID
            u32 uid;        // User ID
            char comm[16];  // Process name (before exec)
            char fname[256]; // Filename being executed
        };

        // Perf buffer for sending events to Python
        BPF_PERF_OUTPUT(events);

        // =========================================================
        // TRACEPOINT_PROBE: Attaches to syscalls:sys_enter_execve
        // 
        // This fires BEFORE execve executes, so:
        //   - comm = parent process name (e.g., "bash")
        //   - fname = what's being executed (e.g., "/usr/bin/ls")
        //
        // The args pointer gives us structured access to syscall args:
        //   - args->filename: path of the executable
        // =========================================================
        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
            struct data_t data = {};

            // Get current user ID (lower 32 bits of uid_gid)
            data.uid = bpf_get_current_uid_gid();
            
            // Get PID (actually TGID - Thread Group ID, which is the "real" PID)
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;

            // Get process name (this is still the parent's name, before exec)
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Read the filename from the tracepoint args
            // args->filename is a pointer to the executable path in userspace
            // This is the key improvement over kprobe - stable structured access!
            bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

            // Send event to userspace via perf buffer
            events.perf_submit(args, &data, sizeof(data));
            return 0;
        }
        """
        
        # Compile the eBPF program
        # BCC automatically attaches TRACEPOINT_PROBE to the correct tracepoint
        self.bpf = BPF(text=self.bpf_program_text)
    
    def _handle_event(self, cpu, data, size):
        """
        Callback for processing perf buffer events.
        
        Args:
            cpu: CPU that generated the event
            data: Raw event data
            size: Size of the event data
        """
        event = self.bpf["events"].event(data)
        
        print(f"[PROCESS] PID: {event.pid:<6} | UID: {event.uid:<6} | "
              f"{event.comm.decode('utf-8', 'replace'):<15} -> "
              f"{event.fname.decode('utf-8', 'replace')}")
    
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