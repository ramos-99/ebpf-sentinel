# src/probes/process.py
"""
Process Monitor Probe
Monitors process executions using eBPF kprobe on sys_execve.
"""
from bcc import BPF


class ProcessMonitor:
    """
    eBPF-based process execution monitor.
    
    Attaches a kprobe to sys_execve to intercept all process
    executions and reports them via perf buffer.
    """
    
    def __init__(self):
        """Initialize and compile the eBPF program."""
        self.running = False
        
        # eBPF C program
        self.bpf_program_text = """
        #include <uapi/linux/ptrace.h>
        #include <linux/sched.h>

        struct data_t {
            u32 pid;
            u32 uid;
            char comm[16];
            char fname[256];
        };

        BPF_PERF_OUTPUT(events);

        int kprobe__sys_execve(struct pt_regs *ctx) {
            struct data_t data = {};

            data.uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32; // Shift to get TGID (Thread Group ID)

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            // Note: On very recent kernels, PT_REGS_PARM1 might need adjustments
            // but on standard Arch it usually works out of the box.
            bpf_probe_read_user_str(&data.fname, sizeof(data.fname), (void *)PT_REGS_PARM1(ctx));

            events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """
        
        # Compile the eBPF program
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
        
        print(f"PID: {event.pid:<6} | UID: {event.uid:<6} | "
              f"Process: {event.comm.decode('utf-8', 'replace'):<15} -> "
              f"Executed: {event.fname.decode('utf-8', 'replace')}")
    
    def start(self):
        """Start the monitoring loop."""
        print("⚡ Process Monitor Active... (Ctrl+C to exit)")
        
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
        print("✅ Monitor stopped cleanly.")