# src/probes/process.py
"""
Process Monitor Probe
Monitors process executions using eBPF tracepoint on sys_enter_execve.
"""
from bcc import BPF
from src.config import NOISY_SERVICES
import time


class ProcessMonitor:
    """
    eBPF-based process execution monitor.
    
    Sends events to a queue instead of printing directly.
    """
    
    def __init__(self, cache, queue):
        """
        Initialize and compile the eBPF program.
        
        Args:
            cache: ProcessCache instance for ancestry lookups
            queue: multiprocessing.Queue for sending events to TUI
        """
        self.cache = cache
        self.queue = queue
        self.running = False
        
        self.bpf_program_text = """
        #include <linux/sched.h>
        
        struct data_t {
            u32 pid;
            u32 ppid;
            u32 uid;
            char comm[16];
            char fname[256];
        };

        BPF_PERF_OUTPUT(events);

        TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
            struct data_t data = {};

            data.uid = bpf_get_current_uid_gid();
            
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;

            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            bpf_probe_read_kernel(&data.ppid, sizeof(data.ppid), &task->real_parent->tgid);

            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            bpf_probe_read_user_str(&data.fname, sizeof(data.fname), args->filename);

            events.perf_submit(args, &data, sizeof(data));
            return 0;
        }
        """
        
        self.bpf = BPF(text=self.bpf_program_text)
    
    def _handle_event(self, cpu, data, size):
        """Callback for processing perf buffer events."""
        event = self.bpf["events"].event(data)
        
        comm = event.comm.decode('utf-8', 'replace')
        fname = event.fname.decode('utf-8', 'replace')
        
        # Update cache
        self.cache.add(event.pid, event.ppid, comm)
        
        # Get root ancestor
        root_pid, root_name = self.cache.get_root_ancestor(event.ppid)
        
        # Filter noisy services
        if root_name in NOISY_SERVICES:
            return
        
        # Send to queue instead of print
        self.queue.put({
            'type': 'PROCESS',
            'timestamp': time.time(),
            'root': root_name,
            'comm': comm,
            'fname': fname
        })
    
    def start(self):
        """Start the monitoring loop."""
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