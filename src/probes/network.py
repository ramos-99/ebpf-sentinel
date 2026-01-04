# src/probes/network.py
"""
Network Monitor Probe
Monitors TCP connections (outbound and inbound) using eBPF.
- Outbound: kprobe on tcp_v4_connect
- Inbound: kretprobe on inet_csk_accept
"""
from bcc import BPF
import socket
import struct
import time


class NetworkMonitor:
    """
    eBPF-based network connection monitor.
    
    Monitors both outbound (connect) and inbound (accept) TCP connections.
    """
    
    # Direction constants (match C code)
    DIR_OUTBOUND = 0
    DIR_INBOUND = 1
    
    def __init__(self, queue):
        """
        Initialize and compile the eBPF program.
        
        Args:
            queue: multiprocessing.Queue for sending events to TUI
        """
        self.queue = queue
        self.running = False
        
        # =========================================================
        # eBPF C program with TWO probes:
        # 1. kprobe__tcp_v4_connect - outbound connections
        # 2. kretprobe__inet_csk_accept - inbound connections
        # =========================================================
        self.bpf_program_text = """
        #include <net/sock.h>
        
        // =========================================================
        // UNIFIED struct for both connect and accept events
        // =========================================================
        struct net_data_t {
            u32 pid;
            u32 uid;
            char comm[16];
            u32 daddr;      // Remote IP (destination for connect, source for accept)
            u16 dport;      // Remote port
            u16 lport;      // Local port (mainly useful for accept)
            u8 direction;   // 0 = OUTBOUND (connect), 1 = INBOUND (accept)
        };

        // Single perf buffer for both event types
        BPF_PERF_OUTPUT(net_events);

        // =========================================================
        // OUTBOUND: kprobe on tcp_v4_connect
        // 
        // Fires when the local machine initiates a TCP connection.
        // Example: browser connecting to google.com
        // =========================================================
        int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
            struct net_data_t data = {};

            data.uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            // Read destination IP and port from socket
            bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                                  &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);
            
            // Local port not relevant for outbound (ephemeral port)
            data.lport = 0;
            
            // Mark as outbound
            data.direction = 0;

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // =========================================================
        // INBOUND: kretprobe on inet_csk_accept
        // 
        // Fires when a connection is ACCEPTED (return of accept syscall).
        // Example: SSH server accepting a client connection.
        //
        // Why kRETprobe?
        // - At entry, the socket isn't ready yet
        // - At return, we have the fully connected socket
        // 
        // PT_REGS_RC(ctx) = Return value = the accepted socket
        // =========================================================
        int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
            // Get the returned socket (the accepted connection)
            struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
            
            // Check if socket is valid
            if (sk == NULL) {
                return 0;
            }

            struct net_data_t data = {};

            data.uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            // For accept, daddr is the REMOTE client's IP
            // skc_daddr = destination address (from kernel's perspective)
            bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                                  &sk->__sk_common.skc_daddr);
            
            // Remote client's port
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);
            
            // LOCAL port where we accepted the connection (e.g., 22 for SSH)
            // skc_num = local port number (already in host byte order)
            u16 lport;
            bpf_probe_read_kernel(&lport, sizeof(lport), 
                                  &sk->__sk_common.skc_num);
            data.lport = lport;
            
            // Mark as inbound
            data.direction = 1;

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """
        
        self.bpf = BPF(text=self.bpf_program_text)
    
    def _handle_event(self, cpu, data, size):
        """Callback for processing perf buffer events."""
        event = self.bpf["net_events"].event(data)
        
        # Convert IP from network byte order to string
        ip_str = socket.inet_ntoa(struct.pack("I", event.daddr))
        
        # Convert port from network byte order to host order
        remote_port = socket.ntohs(event.dport)
        
        # Local port is already in host byte order (from skc_num)
        local_port = event.lport
        
        comm = event.comm.decode('utf-8', 'replace')
        
        # Determine direction string
        if event.direction == self.DIR_OUTBOUND:
            direction = "OUT"
            dest_str = f"→ {ip_str}:{remote_port}"
        else:
            direction = "IN"
            dest_str = f"← {ip_str}:{remote_port} on :{local_port}"
        
        # Send to queue
        self.queue.put({
            'type': 'NETWORK',
            'timestamp': time.time(),
            'direction': direction,
            'comm': comm,
            'ip': ip_str,
            'port': remote_port,
            'local_port': local_port,
            'display': dest_str
        })
    
    def start(self):
        """Start the monitoring loop."""
        self.bpf["net_events"].open_perf_buffer(self._handle_event)
        
        self.running = True
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                break
    
    def stop(self):
        """Stop the monitoring loop gracefully."""
        self.running = False