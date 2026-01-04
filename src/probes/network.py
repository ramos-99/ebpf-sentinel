# src/probes/network.py
"""
Network Monitor Probe
Monitors TCP connections (IPv4 and IPv6, inbound and outbound) using eBPF.

Probes:
- kprobe__tcp_v4_connect: IPv4 outbound
- kprobe__tcp_v6_connect: IPv6 outbound
- kretprobe__inet_csk_accept: Both v4/v6 inbound
"""
from bcc import BPF
import socket
import time


class NetworkMonitor:
    """
    eBPF-based network connection monitor with dual-stack (IPv4/IPv6) support.
    
    Uses a generic 16-byte address array to handle both address families
    seamlessly in the same data pipeline.
    """
    
    # Direction constants
    DIR_OUTBOUND = 0
    DIR_INBOUND = 1
    
    # IP version constants
    IP_V4 = 4
    IP_V6 = 6
    
    def __init__(self, queue):
        """
        Initialize and compile the eBPF program.
        
        Args:
            queue: multiprocessing.Queue for sending events to TUI
        """
        self.queue = queue
        self.running = False
        
        # =========================================================
        # eBPF C program with IPv4 and IPv6 support
        #
        # Key design decision:
        # - Use unsigned char addr[16] for ALL addresses
        # - IPv4: stored in first 4 bytes, rest zeroed
        # - IPv6: full 16 bytes used
        # - version field indicates which to interpret
        # =========================================================
        self.bpf_program_text = """
        #include <net/sock.h>
        #include <linux/in6.h>
        
        // =========================================================
        // GENERIC struct for both IPv4 and IPv6
        //
        // Why 16 bytes?
        // - IPv4 = 32 bits = 4 bytes
        // - IPv6 = 128 bits = 16 bytes
        // Using 16 bytes accommodates both, avoiding separate structs.
        // =========================================================
        struct net_data_t {
            u32 pid;
            u32 uid;
            char comm[16];
            unsigned char addr[16];  // Generic: v4 in [0:4], v6 in [0:16]
            u16 dport;               // Remote port
            u16 lport;               // Local port (for accept)
            u8 direction;            // 0 = OUT, 1 = IN
            u8 version;              // 4 = IPv4, 6 = IPv6
        };

        BPF_PERF_OUTPUT(net_events);

        // =========================================================
        // Helper: Fill common fields (pid, uid, comm)
        // =========================================================
        static inline void fill_common(struct net_data_t *data) {
            data->uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data->pid = id >> 32;
            bpf_get_current_comm(&data->comm, sizeof(data->comm));
        }

        // =========================================================
        // IPv4 OUTBOUND: kprobe on tcp_v4_connect
        // =========================================================
        int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
            struct net_data_t data = {};
            fill_common(&data);

            // Read IPv4 address (4 bytes) into start of addr array
            u32 daddr;
            bpf_probe_read_kernel(&daddr, sizeof(daddr), 
                                  &sk->__sk_common.skc_daddr);
            // Copy to generic array (first 4 bytes)
            __builtin_memcpy(data.addr, &daddr, 4);
            
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);
            
            data.lport = 0;
            data.direction = 0;  // Outbound
            data.version = 4;    // IPv4

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // =========================================================
        // IPv6 OUTBOUND: kprobe on tcp_v6_connect
        //
        // IPv6 address is stored in:
        // sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8[16]
        // =========================================================
        int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
            struct net_data_t data = {};
            fill_common(&data);

            // Read full 16-byte IPv6 address
            bpf_probe_read_kernel(&data.addr, 16, 
                                  &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
            
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);
            
            data.lport = 0;
            data.direction = 0;  // Outbound
            data.version = 6;    // IPv6

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }

        // =========================================================
        // INBOUND (both v4 and v6): kretprobe on inet_csk_accept
        //
        // At return time, we check socket family to determine version.
        // =========================================================
        int kretprobe__inet_csk_accept(struct pt_regs *ctx) {
            struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
            if (sk == NULL) return 0;

            struct net_data_t data = {};
            fill_common(&data);

            // Determine IP version from socket family
            u16 family;
            bpf_probe_read_kernel(&family, sizeof(family), 
                                  &sk->__sk_common.skc_family);

            if (family == AF_INET) {
                // IPv4
                u32 daddr;
                bpf_probe_read_kernel(&daddr, sizeof(daddr), 
                                      &sk->__sk_common.skc_daddr);
                __builtin_memcpy(data.addr, &daddr, 4);
                data.version = 4;
            } else if (family == AF_INET6) {
                // IPv6
                bpf_probe_read_kernel(&data.addr, 16, 
                                      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8);
                data.version = 6;
            } else {
                return 0;  // Unknown family, skip
            }

            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);
            
            u16 lport;
            bpf_probe_read_kernel(&lport, sizeof(lport), 
                                  &sk->__sk_common.skc_num);
            data.lport = lport;
            
            data.direction = 1;  // Inbound

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """
        
        self.bpf = BPF(text=self.bpf_program_text)
    
    def _handle_event(self, cpu, data, size):
        """Callback for processing perf buffer events."""
        event = self.bpf["net_events"].event(data)
        
        # Convert address based on IP version
        if event.version == self.IP_V4:
            # IPv4: first 4 bytes of addr array
            ip_bytes = bytes(event.addr[:4])
            ip_str = socket.inet_ntop(socket.AF_INET, ip_bytes)
        else:
            # IPv6: full 16 bytes
            ip_bytes = bytes(event.addr)
            ip_str = socket.inet_ntop(socket.AF_INET6, ip_bytes)
        
        remote_port = socket.ntohs(event.dport)
        local_port = event.lport
        comm = event.comm.decode('utf-8', 'replace')
        
        # Format display string
        if event.direction == self.DIR_OUTBOUND:
            direction = "OUT"
            if event.version == self.IP_V6:
                dest_str = f"→ [{ip_str}]:{remote_port}"
            else:
                dest_str = f"→ {ip_str}:{remote_port}"
        else:
            direction = "IN"
            if event.version == self.IP_V6:
                dest_str = f"← [{ip_str}]:{remote_port} on :{local_port}"
            else:
                dest_str = f"← {ip_str}:{remote_port} on :{local_port}"
        
        # Send to queue
        self.queue.put({
            'type': 'NETWORK',
            'timestamp': time.time(),
            'direction': direction,
            'version': event.version,
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