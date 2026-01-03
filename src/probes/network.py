# src/probes/network.py
"""
Network Monitor Probe
Monitors outbound TCP connections using eBPF kprobe on tcp_v4_connect.

Why kprobe instead of tracepoint here?
- tcp_v4_connect gives direct access to struct sock
- Avoids complex parsing of sockaddr from userspace
- See /docs/decisions.md ADR-002 for full justification
"""
from bcc import BPF
import socket
import struct


class NetworkMonitor:
    """
    eBPF-based network connection monitor.
    
    Attaches a kprobe to tcp_v4_connect to intercept all outbound
    IPv4 TCP connections and reports them via perf buffer.
    """
    
    def __init__(self):
        """Initialize and compile the eBPF program."""
        self.running = False
        
        # =========================================================
        # eBPF C program - Kprobe on tcp_v4_connect
        # =========================================================
        self.bpf_program_text = """
        #include <net/sock.h>
        
        // =========================================================
        // STEP 1: Define the data structure
        // 
        // This struct will be sent from kernel to Python.
        // Keep it simple - only what we need to display.
        // =========================================================
        struct net_data_t {
            u32 pid;        // Process ID
            u32 uid;        // User ID  
            char comm[16];  // Process name
            u32 daddr;      // Destination IP (32 bits, network byte order)
            u16 dport;      // Destination Port (16 bits, network byte order)
        };

        // Perf buffer - the "channel" to send events to Python
        BPF_PERF_OUTPUT(net_events);

        // =========================================================
        // STEP 2: The kprobe function
        //
        // Function signature matches tcp_v4_connect:
        //   int tcp_v4_connect(struct sock *sk, ...)
        //
        // BCC magic: kprobe__<function_name> auto-attaches!
        // The first arg after ctx is the first arg of the kernel function.
        // =========================================================
        int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
            struct net_data_t data = {};

            // Get basic process info (same as process.py)
            data.uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            // =========================================================
            // STEP 3: Extract IP and Port from struct sock
            //
            // The kernel's struct sock has a common header: __sk_common
            // Inside __sk_common:
            //   - skc_daddr: destination IPv4 address
            //   - skc_dport: destination port
            //
            // We use bpf_probe_read_kernel() for safe kernel memory access.
            // Direct access (sk->__sk_common.skc_daddr) might fail
            // the eBPF verifier on some kernels.
            // =========================================================
            bpf_probe_read_kernel(&data.daddr, sizeof(data.daddr), 
                                  &sk->__sk_common.skc_daddr);
            bpf_probe_read_kernel(&data.dport, sizeof(data.dport),
                                  &sk->__sk_common.skc_dport);

            // Send to Python via perf buffer
            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """
        
        # Compile the eBPF program
        # BCC auto-attaches kprobe__tcp_v4_connect to the kernel function
        self.bpf = BPF(text=self.bpf_program_text)
    
    # =========================================================
    # STEP 4: Python callback to handle incoming events
    #
    # This is called every time the kernel sends us an event.
    # We need to:
    #   1. Parse the raw data into our struct
    #   2. Convert IP from u32 to "x.x.x.x" string
    #   3. Convert port from network byte order to host order
    # =========================================================
    def _handle_event(self, cpu, data, size):
        """
        Callback for processing perf buffer events.
        
        Args:
            cpu: CPU that generated the event
            data: Raw event data from kernel
            size: Size of the event data
        """
        # Parse raw bytes into our struct
        event = self.bpf["net_events"].event(data)
        
        # =========================================================
        # IP Conversion: u32 -> "192.168.1.1"
        #
        # socket.inet_ntoa() converts 4 bytes to IP string
        # struct.pack("I", ...) converts u32 to 4 bytes
        # "I" = unsigned int (4 bytes), little-endian on x86
        # =========================================================
        ip_str = socket.inet_ntoa(struct.pack("I", event.daddr))
        
        # =========================================================
        # Port Conversion: Network byte order -> Host byte order
        #
        # Network = Big-endian (most significant byte first)
        # Host (x86) = Little-endian (least significant byte first)
        # socket.ntohs() does this conversion
        #
        # Example: Port 443
        #   Network order: 0x01BB (bytes: 01 BB)
        #   After ntohs:   443 (0x01BB interpreted correctly)
        # =========================================================
        port = socket.ntohs(event.dport)
        
        # Print with [NETWORK] prefix for log clarity
        print(f"[NETWORK] PID: {event.pid:<6} | UID: {event.uid:<6} | "
              f"{event.comm.decode('utf-8', 'replace'):<15} -> "
              f"{ip_str}:{port}")
    
    def start(self):
        """Start the monitoring loop."""
        print("[NETWORK] ⚡ Monitor Active (kprobe: tcp_v4_connect)")
        
        # Attach our callback to the perf buffer named "net_events"
        self.bpf["net_events"].open_perf_buffer(self._handle_event)
        
        # Polling loop - check for new events every 100ms
        self.running = True
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except Exception:
                # Exit loop on any error (including keyboard interrupt)
                break
    
    def stop(self):
        """Stop the monitoring loop gracefully."""
        self.running = False
        print("[NETWORK] ✅ Stopped cleanly.")