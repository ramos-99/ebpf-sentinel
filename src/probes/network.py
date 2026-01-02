# src/probes/network.py
from bcc import BPF
import multiprocessing
import socket
import struct
import os

class NetworkMonitor(multiprocessing.Process):
    def __init__(self):
        super().__init__()
        self.daemon = True
        
        self.bpf_program_text = """
        #include <uapi/linux/ptrace.h>
        #include <net/sock.h>
        #include <bcc/proto.h>

        // 1. A Estrutura de Dados
        struct net_data_t {
            u32 pid;
            u32 uid;
            char comm[16];
            
            // PREENCHI ISTO PARA TI COM BASE NA TUA RESPOSTA:
            u32 daddr;  // IP (32 bits)
            u16 dport;  // Porta (16 bits)
        };

        BPF_PERF_OUTPUT(net_events);

        int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
            struct net_data_t data = {};

            data.uid = bpf_get_current_uid_gid();
            u64 id = bpf_get_current_pid_tgid();
            data.pid = id >> 32;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));

            // --- O DESAFIO ESTÁ AQUI ---
            // O Kernel moderno guarda o endereço dentro de __sk_common.
            // A estrutura é: sk -> __sk_common -> skc_daddr
            
            // Como se escreve isto em C?
            data.daddr = sk->__sk_common.skc_daddr; 
            
            // E a porta? (sk -> __sk_common -> skc_dport)
            data.dport = sk->__sk_common.skc_dport;

            net_events.perf_submit(ctx, &data, sizeof(data));
            return 0;
        }
        """

    # ... (O resto do código Python vem a seguir)