# src/main.py
"""
ebpf-sentinel - Entry Point
Kernel-level security monitor with self-supervised ML anomaly detection.
"""
import sys
import signal
import multiprocessing
from src.probes.process import ProcessMonitor
from src.probes.network import NetworkMonitor


# =========================================================
# Wrapper functions for each monitor
#
# Why wrappers? Two reasons:
# 1. Isolate exceptions - if eBPF fails to load, it crashes
#    inside the child process, not the parent
# 2. Clean interface - each wrapper is a simple callable
#    that multiprocessing.Process can target
# =========================================================

def run_process_monitor():
    """Wrapper to run ProcessMonitor in a child process."""
    try:
        monitor = ProcessMonitor()
    except Exception as e:
        print(f"[PROCESS] ❌ Critical error loading eBPF: {e}")
        sys.exit(1)
    monitor.start()


def run_network_monitor():
    """Wrapper to run NetworkMonitor in a child process."""
    try:
        monitor = NetworkMonitor()
    except Exception as e:
        print(f"[NETWORK] ❌ Critical error loading eBPF: {e}")
        sys.exit(1)
    monitor.start()


def main():
    """Main entry point for ebpf-sentinel."""
    
    # List of all monitor processes for scalability
    processes = []
    
    def graceful_shutdown(signum, frame):
        """Handle shutdown signals - terminate all child processes."""
        sig_name = signal.Signals(signum).name
        print(f"\n🛑 Received {sig_name}, shutting down all monitors...")
        
        for p in processes:
            if p.is_alive():
                p.terminate()
        
        # Wait for all to finish (with timeout)
        for p in processes:
            p.join(timeout=2)
            if p.is_alive():
                print(f"⚠️  Force killing {p.name}...")
                p.kill()
        
        print("✅ All monitors stopped.")
        sys.exit(0)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, graceful_shutdown)   # Ctrl+C
    signal.signal(signal.SIGTERM, graceful_shutdown)  # kill command
    
    # =========================================================
    # Monitor Registry
    #
    # To add a new monitor:
    # 1. Create the class in src/probes/
    # 2. Create a wrapper function above
    # 3. Add tuple here: ("Name", wrapper_function)
    # =========================================================
    monitors = [
        ("ProcessMonitor", run_process_monitor),
        ("NetworkMonitor", run_network_monitor),
        # ("FileMonitor", run_file_monitor),  # Phase 3
    ]
    
    # Start all monitors
    for name, func in monitors:
        p = multiprocessing.Process(target=func, name=name)
        p.start()
        processes.append(p)
        print(f"🚀 Started {name} (PID: {p.pid})")
    
    # Wait for all processes to complete
    for p in processes:
        p.join()


if __name__ == "__main__":
    main()