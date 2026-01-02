# src/main.py
"""
ebpf-sentinel - Entry Point
Kernel-level security monitor with self-supervised ML anomaly detection.
"""
import sys
import signal
import multiprocessing
from src.probes.process import ProcessMonitor

# wrapper function for processing monitor
def run_process_monitor():
    try:
        monitor = ProcessMonitor()
    except Exception as e:
        print(f"❌ Critical error loading eBPF: {e}")
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
    
    # Define monitors to run (scalable for future additions)
    monitors = [
        ("ProcessMonitor", run_process_monitor),
        # ("NetworkMonitor", run_network_monitor),  # Phase 2
        # ("FileMonitor", run_file_monitor),        # Phase 3
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