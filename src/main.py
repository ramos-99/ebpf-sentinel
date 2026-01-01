# src/main.py
"""
ebpf-sentinel - Entry Point
Kernel-level security monitor with self-supervised ML anomaly detection.
"""
import sys
import signal
from src.probes.process import ProcessMonitor


def main():
    """Main entry point for the Neuro-Link monitor."""
    monitor = None
    
    def graceful_shutdown(signum, frame):
        """Handle shutdown signals gracefully."""
        signal_name = signal.Signals(signum).name
        print(f"\n🛑 Received {signal_name}, shutting down gracefully...")
        if monitor:
            monitor.stop()
        sys.exit(0)
    
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, graceful_shutdown)   # Ctrl+C
    signal.signal(signal.SIGTERM, graceful_shutdown)  # kill command
    
    # Instantiate the monitor
    # Note: __init__ compiles the C code. If it fails, it crashes here.
    try:
        monitor = ProcessMonitor()
    except Exception as e:
        print(f"❌ Critical error loading eBPF: {e}")
        sys.exit(1)
    
    # Start the event loop
    monitor.start()


if __name__ == "__main__":
    main()