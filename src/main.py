# src/main.py
"""
ebpf-sentinel - Entry Point
Kernel-level security monitor with self-supervised ML anomaly detection.
"""
import sys
import signal
import multiprocessing
import os
import time
from collections import deque
from datetime import datetime
from functools import partial

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

from src.probes.cache import ProcessCache
from src.probes.process import ProcessMonitor
from src.probes.network import NetworkMonitor


MAX_EVENTS = 20


def run_process_monitor(cache, queue):
    """Wrapper to run ProcessMonitor in a child process."""
    try:
        monitor = ProcessMonitor(cache, queue)
    except Exception as e:
        queue.put({'type': 'ERROR', 'msg': f'[PROCESS] {e}'})
        sys.exit(1)
    monitor.start()


def run_network_monitor(queue):
    """Wrapper to run NetworkMonitor in a child process."""
    try:
        monitor = NetworkMonitor(queue)
    except Exception as e:
        queue.put({'type': 'ERROR', 'msg': f'[NETWORK] {e}'})
        sys.exit(1)
    monitor.start()


def make_layout() -> Layout:
    """Create the dashboard layout."""
    layout = Layout()
    
    layout.split_column(
        Layout(name="monitors", ratio=3),
        Layout(name="future", ratio=1),
    )
    
    layout["monitors"].split_row(
        Layout(name="process"),
        Layout(name="network"),
    )
    
    layout["future"].split_row(
        Layout(name="files"),
        Layout(name="ml"),
    )
    
    return layout


def make_process_panel(events: deque) -> Panel:
    """Create the process events panel."""
    table = Table(show_header=True, header_style="bold white", expand=True)
    table.add_column("Time", width=8)
    table.add_column("Root", width=15)
    table.add_column("Process", width=12)
    table.add_column("Executed", no_wrap=False)
    
    for event in events:
        ts = datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')
        table.add_row(
            ts,
            event['root'],
            event['comm'],
            event['fname']
        )
    
    return Panel(table, title="[bold white]Process Monitor[/]", border_style="dim")


def make_network_panel(events: deque) -> Panel:
    """Create the network events panel."""
    table = Table(show_header=True, header_style="bold white", expand=True)
    table.add_column("Time", width=8)
    table.add_column("Dir", width=3)
    table.add_column("Process", width=12)
    table.add_column("Connection", no_wrap=False)
    
    for event in events:
        ts = datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')
        table.add_row(
            ts,
            event.get('direction', '?'),
            event['comm'],
            event.get('display', f"{event['ip']}:{event['port']}")
        )
    
    return Panel(table, title="[bold white]Network Monitor[/]", border_style="dim")


def make_placeholder_panel(title: str, message: str) -> Panel:
    """Create a placeholder panel for future features."""
    text = Text(message, justify="center", style="dim")
    return Panel(text, title=title, border_style="dim")


def main():
    """Main entry point for ebpf-sentinel."""
    console = Console()
    
    # Create shared queue
    queue = multiprocessing.Queue()
    
    # Create and populate cache
    console.print("[dim]Populating process cache...[/]")
    cache = ProcessCache()
    cache.populate_from_proc()
    console.print(f"[dim]Cache ready: {len(cache.processes)} processes[/]")
    
    # Ignore SIGINT before forking
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    processes = []
    
    # Start process monitor with explicit args
    p1 = multiprocessing.Process(
        target=run_process_monitor,
        args=(cache, queue),
        name="ProcessMonitor"
    )
    p1.start()
    processes.append(p1)
    
    # Start network monitor
    p2 = multiprocessing.Process(
        target=run_network_monitor,
        args=(queue,),
        name="NetworkMonitor"
    )
    p2.start()
    processes.append(p2)
    
    # Event buffers
    process_events = deque(maxlen=MAX_EVENTS)
    network_events = deque(maxlen=MAX_EVENTS)
    
    # Create layout
    layout = make_layout()
    
    # Shutdown flag
    shutdown = False
    
    def graceful_shutdown(signum, frame):
        nonlocal shutdown
        shutdown = True
    
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)
    
    # TUI main loop
    with Live(layout, console=console, refresh_per_second=4, screen=True) as live:
        while not shutdown:
            # Drain queue (non-blocking)
            while not queue.empty():
                try:
                    event = queue.get_nowait()
                    if event['type'] == 'PROCESS':
                        process_events.append(event)
                    elif event['type'] == 'NETWORK':
                        network_events.append(event)
                except:
                    break
            
            # Update panels
            layout["process"].update(make_process_panel(process_events))
            layout["network"].update(make_network_panel(network_events))
            layout["files"].update(make_placeholder_panel(
                "[bold white]File Monitor[/]",
                "Phase 3: Coming Soon"
            ))
            layout["ml"].update(make_placeholder_panel(
                "[bold white]ML Anomaly Detection[/]",
                "Phase 4: Coming Soon"
            ))
            
            time.sleep(0.1)
    
    # Cleanup
    console.print("\n[dim]Shutting down...[/]")
    for p in processes:
        p.terminate()
    for p in processes:
        p.join(timeout=2)
        if p.is_alive():
            p.kill()
    console.print("[dim]All monitors stopped.[/]")


if __name__ == "__main__":
    main()