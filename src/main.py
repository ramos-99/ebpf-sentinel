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

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

from src.probes.cache import ProcessCache
from src.probes.process import ProcessMonitor
from src.probes.network import NetworkMonitor


# Global queue and cache
_queue = None
_cache = None

# Event buffers (max 20 items per panel)
MAX_EVENTS = 20


def run_process_monitor():
    """Wrapper to run ProcessMonitor in a child process."""
    try:
        monitor = ProcessMonitor(_cache, _queue)
    except Exception as e:
        _queue.put({'type': 'ERROR', 'msg': f'[PROCESS] {e}'})
        sys.exit(1)
    monitor.start()


def run_network_monitor():
    """Wrapper to run NetworkMonitor in a child process."""
    try:
        monitor = NetworkMonitor(_queue)
    except Exception as e:
        _queue.put({'type': 'ERROR', 'msg': f'[NETWORK] {e}'})
        sys.exit(1)
    monitor.start()


def make_layout() -> Layout:
    """Create the dashboard layout."""
    layout = Layout()
    
    # Main split: top (monitors) and bottom (future: ML/Alerts)
    layout.split_column(
        Layout(name="monitors", ratio=3),
        Layout(name="future", ratio=1),
    )
    
    # Top: Process and Network side by side
    layout["monitors"].split_row(
        Layout(name="process"),
        Layout(name="network"),
    )
    
    # Bottom: File Monitor and ML placeholders
    layout["future"].split_row(
        Layout(name="files"),
        Layout(name="ml"),
    )
    
    return layout


def make_process_panel(events: deque) -> Panel:
    """Create the process events panel."""
    table = Table(show_header=True, header_style="bold cyan", expand=True)
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
    
    return Panel(table, title="[bold green]⚡ Process Monitor[/]", border_style="green")


def make_network_panel(events: deque) -> Panel:
    """Create the network events panel."""
    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("Time", width=8)
    table.add_column("Dir", width=3)
    table.add_column("Process", width=12)
    table.add_column("Connection", no_wrap=False)
    
    for event in events:
        ts = datetime.fromtimestamp(event['timestamp']).strftime('%H:%M:%S')
        # Color based on direction
        dir_style = "green" if event.get('direction') == "OUT" else "cyan"
        table.add_row(
            ts,
            f"[{dir_style}]{event.get('direction', '?')}[/]",
            event['comm'],
            event.get('display', f"{event['ip']}:{event['port']}")
        )
    
    return Panel(table, title="[bold blue]🌐 Network Monitor[/]", border_style="blue")


def make_placeholder_panel(title: str, message: str, style: str) -> Panel:
    """Create a placeholder panel for future features."""
    text = Text(message, justify="center", style="dim")
    return Panel(text, title=title, border_style=style)


def main():
    """Main entry point for ebpf-sentinel."""
    global _queue, _cache
    
    console = Console()
    
    # Create shared queue
    _queue = multiprocessing.Queue()
    
    # Create and populate cache
    console.print("[yellow]📦 Populating process cache...[/]")
    _cache = ProcessCache()
    _cache.populate_from_proc()
    console.print(f"[green]📦 Cache ready: {len(_cache.processes)} processes[/]")
    
    # Ignore SIGINT before forking
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    
    processes = []
    monitors = [
        ("ProcessMonitor", run_process_monitor),
        ("NetworkMonitor", run_network_monitor),
    ]
    
    # Start monitors
    for name, func in monitors:
        p = multiprocessing.Process(target=func, name=name)
        p.start()
        processes.append(p)
    
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
            while not _queue.empty():
                try:
                    event = _queue.get_nowait()
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
                "[bold yellow]📁 File Monitor[/]",
                "Phase 3: Coming Soon",
                "yellow"
            ))
            layout["ml"].update(make_placeholder_panel(
                "[bold magenta]🧠 ML Anomaly Detection[/]",
                "Phase 4: Coming Soon",
                "magenta"
            ))
            
            time.sleep(0.1)
    
    # Cleanup
    console.print("\n[red]🛑 Shutting down...[/]")
    for p in processes:
        p.terminate()
    for p in processes:
        p.join(timeout=2)
        if p.is_alive():
            p.kill()
    console.print("[green]✅ All monitors stopped.[/]")


if __name__ == "__main__":
    main()