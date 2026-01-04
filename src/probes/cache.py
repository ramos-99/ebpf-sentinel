# src/probes/cache.py
"""
Process Cache
Maintains an in-memory cache of the process tree for fast ancestry lookups.
"""
import os


class ProcessCache:
    """
    In-memory cache of process tree.
    
    Why cache instead of /proc?
    1. Performance: O(1) lookup vs disk I/O
    2. Consistency: No race conditions with dying processes
    3. Reliability: Captures short-lived processes that /proc would miss
    """
    
    def __init__(self):
        self.processes = {}  # PID -> {'ppid': int, 'name': str}
    
    def populate_from_proc(self):
        """
        Populate cache from /proc for processes that existed before monitor started.
        Called once at startup.
        """
        for entry in os.listdir('/proc'):
            if not entry.isdigit():
                continue
            pid = int(entry)
            try:
                ppid = self._read_ppid(pid)
                name = self._read_name(pid)
                self.add(pid, ppid, name)
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass  # Process died or no permission
    
    def _read_ppid(self, pid):
        """Read PPID from /proc/{pid}/status"""
        with open(f'/proc/{pid}/status') as f:
            for line in f:
                if line.startswith('PPid:'):
                    return int(line.split()[1])
        return 0
    
    def _read_name(self, pid):
        """Read process name from /proc/{pid}/comm"""
        with open(f'/proc/{pid}/comm') as f:
            return f.read().strip()
    
    def add(self, pid, ppid, name):
        """Add or update a process in the cache."""
        self.processes[pid] = {'ppid': ppid, 'name': name}
    
    def remove(self, pid):
        """Remove a process from the cache (on exit)."""
        self.processes.pop(pid, None)
    
    def get_ancestry(self, pid, max_depth=10):
        """
        Get the ancestry chain for a process.
        
        Args:
            pid: Process ID to get ancestry for
            max_depth: Maximum levels to walk up (prevents infinite loops)
            
        Returns:
            List of (pid, name) tuples from child to ancestor.
            Example: [(12345, 'bash'), (1234, 'auto-cpufreq'), (1, 'systemd')]
        """
        chain = []
        current = pid
        
        for _ in range(max_depth):
            if current <= 1:  # Reached init/systemd
                break
            if current not in self.processes:
                break  # Process not in cache (might be older than monitor)
            
            info = self.processes[current]
            chain.append((current, info['name']))
            current = info['ppid']
        
        return chain
    
    def get_root_ancestor(self, pid):
        """
        Get the first non-shell ancestor (the 'real' parent).
        Skips bash, sh, zsh, etc.
        
        Returns:
            (pid, name) of first interesting ancestor, or (0, 'unknown')
        """
        from src.config import SHELL_NAMES
        
        for ancestor_pid, ancestor_name in self.get_ancestry(pid):
            if ancestor_name not in SHELL_NAMES:
                return (ancestor_pid, ancestor_name)
        
        return (0, 'systemd')