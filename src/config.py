# src/config.py
"""
Configuration for ebpf-sentinel.
Centralized place for all configurable parameters.
"""

# =========================================================
# NOISY_SERVICES
# 
# Services that constantly spawn processes and create noise.
# The cache will filter out processes whose root ancestor
# (first non-shell parent) is in this list.
#
# To add a new noisy service:
#   1. Run the monitor without filters
#   2. Identify the root ancestor name
#   3. Add it here
# =========================================================
NOISY_SERVICES = {
    # Power management
    'auto-cpufreq',
    'cpufreqctl.auto',  # auto-cpufreq's script runner
    'tlp',
    'power_monitor.s',
    
    # Desktop environment
    'waybar',
    'hyprsunset',
    'hyprland',
    'Hyprland',
    'Hyprsunset.sh',
    
    # System utilities
    'cpu-x',
}

# =========================================================
# SHELL_NAMES
#
# Shell processes to skip when walking up the ancestry tree.
# get_root_ancestor() skips these to find the "real" parent.
# =========================================================
SHELL_NAMES = {
    'bash',
    'sh',
    'zsh',
    'fish',
    'dash',
    'tcsh',
    'csh',
}
