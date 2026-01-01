# Makefile for ebpf-sentinel

PYTHON := ./venv/bin/python
PIP := ./venv/bin/pip

.PHONY: setup run clean

# 1. Initial Setup (Run once)
setup:
	@echo "🔧 Installing system dependencies (Requires Sudo)..."
	sudo pacman -S --needed bcc bcc-tools python-bcc linux-headers
	@echo "🐍 Creating Virtual Environment (Hybrid)..."
	python -m venv venv --system-site-packages
	@echo "📦 Installing extra Python dependencies..."
	$(PIP) install -r requirements.txt
	@echo "✅ Setup complete!"

# 2. Run the Monitor (Daily Workflow)
# Note: eBPF requires root (sudo). We explicitly use the venv python.
run:
	@echo "🚀 Starting Neuro-Link (Sudo required)..."
	# PYTHONPATH=. tells python to include project root in module search
	sudo PYTHONPATH=. $(PYTHON) src/main.py

# 3. Cleanup (Useful to start fresh)
clean:
	rm -rf venv
	find . -type d -name "__pycache__" -exec rm -rf {} +
	@echo "🧹 Cleanup complete."
