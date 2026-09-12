# 🔐 Port Scanner

A simple Python port scanner that checks common ports on a host and generates a readable HTML report.

![Python](https://img.shields.io/badge/python-3.8%2B-blue)

## What it does

- Scans a list of ports concurrently (fast, not slow one-by-one)
- Defaults to common ports, or accepts a custom range
- Outputs a clean HTML report with port, service, and status

## Usage

```bash
python scanner.py 127.0.0.1
python scanner.py 127.0.0.1 -p 1-1024
python scanner.py 127.0.0.1 -o myscan.html
