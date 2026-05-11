---
description: Quick setup for PowerScale Analyzer
---

# PowerScale Analyzer Quick Setup

This workflow helps you set up the PowerScale PCAP & Log Analyzer quickly.

## Prerequisites
- Python 3.8 or higher installed
- Wireshark/TShark installed (required for PCAP analysis)

## Setup Steps

1. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Install Wireshark (if not already installed)**
   - Windows: Download from https://www.wireshark.org/download.html
   - Linux: `sudo apt-get install tshark` or `sudo yum install wireshark`
   - macOS: `brew install --cask wireshark`

3. **Start the application**
   ```bash
   streamlit run app.py
   ```

4. **Access the web interface**
   - Open your browser to http://localhost:8501

## Optional: Knowledge Base Setup

The application uses a SQLite knowledge base (knowledge.db) for known issues. If you have a knowledge base file, place it in the project root directory.

## Troubleshooting

- **TShark not found**: Ensure Wireshark is installed and tshark is in your PATH
- **Port 8501 already in use**: Use `streamlit run app.py --server.port 8502` to use a different port
- **Permission denied**: On Linux, you may need to run tshark with sudo or add your user to the wireshark group
