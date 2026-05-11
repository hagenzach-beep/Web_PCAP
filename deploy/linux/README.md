# PowerScale Analyzer - Linux Deployment

This package contains everything needed to deploy the PowerScale PCAP & Log Analyzer on Linux systems.

## Quick Start

1. **Make the setup script executable:**
   ```bash
   chmod +x setup.sh
   ```

2. **Run the setup script:**
   ```bash
   ./setup.sh
   ```

3. **Start the application:**
   ```bash
   source venv/bin/activate
   streamlit run app.py
   ```

4. **Access the web interface:**
   Open your browser to http://localhost:8501

## Supported Distributions

- Ubuntu/Debian
- Fedora/RHEL/CentOS
- Arch Linux

## System Requirements

- Python 3.8 or higher
- tshark (Wireshark command-line tool)
- 500MB free disk space
- Network access for package installation

## Manual Installation

If the automated script doesn't work for your distribution:

1. **Install Python and tshark:**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python3 python3-pip tshark
   
   # Fedora/RHEL
   sudo dnf install python3 python3-pip wireshark
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   streamlit run app.py
   ```

## Running as a System Service

The setup script creates a systemd service file. To use it:

```bash
sudo mv powerscale-analyzer.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable powerscale-analyzer
sudo systemctl start powerscale-analyzer
sudo systemctl status powerscale-analyzer
```

## Troubleshooting

### TShark Permission Denied
Add your user to the wireshark group:
```bash
sudo usermod -aG wireshark $USER
```
Then log out and log back in.

### Port 8501 Already in Use
Use a different port:
```bash
streamlit run app.py --server.port 8502
```

### Virtual Environment Issues
Delete and recreate the venv:
```bash
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
