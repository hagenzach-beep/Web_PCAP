#!/bin/bash

# PowerScale Analyzer - Linux Setup Script
# This script sets up the PowerScale PCAP & Log Analyzer on Linux systems

set -e

echo "=========================================="
echo "PowerScale Analyzer - Linux Setup"
echo "=========================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Please do not run as root. This script will use sudo when needed."
    exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
else
    echo "Cannot detect Linux distribution. Exiting."
    exit 1
fi

echo "Detected distribution: $DISTRO"

# Install system dependencies
echo ""
echo "Installing system dependencies..."
case $DISTRO in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip python3-venv tshark wireshark-common
        ;;
    fedora|rhel|centos)
        sudo dnf install -y python3 python3-pip wireshark
        ;;
    arch)
        sudo pacman -S --noconfirm python python-pip wireshark
        ;;
    *)
        echo "Unsupported distribution. Please manually install Python 3, pip, and tshark."
        exit 1
        ;;
esac

# Create virtual environment
echo ""
echo "Creating Python virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo ""
echo "Creating necessary directories..."
mkdir -p pcap_files
mkdir -p logs

# Set up tshark permissions (optional but recommended)
echo ""
echo "Setting up tshark permissions..."
echo "You may need to add your user to the wireshark group to run tshark without sudo."
echo "Run: sudo usermod -aG wireshark $USER"
echo "Then log out and log back in for changes to take effect."

# Create systemd service file (optional)
echo ""
echo "Creating systemd service file..."
cat <<EOF > powerscale-analyzer.service
[Unit]
Description=PowerScale PCAP & Log Analyzer
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment="PATH=$(pwd)/venv/bin"
ExecStart=$(pwd)/venv/bin/streamlit run app.py --server.port=8501 --server.address=0.0.0.0
Restart=always

[Install]
WantedBy=multi-user.target
EOF

echo "Service file created: powerscale-analyzer.service"
echo "To install as a system service, run:"
echo "  sudo mv powerscale-analyzer.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable powerscale-analyzer"
echo "  sudo systemctl start powerscale-analyzer"

# Finished
echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "To start the application:"
echo "  source venv/bin/activate"
echo "  streamlit run app.py"
echo ""
echo "Or to start it in the background:"
echo "  source venv/bin/activate"
echo "  nohup streamlit run app.py --server.port=8501 > logs/app.log 2>&1 &"
echo ""
echo "Access the application at: http://localhost:8501"
