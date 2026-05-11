# PowerScale PCAP & Log Analyzer

A powerful web-based tool for analyzing PowerScale/Isilon PCAP files and logs, built with Streamlit. This tool helps network administrators and storage engineers quickly identify common issues, analyze protocol errors, and generate escalation templates.

## Features

- **Multiple File Sources**: Upload PCAPs, extract from archives (ZIP/TGZ), access local folders, or mount SMB shares
- **Analysis Modes**:
  - Quick Triage for common problems
  - Deep Protocol Analysis with SRT (Service Response Time)
  - Best Practice & Configuration Review
  - Batch Directory Analysis
  - Custom Script Execution
- **Knowledge Base Integration**: SQLite-based knowledge base for known issues and KB references
- **Protocol Support**: NFSv3, NFSv4, SMB2 analysis
- **Network Health Checks**: MTU fragmentation, TCP retransmissions, zero window detection
- **Escalation Templates**: Auto-generated L2/Swarm escalation templates

## Deployment Options

This project includes deployment packages for multiple platforms:

| Platform | Location | Quick Start |
|----------|----------|-------------|
| **Docker** | Root directory | `docker-compose up` |
| **Linux** | `deploy/linux/` | Run `./setup.sh` |
| **Windows** | `deploy/windows/` | Run `setup.ps1` |
| **Web** | `deploy/web/` | See `deploy/web/README.md` |
| **Windsurf** | `.windsurf/workflows/setup.md` | Use Windsurf workflow |

## Quick Start

### Option 1: Docker (Recommended)

```bash
docker-compose up
```

Access at: http://localhost:8501

### Option 2: Windows

```powershell
cd deploy/windows
.\setup.ps1
```

Then double-click `start.bat` or run `start-background.bat`

### Option 3: Linux

```bash
cd deploy/linux
chmod +x setup.sh
./setup.sh
source venv/bin/activate
streamlit run app.py
```

### Option 4: Manual Setup

1. Install Python 3.8+
2. Install Wireshark (for TShark)
3. Create virtual environment: `python -m venv venv`
4. Activate venv:
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Run: `streamlit run app.py`

## Prerequisites

- **Python**: 3.8 or higher
- **TShark**: Part of Wireshark (required for PCAP analysis)
  - Download from https://www.wireshark.org/download.html
- **Knowledge Base**: Optional SQLite database (`knowledge.db`) for known issues

## Project Structure

```
powerscale-analyzer/
├── app.py                      # Main Streamlit application
├── requirements.txt            # Python dependencies
├── knowledge.db                # Knowledge base (optional)
├── Dockerfile                  # Docker image definition
├── docker-compose.yml          # Docker Compose configuration
├── .streamlit/
│   └── config.toml            # Streamlit configuration
├── .windsurf/
│   └── workflows/
│       └── setup.md           # Windsurf workflow
├── deploy/
│   ├── linux/
│   │   ├── setup.sh           # Linux setup script
│   │   └── README.md          # Linux deployment guide
│   ├── windows/
│   │   ├── setup.ps1          # Windows setup script
│   │   └── README.md          # Windows deployment guide
│   └── web/
│       └── README.md          # Web deployment guide
└── README.md                   # This file
```

## Usage

### Starting the Application

After installation, start the application:

```bash
streamlit run app.py
```

Or with custom port:

```bash
streamlit run app.py --server.port 8502
```

### Using the Web Interface

1. Open http://localhost:8501 in your browser
2. Select file source in the sidebar:
   - Upload multiple PCAPs
   - Upload archive (ZIP/TGZ)
   - Local folder on PC
   - SMB network share
   - Single file upload
3. Choose analysis mode:
   - Quick Triage
   - Deep Protocol Analysis
   - Best Practice Review
   - Batch Directory Analysis
   - Custom Script
4. Click "Run Analysis"
5. View results in the main dashboard

### Analysis Modes

#### Quick Triage
- Identifies top IP endpoints
- Checks for TCP retransmissions
- Detects zero window conditions
- Provides quick insights into common issues

#### Deep Protocol Analysis
- Service Response Time (SRT) for SMB2
- SRT for NFSv3 and NFSv4
- Detailed endpoint statistics
- Advanced TShark output

#### Best Practice Review
- MTU fragmentation detection
- TCP health checks
- Protocol error analysis
- KB mapping for known issues

#### Batch Directory Analysis
- Processes all PCAPs in a directory
- Per-file health and error reports
- Advanced statistics for each file
- Batch escalation templates

#### Custom Script
- Upload and run custom Bash or Python scripts
- Live output streaming
- Useful for custom analysis workflows

## Knowledge Base

The application uses a SQLite knowledge base (`knowledge.db`) to provide:
- Known issue mappings
- KB article references
- PSEE (Product Support Escalation Engineering) references
- Troubleshooting guidance

To add your own knowledge base:
1. Create a SQLite database
2. Add tables with issue information
3. Place as `knowledge.db` in the project root

## Troubleshooting

### TShark Not Found

**Windows:**
- Install Wireshark from https://www.wireshark.org/download.html
- Ensure TShark is in your PATH or in standard locations:
  - `C:\Program Files\Wireshark\tshark.exe`
  - `C:\Program Files (x86)\Wireshark\tshark.exe`

**Linux:**
```bash
sudo apt-get install tshark  # Ubuntu/Debian
sudo dnf install wireshark   # Fedora/RHEL
```

**macOS:**
```bash
brew install --cask wireshark
```

### Port Already in Use

Use a different port:
```bash
streamlit run app.py --server.port 8502
```

### Virtual Environment Issues

**Delete and recreate:**
```bash
# Windows
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\activate.bat
pip install -r requirements.txt

# Linux/Mac
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Permission Issues (Linux)

Add your user to the wireshark group:
```bash
sudo usermod -aG wireshark $USER
```
Then log out and log back in.

## Deployment Guides

For detailed deployment instructions for each platform, see:

- [Docker Deployment](#docker-deployment)
- [Linux Deployment](deploy/linux/README.md)
- [Windows Deployment](deploy/windows/README.md)
- [Web Deployment](deploy/web/README.md)

## Docker Deployment

### Quick Start

```bash
docker-compose up
```

### Manual Docker Build

```bash
docker build -t powerscale-analyzer .
docker run -p 8501:8501 -v $(pwd)/knowledge.db:/app/knowledge.db:ro powerscale-analyzer
```

### Docker Compose Options

Edit `docker-compose.yml` to customize:
- Port mapping
- Volume mounts
- Environment variables
- Restart policies

## Security Considerations

- **File Upload Limits**: Configure appropriate upload size limits in `.streamlit/config.toml`
- **Network Access**: Consider firewall rules for production deployments
- **Authentication**: Add authentication for production deployments
- **HTTPS**: Enable HTTPS for production web deployments

## Performance Tips

- **Large PCAP Files**: Use batch analysis for directories with many files
- **Memory**: Increase memory limits for Docker deployments if analyzing large files
- **TShark Optimization**: The app uses head/tail limits to prevent excessive output

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is provided as-is for use in PowerScale/Isilon network analysis.

## Support

For issues or questions:
- Check the troubleshooting section
- Review platform-specific deployment guides
- Ensure TShark is properly installed
- Verify Python and dependency versions

## Changelog

### Version 1.0
- Initial release
- Multi-platform deployment packages
- Docker, Linux, Windows, and web deployment options
- Batch analysis capabilities
- Knowledge base integration
- SMB share mounting support
- Archive extraction (ZIP/TGZ)
