# PowerScale Analyzer - Windows Deployment

This package contains everything needed to deploy the PowerScale PCAP & Log Analyzer on Windows systems.

## Quick Start

1. **Run the setup script as Administrator (recommended):**
   ```powershell
   Right-click on setup.ps1 -> Run with PowerShell
   ```
   
   Or run from PowerShell:
   ```powershell
   .\setup.ps1
   ```

2. **Start the application:**
   - Double-click `start.bat` to run in foreground
   - Double-click `start-background.bat` to run in background
   - Or run manually:
     ```powershell
     .\venv\Scripts\activate.bat
     streamlit run app.py
     ```

3. **Access the web interface:**
   Open your browser to http://localhost:8501

## Prerequisites

- Windows 10 or later
- Python 3.8 or higher
- Wireshark (for TShark - required for PCAP analysis)

## Manual Installation

If the automated script doesn't work:

1. **Install Python:**
   - Download from https://www.python.org/downloads/
   - **Important:** Check "Add Python to PATH" during installation

2. **Install Wireshark:**
   - Download from https://www.wireshark.org/download.html
   - This installs TShark which is required for PCAP analysis

3. **Create virtual environment:**
   ```powershell
   python -m venv venv
   ```

4. **Activate virtual environment:**
   ```powershell
   .\venv\Scripts\activate.bat
   ```

5. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

6. **Run the application:**
   ```powershell
   streamlit run app.py
   ```

## Troubleshooting

### Python not found
- Ensure Python is installed and added to PATH
- Restart your terminal/command prompt after installation
- Verify with: `python --version`

### TShark not found
- Install Wireshark from https://www.wireshark.org/download.html
- The application will search common Wireshark installation paths
- Ensure TShark is in your PATH if installed in a custom location

### Port 8501 already in use
Use a different port:
```powershell
streamlit run app.py --server.port 8502
```

### Virtual environment issues
Delete and recreate the venv:
```powershell
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\activate.bat
pip install -r requirements.txt
```

### PowerShell execution policy
If you get an execution policy error:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## Running as a Windows Service (Optional)

To run the application as a Windows service, you can use tools like:
- NSSM (Non-Sucking Service Manager): https://nssm.cc/
- Windows Service Wrapper (WinSW): https://github.com/winsw/winsw

Example with NSSM:
```powershell
nssm install PowerScaleAnalyzer "C:\path\to\venv\Scripts\python.exe" "-m" "streamlit" "run" "app.py" "--server.port=8501"
nssm start PowerScaleAnalyzer
```

## Firewall Configuration

If you want to access the application from other computers on your network:

1. Open Windows Defender Firewall
2. Create an inbound rule for port 8501
3. Allow TCP traffic on port 8501

Then access from another computer using:
```
http://<your-computer-ip>:8501
```
