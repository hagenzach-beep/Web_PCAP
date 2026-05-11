import streamlit as st
import subprocess
import os
import tempfile
import shutil
import zipfile
import tarfile
import sqlite3
import re
from datetime import datetime
from pathlib import Path

def sanitize_output(text):
    """Sanitize text to prevent JavaScript errors in Streamlit."""
    if not isinstance(text, str):
        text = str(text)
    # Remove null bytes and control characters
    text = text.replace('\x00', '').replace('\x01', '').replace('\x02', '').replace('\x03', '')
    text = text.replace('\x04', '').replace('\x05', '').replace('\x06', '').replace('\x07', '')
    text = text.replace('\x08', '').replace('\x0b', '').replace('\x0c', '').replace('\x0e', '')
    text = text.replace('\x0f', '').replace('\x10', '').replace('\x11', '').replace('\x12', '')
    # Remove any non-printable characters except newlines and tabs
    text = ''.join(char for char in text if char == '\n' or char == '\t' or char == '\r' or (32 <= ord(char) <= 126))
    return text

# --- TSHARK AUTO-DETECTION ---
def find_tshark():
    """Find tshark executable on Windows or Linux/Mac."""
    # Try PATH first
    tshark_cmd = shutil.which("tshark")
    if tshark_cmd:
        return tshark_cmd
    
    # Common Windows Wireshark installation paths
    windows_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Wireshark\tshark.exe"),
        os.path.expandvars(r"%ProgramFiles%\Wireshark\tshark.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Wireshark\tshark.exe"),
    ]
    
    for path in windows_paths:
        if os.path.exists(path):
            return path
    
    return "tshark"  # Fallback to command name

TSHARK_PATH = find_tshark()

# Check if tshark is available
tshark_available = False
try:
    result = subprocess.run([TSHARK_PATH, "--version"], capture_output=True, timeout=5)
    tshark_available = result.returncode == 0
except:
    pass

# --- SQLITE KNOWLEDGE BASE FUNCTIONS ---
KNOWLEDGE_DB_PATH = r"C:\Users\hagenz\CascadeProjects\powerscale-analyzer\knowledge.db"

def query_knowledge_base(error_pattern, protocol=None):
    """
    Query the SQLite knowledge base for known issues matching error patterns.
    Returns list of dicts with issue details and KB references.
    """
    results = []
    
    if not os.path.exists(KNOWLEDGE_DB_PATH):
        return results
    
    try:
        conn = sqlite3.connect(KNOWLEDGE_DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        if not tables:
            conn.close()
            return results
        
        # Search across all tables for error patterns
        search_term = f"%{error_pattern}%"
        
        for table in tables:
            try:
                # Get column names
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [row[1] for row in cursor.fetchall()]
                
                # Build query to search text columns
                text_cols = [c for c in columns if c.lower() not in ['id', 'rowid']]
                if not text_cols:
                    continue
                
                # Search for pattern in any text column
                where_clauses = [f"{col} LIKE ?" for col in text_cols]
                query = f"SELECT * FROM {table} WHERE {' OR '.join(where_clauses)} LIMIT 10"
                
                cursor.execute(query, [search_term] * len(text_cols))
                rows = cursor.fetchall()
                
                for row in rows:
                    row_dict = dict(row)
                    # Add table name for context
                    row_dict['_source_table'] = table
                    results.append(row_dict)
                    
            except Exception as e:
                # Skip tables that can't be queried
                continue
        
        conn.close()
        
    except Exception as e:
        st.warning(f"Knowledge base query error: {str(e)}")
    
    return results

def check_errors_against_kb(errors_text, protocol_filter=None):
    """
    Check error text against knowledge base and return matching KBs.
    """
    kb_matches = []
    
    # Extract error patterns from text
    error_patterns = []
    
    # Common error patterns to search for
    patterns = [
        "NFS4ERR", "STATUS_PENDING", "ZeroWindow", "Retransmission",
        "SYN_RCVD", "NFS3ERR", "SMB2_ERROR", "TIMEOUT", "CONNECTION_REFUSED",
        "RESET", "FRAGMENTATION", "MTU", "LACP", "STALE", "ACCESS_DENIED"
    ]
    
    for pattern in patterns:
        if pattern.lower() in errors_text.lower():
            error_patterns.append(pattern)
    
    # Query KB for each pattern
    for pattern in error_patterns:
        kb_results = query_knowledge_base(pattern, protocol_filter)
        for result in kb_results:
            kb_matches.append({
                'pattern': pattern,
                'kb_data': result
            })
    
    return kb_matches

# --- CONFIGURATION & UI SETUP ---
st.set_page_config(page_title="PowerScale PCAP & Log Analyzer", layout="wide", page_icon="🌐")
st.title("🌐 PowerScale / Isilon PCAP & Log Analyzer")
st.markdown("### Powered by Windsurf IDE & Streamlit")

# --- ISILON KNOWLEDGE BASE MAPPING ---
KB_MAP = {
    "ZeroWindow": {"desc": "Client or Cluster is throttling traffic. Receive queues may be full.", "kb": "Check InsightIQ or `netstat -an` for full Recv-Q. (Ref: PSEE-6182)"},
    "NFS4ERR_RESOURCE": {"desc": "NFSv4 Resource exhaustion.", "kb": "See KB 000185173 - Memory limits reached."},
    "STATUS_PENDING": {"desc": "SMB node waiting in kernel space.", "kb": "Check lwio gcores or thread stacks."},
    "Retransmission": {"desc": "Network saturation or physical layer issues.", "kb": "Check LACP configuration, Jumbo Frames (MTU 9000), or switch buffer limits (KB Network Design)."},
    "SYN_RCVD": {"desc": "TCP Handshake failing.", "kb": "See KB 000198969 - NFS clients fail to connect."}
}

# --- EXTENDED KB MAPPINGS FOR BATCH ANALYSIS ---
KB_MAPPINGS = {
    "tcp.analysis.zero_window": "KB 000198969 / PSEE-6182: Client or Cluster is throttling traffic. Receive queues may be full. Check 'netstat -an'.",
    "tcp.analysis.retransmission": "Performance Tuning Guide: High retransmissions (>1%). Check LACP configuration, MTU mismatches, or switch buffer limits.",
    "STATUS_PENDING": "SMB Troubleshooting: Node waiting in kernel space. Check lwio gcores or thread stacks.",
    "NFS4ERR_RESOURCE": "KB 000185173: NFSv4 Resource exhaustion. Memory limits reached.",
    "NFS3ERR_NOENT": "NFS Troubleshooting: File or directory not found. Often benign unless correlated with other failures.",
    "STATUS_INVALID_PARAMETER": "SMB Permissions TSG: Often caused by unsupported SACL/DACL types being sent to OneFS."
}

# --- HELPER FUNCTIONS ---
def run_tshark_command(pcap_path, filter_str):
    """Executes a tshark command based on Isilon training docs."""
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -Y "{filter_str}" | head -n 50'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def get_srt_stats(pcap_path, protocol="smb2"):
    """Gets Service Response Time (SRT) for NFS or SMB."""
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -qz {protocol},srt'
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def get_top_ips(pcap_path, limit=10):
    """Returns top IP talkers."""
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -qz endpoints,ip'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout if result.stdout else result.stderr
    return sanitize_output(output)

def run_tshark_streaming(pcap_path, filter_str, description, output_container):
    """Executes tshark command with live output streaming."""
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -Y "{filter_str}"'
    output_lines = []
    progress_text = output_container.empty()
    
    try:
        process = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, universal_newlines=True
        )
        
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line)
            # Keep last 30 lines for display
            display = ''.join(output_lines[-30:])
            if len(output_lines) > 30:
                display = f"... ({len(output_lines) - 30} lines above)\n{display}"
            display = sanitize_output(display)
            progress_text.code(f"[{description}]\n{display}", language='bash')
        
        process.stdout.close()
        process.wait()
        
        final = ''.join(output_lines[:50])  # Return first 50 lines
        final = sanitize_output(final)
        progress_text.code(f"[{description} - Complete]\n{final}", language='bash')
        return final
    except Exception as e:
        error_msg = sanitize_output(str(e))
        progress_text.code(f"[{description} - Error: {error_msg}]")
        return error_msg

def run_tshark_stats_streaming(pcap_path, protocol, description, output_container):
    """Executes tshark SRT stats with live output."""
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -qz {protocol},srt'
    
    progress_text = output_container.empty()
    progress_text.info(f"⏳ Running: {description}...")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout if result.stdout else result.stderr
        output = sanitize_output(output)
        progress_text.code(f"[{description} - Complete]\n{output}", language='bash')
        return output
    except Exception as e:
        error_msg = sanitize_output(str(e))
        progress_text.error(f"[{description} - Error: {error_msg}]")
        return error_msg

def run_custom_script(script_file, target_file):
    """Executes a user-uploaded bash or python script against the log/pcap."""
    import platform
    suffix = script_file.name.split('.')[-1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{suffix}") as tmp_script:
        tmp_script.write(script_file.getvalue())
        tmp_script_path = tmp_script.name
    
    is_windows = platform.system() == 'Windows'
    
    if suffix == 'sh':
        if is_windows:
            cmd = f'wsl bash "{tmp_script_path}" "{target_file}"'
        else:
            cmd = f'bash "{tmp_script_path}" "{target_file}"'
    else:
        python_cmd = 'python' if is_windows else 'python3'
        cmd = f'{python_cmd} "{tmp_script_path}" "{target_file}"'
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if result.returncode != 0 and not output:
            output = f"Command failed with return code {result.returncode}. Ensure {'WSL is installed for bash scripts' if suffix == 'sh' and is_windows else f'{python_cmd} is available'}."
    except Exception as e:
        output = f"Error executing script: {str(e)}"
    finally:
        os.remove(tmp_script_path)
    
    return output

def run_custom_script_live(script_file, target_file, output_container):
    """Executes script with live streaming output to the provided container."""
    import platform
    import subprocess
    import time
    
    suffix = script_file.name.split('.')[-1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{suffix}", mode='wb', delete_on_close=False) as tmp_script:
        tmp_script.write(script_file.getvalue())
        tmp_script_path = tmp_script.name
    
    is_windows = platform.system() == 'Windows'
    
    if suffix == 'sh':
        if is_windows:
            cmd = ['wsl', 'bash', tmp_script_path, target_file]
        else:
            cmd = ['bash', tmp_script_path, target_file]
    else:
        python_cmd = 'python' if is_windows else 'python3'
        cmd = [python_cmd, tmp_script_path, target_file]
    
    full_output = []
    progress_text = output_container.empty()
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        for line in iter(process.stdout.readline, ''):
            full_output.append(line)
            # Update display with last 50 lines to keep it responsive
            display_text = ''.join(full_output[-50:])
            if len(full_output) > 50:
                display_text = f"... ({len(full_output) - 50} lines above)\n" + display_text
            progress_text.code(display_text, language='bash')
        
        process.stdout.close()
        return_code = process.wait()
        
        final_output = ''.join(full_output)
        if return_code != 0:
            final_output += f"\n\n[Script exited with return code {return_code}]"
        
        progress_text.code(final_output, language='bash')
        return final_output
        
    except Exception as e:
        error_msg = f"Error executing script: {str(e)}"
        progress_text.code(error_msg)
        return error_msg
    finally:
        try:
            os.remove(tmp_script_path)
        except:
            pass

# --- BATCH ANALYSIS FUNCTIONS ---
from pathlib import Path

def find_pcaps(root_dir):
    """Recursively finds all PCAP and PCAPNG files in a directory and its subdirectories."""
    pcap_files = []
    root_path = Path(root_dir)
    if not root_path.exists():
        return []
    for ext in ['*.pcap', '*.pcapng', '*.cap']:
        pcap_files.extend(root_path.rglob(ext))
    return [str(p.absolute()) for p in pcap_files]

def run_tshark_cmd(command, timeout=120):
    """Helper function to execute tshark commands safely."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Analysis took too long for this file."
    except Exception as e:
        return f"[ERROR] Execution failed: {str(e)}"

def check_best_practices_and_health(pcap_path):
    """
    Checks for general network health, MTU fragmentation, 
    Zero Windows, and Retransmissions.
    """
    findings = []
    
    global TSHARK_PATH
    
    # 1. Check for Fragmentation (MTU issues)
    frag_cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -Y "ip.flags.mf == 1" -c 5'
    frag_out = run_tshark_cmd(frag_cmd)
    if frag_out:
        findings.append("❌ FRAGMENTATION DETECTED: Packets are being fragmented (ip.flags.mf == 1). Verify end-to-end MTU is set to 9000 (Jumbo Frames).")
    else:
        findings.append("✅ MTU HEALTHY: No IP fragmentation detected in initial scan.")

    # 2. Check for TCP Issues (Zero Window & Retransmissions)
    tcp_err_cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -Y "tcp.analysis.retransmission || tcp.analysis.zero_window" -T fields -e tcp.analysis.flags -c 50'
    tcp_err_out = run_tshark_cmd(tcp_err_cmd)
    
    if "zero window" in tcp_err_out.lower():
        findings.append(f"❌ ZERO WINDOW DETECTED: {KB_MAPPINGS['tcp.analysis.zero_window']}")
    if "retransmission" in tcp_err_out.lower():
        findings.append(f"❌ RETRANSMISSIONS DETECTED: {KB_MAPPINGS['tcp.analysis.retransmission']}")
        
    if not tcp_err_out or ("zero window" not in tcp_err_out.lower() and "retransmission" not in tcp_err_out.lower()):
        findings.append("✅ TCP HEALTHY: No immediate Zero Windows or Retransmissions detected.")
        
    return "\n".join(findings)

def get_protocol_errors(pcap_path):
    """
    Scans for specific NFS and SMB error codes.
    """
    global TSHARK_PATH
    cmd = f'"{TSHARK_PATH}" -r "{pcap_path}" -Y "nfs.status != 0 || smb2.nt_status != 0" -T fields -e nfs.status -e smb2.nt_status -c 100'
    output = run_tshark_cmd(cmd)
    
    triggered_kbs = set()
    for err, kb in KB_MAPPINGS.items():
        if err in output or err.split('_')[-1] in output:
            triggered_kbs.add(f"- {err}: {kb}")
            
    if triggered_kbs:
        return "🚨 PROTOCOL ERRORS FOUND:\n" + "\n".join(triggered_kbs)
    return "✅ No obvious SMB/NFS protocol errors found in standard trace."

def run_advanced_analysis(pcap_path):
    """
    Pulls Service Response Time (SRT) and endpoint statistics.
    """
    results = []
    
    global TSHARK_PATH
    
    # Get Top Talkers (Endpoints)
    results.append("### TOP 10 IP ENDPOINTS ###")
    results.append(run_tshark_cmd(f'"{TSHARK_PATH}" -r "{pcap_path}" -qz endpoints,ip | head -n 15'))
    
    # SMB2 Service Response Time (SRT)
    results.append("\n### SMB2 SERVICE RESPONSE TIMES (SRT) ###")
    results.append(run_tshark_cmd(f'"{TSHARK_PATH}" -r "{pcap_path}" -qz smb2,srt'))
    
    # NFSv3 Service Response Time (SRT)
    results.append("\n### NFSv3 SERVICE RESPONSE TIMES (SRT) ###")
    results.append(run_tshark_cmd(f'"{TSHARK_PATH}" -r "{pcap_path}" -qz rpc,srt,100003,3'))

    # NFSv4 Service Response Time (SRT)
    results.append("\n### NFSv4 SERVICE RESPONSE TIMES (SRT) ###")
    results.append(run_tshark_cmd(f'"{TSHARK_PATH}" -r "{pcap_path}" -qz rpc,srt,100003,4'))

    return "\n".join(results)

def batch_analyze_directory(root_dir, progress_container=None):
    """Main function to process all PCAPs in a directory with live progress."""
    pcaps = find_pcaps(root_dir)
    if not pcaps:
        return {"error": "No PCAP files found in the specified directory."}
    
    report = {}
    total = len(pcaps)
    
    for i, pcap in enumerate(pcaps):
        file_name = os.path.basename(pcap)
        
        if progress_container:
            progress_container.info(f"⏳ Processing {i+1}/{total}: `{file_name}`...")
        
        report[file_name] = {
            "health": check_best_practices_and_health(pcap),
            "errors": get_protocol_errors(pcap),
            "advanced": run_advanced_analysis(pcap),
            "path": pcap
        }
        
        if progress_container:
            progress_container.success(f"✅ Completed {file_name}")
    
    return report

# --- ARCHIVE & SMB FUNCTIONS ---
def extract_archive(archive_path, extract_dir):
    """Extract .zip or .tgz/.tar.gz files to a directory."""
    pcaps_found = []
    
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
        elif archive_path.endswith(('.tar.gz', '.tgz', '.tar')):
            with tarfile.open(archive_path, 'r:*') as tar_ref:
                tar_ref.extractall(extract_dir)
        
        # Find all PCAPs in extracted content
        pcaps_found = find_pcaps(extract_dir)
        return pcaps_found
    except Exception as e:
        st.error(f"Error extracting archive: {str(e)}")
        return []

def mount_smb_share(smb_path, username=None, password=None):
    """Mount SMB share and return local mount point."""
    # Create a temp mount directory
    mount_point = tempfile.mkdtemp(prefix="smb_mount_")
    
    try:
        # Build mount command
        if username and password:
            cmd = f'net use "{mount_point}" "{smb_path}" /user:{username} {password}'
        else:
            cmd = f'net use "{mount_point}" "{smb_path}"'
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return mount_point
        else:
            # Try with powershell alternative
            ps_cmd = f'New-PSDrive -Name "SMBTemp" -PSProvider FileSystem -Root "{smb_path}"'
            if username:
                ps_cmd += f' -Credential (Get-Credential -UserName "{username}" -Message "Enter password")'
            
            result = subprocess.run(["powershell", "-Command", ps_cmd], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return smb_path  # Return the UNC path directly if PowerShell drive works
            
            st.error(f"Failed to mount SMB share: {result.stderr}")
            return None
    except Exception as e:
        st.error(f"SMB mount error: {str(e)}")
        return None

def process_uploaded_archive(uploaded_file, temp_dir):
    """Process uploaded ZIP or TGZ file and extract PCAPs."""
    if not uploaded_file:
        return []
    
    # Save uploaded file
    archive_path = os.path.join(temp_dir, uploaded_file.name)
    with open(archive_path, 'wb') as f:
        f.write(uploaded_file.getvalue())
    
    # Extract and find PCAPs
    extract_dir = os.path.join(temp_dir, "extracted")
    os.makedirs(extract_dir, exist_ok=True)
    
    pcaps = extract_archive(archive_path, extract_dir)
    return pcaps

# --- SIDEBAR: UPLOADS & OPTIONS ---
with st.sidebar:
    st.header("1. Upload Files")
    
    # File source selection
    source_type = st.radio("Select File Source:", [
        "📁 Upload Multiple PCAPs",
        "📦 Upload Archive (ZIP/TGZ)",
        "💻 Local Folder on PC",
        "🌐 SMB Network Share",
        "📄 Single File Upload"
    ])
    
    uploaded_pcaps = None
    uploaded_archive = None
    target_dir = None
    smb_path = None
    smb_username = None
    smb_password = None
    uploaded_pcap = None
    
    if source_type == "📁 Upload Multiple PCAPs":
        uploaded_pcaps = st.file_uploader(
            "Drop multiple PCAP files", 
            type=['pcap', 'pcapng', 'cap'],
            accept_multiple_files=True
        )
        if uploaded_pcaps:
            st.success(f"📎 {len(uploaded_pcaps)} file(s) selected")
    
    elif source_type == "📦 Upload Archive (ZIP/TGZ)":
        uploaded_archive = st.file_uploader(
            "Upload ZIP or TGZ archive",
            type=['zip', 'tar', 'tar.gz', 'tgz']
        )
        if uploaded_archive:
            st.info("📦 Archive will be extracted automatically")
    
    elif source_type == "💻 Local Folder on PC":
        target_dir = st.text_input(
            "Enter local folder path:",
            value="C:/logs",
            help="Example: C:/logs or /home/user/logs"
        )
        if target_dir:
            st.info(f"📂 Will scan: {target_dir}")
    
    elif source_type == "🌐 SMB Network Share":
        st.markdown("**SMB Share Path**")
        smb_path = st.text_input(
            "UNC Path:",
            value="\\\\server\\share\\logs",
            help="Example: \\\\server\\share\\folder"
        )
        with st.expander("🔐 Authentication (optional)"):
            smb_username = st.text_input("Username:", value="")
            smb_password = st.text_input("Password:", value="", type="password")
        if smb_path:
            st.info(f"🌐 Will access: {smb_path}")
    
    else:  # Single File Upload
        uploaded_pcap = st.file_uploader(
            "Drop PCAP or Log File (.pcap, .txt)", 
            type=['pcap', 'pcapng', 'txt', 'log']
        )
    
    uploaded_script = st.file_uploader("Upload Custom Script (.sh, .py)", type=['sh', 'py'])
    
    st.header("2. Analysis Mode")
    analysis_mode = st.radio("Select Review Type:", [
        "Quick Triage (Common Problems)",
        "Deep Protocol Analysis (pscan/SRT)",
        "Best Practice & Configuration Review",
        "Batch Directory Analysis (All PCAPs)",
        "Run Custom Script"
    ])
    
    st.header("3. Escalation")
    generate_swarm = st.checkbox("Generate Swarm/Collab Template")
    
    # Knowledge Base Status
    st.header("4. Knowledge Base")
    if os.path.exists(KNOWLEDGE_DB_PATH):
        db_size_mb = os.path.getsize(KNOWLEDGE_DB_PATH) / (1024 * 1024)
        st.success(f"✅ KB Connected ({db_size_mb:.1f} MB)")
    else:
        st.error("❌ KB Not Found")
        st.info(f"Expected at: `{KNOWLEDGE_DB_PATH}`")

# --- MAIN DASHBOARD ---
# Determine what input mode we're using
is_batch_mode = analysis_mode == "Batch Directory Analysis (All PCAPs)"
has_multiple_uploads = uploaded_pcaps and len(uploaded_pcaps) > 0
has_archive = uploaded_archive is not None
has_local_folder = target_dir and os.path.exists(target_dir)
has_smb = smb_path is not None
has_single_file = uploaded_pcap is not None

# Show tshark status
if not tshark_available:
    st.warning(f"⚠️ **TShark Not Found** at `{TSHARK_PATH}`\n\nPlease install Wireshark from https://www.wireshark.org/download.html")

# Determine effective target directory or files to process
pcap_files_to_process = []
temp_dirs_to_clean = []

if has_archive:
    st.info("� **Archive Mode:** Will extract and analyze PCAPs from archive")
elif has_multiple_uploads:
    st.info(f"📎 **Multiple Files:** {len(uploaded_pcaps)} PCAP(s) ready")
elif has_smb:
    st.info(f"🌐 **SMB Mode:** Will access `{smb_path}`")
elif has_local_folder:
    st.info(f"💻 **Local Folder:** Scanning `{target_dir}`")
elif has_single_file:
    st.info(f"📄 **Single File:** `{uploaded_pcap.name}` ready")

if st.button("Run Analysis"):
    with st.spinner('Preparing and analyzing...'):
        
        # --- HANDLE ARCHIVE EXTRACTION ---
        if has_archive:
            st.markdown("**📦 Extracting Archive...**")
            extract_dir = tempfile.mkdtemp(prefix="pcap_extract_")
            temp_dirs_to_clean.append(extract_dir)
            pcaps = process_uploaded_archive(uploaded_archive, extract_dir)
            if pcaps:
                pcap_files_to_process = pcaps
                st.success(f"✅ Extracted {len(pcaps)} PCAP(s) from archive")
            else:
                st.error("❌ No PCAPs found in archive")
        
        # --- HANDLE MULTIPLE UPLOADS ---
        elif has_multiple_uploads:
            upload_dir = tempfile.mkdtemp(prefix="pcap_uploads_")
            temp_dirs_to_clean.append(upload_dir)
            for upfile in uploaded_pcaps:
                save_path = os.path.join(upload_dir, upfile.name)
                with open(save_path, 'wb') as f:
                    f.write(upfile.getvalue())
                pcap_files_to_process.append(save_path)
        
        # --- HANDLE SMB SHARE ---
        elif has_smb:
            st.markdown("**🌐 Connecting to SMB Share...**")
            smb_mount = mount_smb_share(smb_path, smb_username, smb_password)
            if smb_mount:
                pcaps = find_pcaps(smb_mount)
                if pcaps:
                    pcap_files_to_process = pcaps
                    st.success(f"✅ Found {len(pcaps)} PCAP(s) on SMB share")
                else:
                    st.error("❌ No PCAPs found on SMB share")
            else:
                st.error("❌ Failed to connect to SMB share")
        
        # --- HANDLE LOCAL FOLDER ---
        elif has_local_folder:
            pcaps = find_pcaps(target_dir)
            if pcaps:
                pcap_files_to_process = pcaps
                st.success(f"✅ Found {len(pcaps)} PCAP(s) in folder")
            else:
                st.error("❌ No PCAPs found in folder")
        
        # --- BATCH ANALYSIS MODE ---
        if is_batch_mode and pcap_files_to_process:
            st.subheader("📁 Batch Directory Analysis")
            
            with st.expander("📋 What this mode checks for", expanded=True):
                st.markdown("""
                **Batch Processing of All PCAPs:**
                - 🔍 **Health Checks** - MTU fragmentation, TCP retransmissions, zero windows
                - 🚨 **Protocol Errors** - NFS/SMB error codes and KB mapping
                - 📊 **SRT Analysis** - Service Response Times for SMB2, NFSv3, NFSv4
                - 📈 **Top Talkers** - IP endpoints analysis per file
                **Output:** Individual reports for each file with escalation template
                """)
            
            # Live progress
            st.markdown("**Live Progress Window**")
            progress_container = st.container()
            with progress_container:
                batch_progress = st.empty()
                batch_progress.info(f"🔍 Processing {len(pcap_files_to_process)} PCAP file(s)...")
            
            # Process all files
            report = {}
            total = len(pcap_files_to_process)
            
            for i, pcap_path in enumerate(pcap_files_to_process):
                file_name = os.path.basename(pcap_path)
                batch_progress.info(f"⏳ {i+1}/{total}: Analyzing `{file_name}`...")
                
                report[file_name] = {
                    "health": check_best_practices_and_health(pcap_path),
                    "errors": get_protocol_errors(pcap_path),
                    "advanced": run_advanced_analysis(pcap_path),
                    "path": pcap_path
                }
                
                batch_progress.success(f"✅ Completed {file_name} ({i+1}/{total})")
            
            st.success(f"✅ Successfully analyzed **{len(report)} PCAP file(s)**!")
            
            # Display results in tabs
            if report:
                st.markdown("### 📊 Per-File Analysis Results")
                tabs = st.tabs(list(report.keys()))
                
                for i, (file_name, data) in enumerate(report.items()):
                    with tabs[i]:
                        st.markdown(f"#### 📄 `{file_name}`")
                        st.caption(f"Path: `{data['path']}`")
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.info("#### ✅ Best Practice & Health Review")
                            st.markdown(sanitize_output(data["health"]))
                            
                            st.error("#### 🚨 Known Issues & Errors")
                            st.markdown(sanitize_output(data["errors"]))
                            
                            kb_list = [line for line in sanitize_output(data["errors"]).split('\n') if "KB" in line or "PSEE" in line]
                            kb_string = "\n".join(kb_list) if kb_list else "None identified automatically."
                            
                            st.markdown("#### 📝 L2 Escalation / Swarm Template")
                            st.code(f"""
Severity: [P2/P3]
PCAP File: {file_name}
Problem Statement: Intermittent latency / connection drops.
Downloaded Logs: {data['path']}
Errors found in PCAP:
{kb_string}
Specific question for SME: Review of SRT shows latency on [SMB/NFS]. Is this cluster CPU or disk bound?
                            """)
                        
                        with col2:
                            st.warning("#### 🔬 Deep Analysis (SRT & Top Talkers)")
                            with st.expander("View Advanced Tshark Output"):
                                st.code(data["advanced"], language='bash')
        
        # --- SINGLE FILE MODE (other analysis types) ---
        elif has_single_file and not is_batch_mode:
            # Save single file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pcap') as tmp_pcap:
                tmp_pcap.write(uploaded_pcap.getvalue())
                tmp_pcap_path = tmp_pcap.name
            
            st.success(f"Successfully loaded: **{uploaded_pcap.name}**")
            
            with st.spinner('Analyzing...'):
                # --- 1. QUICK TRIAGE ---
                if analysis_mode == "Quick Triage (Common Problems)":
                    st.subheader("🛠️ Quick Triage Findings")
                    
                    with st.expander("📋 What this mode checks for", expanded=True):
                        st.markdown("""
                        **Checking for common network and protocol issues:**
                        - 🔍 **Top IP Endpoints** - Identifies busiest talkers (potential hotspots)
                        - 🔄 **TCP Retransmissions** - Network congestion or packet loss indicators
                        - 🚫 **Zero Window** - Flow control issues, receive buffer exhaustion
                        - ⚠️ **NFS Errors** - NFS status codes (access denied, stale file handles, etc.)
                        - ⚠️ **SMB Errors** - SMB2/NT status codes (authentication, resource issues)
                        """)
                    
                    st.markdown("**Live Progress Window**")
                    progress_container = st.container()
                    with progress_container:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.markdown("📊 **Top IP Endpoints (Talkers)**")
                            top_ips_box = st.empty()
                            st.code(get_top_ips(tmp_pcap_path))
                        
                        with col2:
                            st.markdown("🚨 **Common TCP/Protocol Errors**")
                            errors_box = st.empty()
                            error_filter = 'tcp.analysis.retransmission || tcp.analysis.zero_window || nfs.status != 0 || smb2.nt_status != 0'
                            errors = run_tshark_streaming(tmp_pcap_path, error_filter, "Scanning for errors", errors_box)

                    # Sanitize errors before processing
                    errors = sanitize_output(errors)
                    
                    st.markdown("### 📚 Related KBs & Next Actions")
                    found_issues = []
                    kb_matches = []
                    
                    # Check hardcoded KB mappings
                    for key, val in KB_MAP.items():
                        if key.lower() in errors.lower():
                            found_issues.append(key)
                            st.warning(f"**Found {key}**: {sanitize_output(val['desc'])} \n\n**Action**: {sanitize_output(val['kb'])}")
                    
                    # Query SQLite Knowledge Base for additional matches
                    if os.path.exists(KNOWLEDGE_DB_PATH):
                        with st.spinner("🔍 Querying knowledge base..."):
                            kb_matches = check_errors_against_kb(errors)
                            if kb_matches:
                                st.success(f"📖 Found {len(kb_matches)} related KB article(s) in database")
                                for match in kb_matches[:5]:  # Show top 5
                                    with st.expander(f"🔍 {match['pattern']} - KB Match"):
                                        for col, val in match['kb_data'].items():
                                            if not col.startswith('_') and val:
                                                # Sanitize value for display
                                                try:
                                                    display_val = sanitize_output(val)
                                                    if display_val.strip():
                                                        st.markdown(f"**{col}:** `{display_val[:500]}`")
                                                except Exception as e:
                                                    st.write(f"**{col}:** [Display Error]")
                    
                    if not found_issues and not kb_matches:
                        st.info("✅ No critically mapped known issues found in this snapshot.")

                # --- 2. DEEP PROTOCOL ANALYSIS ---
                elif analysis_mode == "Deep Protocol Analysis (pscan/SRT)":
                    st.subheader("🔍 Deep Protocol Latency Analysis")
                    
                    with st.expander("📋 What this mode checks for", expanded=True):
                        st.markdown("""
                        **Service Response Time (SRT) Analysis:**
                        - ⏱️ **SMB2 SRT** - Measures SMB2 protocol response latency
                          - Min/Avg/Max response times per operation type
                          - Helps identify slow cluster responses vs network latency
                        - ⏱️ **NFSv3 SRT** - Measures NFS RPC response latency
                          - Breakdown by procedure (READ, WRITE, GETATTR, etc.)
                          - Identifies which operations are slowest
                        
                        **Interpretation:**
                        - High SRT = Cluster is slow to respond (investigate PowerScale)
                        - Low SRT + client latency = Network or client-side issue
                        """)
                    
                    st.markdown("**Live Progress Window**")
                    progress_container = st.container()
                    with progress_container:
                        tab1, tab2 = st.tabs(["📁 SMB Response Times", "📁 NFS Response Times"])
                        with tab1:
                            smb_box = st.empty()
                            st.markdown("`tshark -qz smb2,srt`")
                            smb_result = run_tshark_stats_streaming(tmp_pcap_path, "smb2", "SMB2 SRT Analysis", smb_box)
                        with tab2:
                            nfs_box = st.empty()
                            st.markdown("`tshark -qz rpc,srt,100003,3` (NFSv3)")
                            nfs_result = run_tshark_stats_streaming(tmp_pcap_path, "rpc,srt,100003,3", "NFSv3 SRT Analysis", nfs_box)
                        
                    with st.expander("📖 How to interpret results"):
                        st.markdown("""
                        **High SRT (Service Response Time)** indicates the PowerScale cluster is taking too long to build replies.
                        **Low SRT with client-reported latency** suggests the issue is on the network or client side.
                        
                        Common thresholds:
                        - SMB2: Avg > 100ms may indicate cluster load issues
                        - NFS: Avg > 50ms for READ/WRITE may indicate backend storage latency
                        """)

                # --- 3. BEST PRACTICES REVIEW ---
                elif analysis_mode == "Best Practice & Configuration Review":
                    st.subheader("✅ Best Practices Review")
                    
                    with st.expander("📋 What this mode checks for", expanded=True):
                        st.markdown("""
                        **Configuration & Best Practice Validation:**
                        - 📦 **IP Fragmentation** - Detects `ip.flags.mf == 1` (More Fragments bit)
                          - Indicates MTU mismatch or fragmentation occurring
                          - Should NOT happen if Jumbo Frames (MTU 9000) properly configured
                        - 🔒 **Unencrypted Traffic** - Identifies SMB/NFS without encryption
                          - SMB3 without encryption flags
                          - NFS without Kerberos (sec=krb5)
                        - 📡 **LACP/Link Aggregation** - Checks for proper bonding behavior
                        - 🌐 **SmartConnect/DNS** - Validates client connection patterns
                        
                        **Expected Best Practices:**
                        - Jumbo Frames (MTU 9000) on 10G+ networks
                        - Passive LACP for PowerScale (do not force active)
                        - DNS TTL = 0 for SmartConnect zones
                        """)
                    
                    st.markdown("**Live Progress Window**")
                    progress_container = st.container()
                    with progress_container:
                        st.markdown("🔍 **Scanning for fragmentation and configuration issues...**")
                        frag_box = st.empty()
                        
                        # Check for fragmentation
                        frag_filter = 'ip.flags.mf == 1 || icmp.type == 3 && icmp.code == 4'
                        frag_check = run_tshark_streaming(tmp_pcap_path, frag_filter, "Checking fragmentation & MTU issues", frag_box)
                        
                        if frag_check.strip():
                            st.error("🚨 Fragmentation or MTU issues detected!")
                            st.code(frag_check)
                        else:
                            st.success("✅ No fragmentation detected - MTU settings look good")
                    
                    with st.expander("📖 Best Practice Recommendations"):
                        st.markdown("""
                        **Jumbo Frames (MTU 9000):**
                        - Required for 10G/40G/100G networks to reduce CPU overhead
                        - Must be configured end-to-end: clients, switches, and PowerScale nodes
                        - Fragmentation causes performance degradation
                        
                        **LACP Configuration:**
                        - PowerScale uses **passive LACP** only
                        - Do NOT configure active LACP on switches for PowerScale connections
                        - SMB3 Multichannel works independently of LACP
                        
                        **SmartConnect/DNS:**
                        - DNS TTL should be set to 0 for SmartConnect zone records
                        - Ensures clients re-query DNS for load balancing
                        - Verify clients resolve to correct SSIP (SmartConnect Service IP)
                        """)

                # --- 4. CUSTOM SCRIPT ---
                elif analysis_mode == "Run Custom Script":
                    st.subheader("⚙️ Custom Script Output")
                    if uploaded_script:
                        # Create a container for live output
                        st.markdown("**Live Progress Window**")
                        progress_container = st.container()
                        with progress_container:
                            output_box = st.empty()
                        
                        # Run script with live output
                        run_custom_script_live(uploaded_script, tmp_pcap_path, output_box)
                    else:
                        st.warning("Please upload a Bash or Python script in the sidebar.")

                # --- ESCALATION TEMPLATE ---
                if generate_swarm:
                    st.divider()
                    st.subheader("🚨 Pod Swarm / Collab Escalation Template")
                    st.markdown("Copy and paste this into Jira/Slack for L2/SME Escalation based on current findings:")
                    st.code(f"""
Severity: [P2/P3 - Insert based on customer impact]
Problem Statement: Clients connecting via [SMB/NFS] experiencing [Latency/Disconnects].
Downloaded Logs: Path to logs on Elvis (/srdata/...)
Errors found in logs/PCAPs: 
- {', '.join(found_issues) if 'found_issues' in locals() and found_issues else 'List specific Tshark output or Error codes here'}
DU/DL/DRU: [Data Unavailable/Data Loss/Data Read Unavailable]
Confirmed Active call with the customer: [Yes/No]
Current status communicated to the customer: PCAP analysis complete, reviewing findings with L2.
Specific question for SME: Why are we seeing high SRT on node X interface Y?
KB/TSG/Confluence reference if reviewed: {', '.join([KB_MAP[i]['kb'] for i in found_issues]) if 'found_issues' in locals() and found_issues else 'NFS/SMB Troubleshooting Guide'}
                    """)
            
            # Cleanup single file temp file
            try:
                os.remove(tmp_pcap_path)
            except:
                pass
        
        # Cleanup temp dirs
        for tmp_dir in temp_dirs_to_clean:
            try:
                shutil.rmtree(tmp_dir)
            except:
                pass

else:
    # No input selected
    st.info("👈 Please select a file source from the sidebar to begin analysis")
