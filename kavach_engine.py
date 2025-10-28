# kavach_engine.py
# V2 - Adds progress callback to scan_directory

import pefile
import math
import os

# --- Suspicious Imports List (Keep as is) ---
SUSPICIOUS_IMPORTS = {
    "SetWindowsHookExA": "Potentially a keylogger", "GetAsyncKeyState": "Potentially a keylogger",
    "GetKeyState": "Potentially a keylogger", "CreateRemoteThread": "Used for code injection",
    "WriteProcessMemory": "Used to write malicious code", "OpenProcess": "Used to access other processes",
    "VirtualAllocEx": "Used to allocate memory in another process",
    "LsaQueryInformationPolicy": "Can steal password policies", "SamQueryInformationUser": "Can steal user info",
    "SetFileAttributesA": "Can hide files"
}

# --- Analysis Functions (Keep as is) ---
def shannon_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0: entropy += - p_x * math.log(p_x, 2)
    return entropy

def analyze_entropy(filepath):
    try:
        with open(filepath, "rb") as f: data = f.read()
        entropy = shannon_entropy(data)
        if entropy > 7.2: return "HIGH", f"{entropy:.2f} (Suspicious: Likely packed/encrypted)"
        else: return "NORMAL", f"{entropy:.2f} (Looks normal)"
    except Exception as e: return "ERROR", f"Could not read file: {e}"

def analyze_imports(filepath):
    try:
        pe = pefile.PE(filepath)
        found_imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', 'ignore') if imp.name else None
                    if func_name in SUSPICIOUS_IMPORTS:
                        found_imports.append(f"{func_name}: {SUSPICIOUS_IMPORTS[func_name]}")
        if not found_imports: return "CLEAN", "No suspicious function imports found."
        else: return "SUSPICIOUS", found_imports
    except pefile.PEFormatError: return "NOT_PE", "Not a Windows .exe file. Cannot scan."
    except Exception as e: return "ERROR", f"Could not parse imports: {e}"

def analyze_header(filepath):
    try:
        pe = pefile.PE(filepath)
        anomalies = []
        if pe.FILE_HEADER.TimeDateStamp == 0: anomalies.append("Header timestamp is zero (common in malware)")
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        text_section = None
        for section in pe.sections:
            if section.Name.startswith(b'.text'): text_section = section; break
        if text_section and not (text_section.VirtualAddress <= entry_point < (text_section.VirtualAddress + text_section.SizeOfRawData)):
            anomalies.append("Entry point is outside the .text section (suspicious)")
        if not anomalies: return "CLEAN", "PE Header looks normal."
        else: return "SUSPICIOUS", anomalies
    except pefile.PEFormatError: return "NOT_PE", "Not a Windows .exe file."
    except Exception as e: return "ERROR", f"Could not parse header: {e}"

# --- Single File Scan Function (Keep as is) ---
def run_scan(filepath):
    entropy_status, entropy_data = analyze_entropy(filepath)
    try:
        pe = pefile.PE(filepath)
        import_status, import_data = analyze_imports(filepath)
        header_status, header_data = analyze_header(filepath)
    except pefile.PEFormatError:
        import_status, import_data = ("SKIPPED", "Not a valid PE file.")
        header_status, header_data = ("SKIPPED", "Not a valid PE file.")
    except Exception as e: return {"error": f"An unknown error occurred: {e}"}
    risk_score = 0
    if entropy_status == "HIGH": risk_score += 2
    if import_status == "SUSPICIOUS": risk_score += 2
    if header_status == "SUSPICIOUS": risk_score += 1
    return { "filepath": filepath, "risk_score": risk_score, "entropy": (entropy_status, entropy_data),
             "imports": (import_status, import_data), "header": (header_status, header_data) }

# --- MODIFIED: Directory Scan Function ---
def scan_directory(dirpath, progress_callback=None): # <-- Added callback argument
    """
    Walks a directory and scans all .exe/.dll files, reporting progress.
    """
    files_scanned = 0
    threats_found = []

    for root, dirs, files in os.walk(dirpath):
        for file in files:
            if file.lower().endswith(('.exe', '.dll')):
                filepath = os.path.join(root, file)

                # --- NEW: Call the progress callback ---
                if progress_callback:
                    try:
                        progress_callback(filepath) # Report the file being scanned
                    except Exception as cb_e:
                        print(f"Error in progress callback: {cb_e}") # Avoid crashing scan

                files_scanned += 1
                try:
                    results = run_scan(filepath)
                    if results.get("risk_score", 0) > 0:
                        threats_found.append(results)
                except Exception as e:
                    print(f"Could not scan {filepath}: {e}")

    # --- NEW: Signal completion via callback ---
    if progress_callback:
        progress_callback(None) # Pass None to signal scan completion

    return { "files_scanned": files_scanned, "threats_found": threats_found }