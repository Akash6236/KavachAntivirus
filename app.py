# app.py
# V13 - Adds real-time file display during folder scan

import customtkinter as ctk
from tkinterdnd2 import DND_FILES, TkinterDnD
from tkinter import filedialog
import os
import datetime

# Matplotlib Imports
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib
matplotlib.use("TkAgg")

# Import Engine
import kavach_engine

# #################################################################### #
# ##################    YOUR CUSTOMIZATION AREA    ################### #
# #################################################################### #
# --- Theme, Colors, Size, Speeds (Keep your previous settings) ---
ctk.set_appearance_mode("dark")
COLOR_PALETTE = {
    "background": "#0A0F1A", "frame_bg": "#101828", "frame_border": "#00E0FF",
    "text": "#E0E0E0", "text_dark_accent": "#A0A8B8", "button": "#007BFF",
    "button_hover": "#00E0FF", "drop_hover": "#1C2A41", "accent_green": "#00FF9C",
    "accent_red": "#FF5A5A", "accent_yellow": "#FFC857", "accent_cyan": "#00E0FF",
    "tab_selected": "#007BFF", "history_card_bg": "#1C2A41",
}
WINDOW_WIDTH = 700; WINDOW_HEIGHT = 750
TYPE_SPEED_MS = 30; PROGRESS_BAR_FILL_INCREMENT_MS = 30
# #################################################################### #
# ##################     END OF CUSTOMIZATION AREA     ################# #
# #################################################################### #

class App(ctk.CTk, TkinterDnD.DnDWrapper):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.TkdndVersion = TkinterDnD._require(self)
        self.title("Kavach - Heuristic Analyzer")
        self.geometry(f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}")
        self.configure(bg=COLOR_PALETTE["background"])
        # State Variables
        self.scan_in_progress = False; self.path_to_scan = None
        self.is_directory_scan = False; self.scan_history = []
        self.chart_canvas = None
        # Main Layout
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(0, weight=1)
        # Tab View
        self.tab_view = ctk.CTkTabview(self, fg_color=COLOR_PALETTE["frame_bg"], segmented_button_selected_color=COLOR_PALETTE["tab_selected"], segmented_button_selected_hover_color=COLOR_PALETTE["button_hover"], segmented_button_unselected_color=COLOR_PALETTE["frame_bg"])
        self.tab_view.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
        self.tab_view.add("Scan"); self.tab_view.add("History & Stats"); self.tab_view.set("Scan")
        # Configure Tab Grids
        self.tab_view.tab("Scan").grid_columnconfigure(0, weight=1); self.tab_view.tab("Scan").grid_rowconfigure(5, weight=1)
        self.tab_view.tab("History & Stats").grid_columnconfigure(0, weight=1, minsize=300); self.tab_view.tab("History & Stats").grid_columnconfigure(1, weight=1, minsize=300); self.tab_view.tab("History & Stats").grid_rowconfigure(1, weight=1)
        # Build Tabs
        self._build_scan_tab()
        self._build_history_tab()
        # Bind Events (Only DnD on drop label)
        self.drop_label.drop_target_register(DND_FILES); self.drop_label.dnd_bind('<<Drop>>', self.handle_file_drop)
        self.drop_label.bind("<Enter>", self.on_drop_hover); self.drop_label.bind("<Leave>", self.on_drop_leave)

    # --- Builds Scan Tab ---
    def _build_scan_tab(self):
        scan_tab = self.tab_view.tab("Scan")
        # Title
        self.title_label = ctk.CTkLabel(scan_tab, text="कवच (Kavach)", font=ctk.CTkFont(size=28, weight="bold"), text_color=COLOR_PALETTE["text"])
        self.title_label.grid(row=0, column=0, pady=(10, 5))
        # Scan Path Label
        self.scan_path_label = ctk.CTkLabel(scan_tab, text="Ready to scan...", font=ctk.CTkFont(size=12), text_color=COLOR_PALETTE["text_dark_accent"])
        self.scan_path_label.grid(row=1, column=0, pady=(0, 15))
        # Drop Zone
        self.drop_label = ctk.CTkLabel(scan_tab, text="Drag & Drop a File or Folder Here", height=100, fg_color=COLOR_PALETTE["background"], corner_radius=10, font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_PALETTE["text"])
        self.drop_label.grid(row=2, column=0, sticky="ew", padx=20, pady=10)
        # Button Frame
        self.button_frame = ctk.CTkFrame(scan_tab, fg_color="transparent")
        self.button_frame.grid(row=3, column=0, pady=10)
        self.button_frame.grid_columnconfigure((0,1), weight=1)
        self.browse_file_button = ctk.CTkButton(self.button_frame, text="Scan File", command=self.browse_file, fg_color=COLOR_PALETTE["button"], hover_color=COLOR_PALETTE["button_hover"], font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_PALETTE["background"])
        self.browse_file_button.grid(row=0, column=0, padx=5, sticky="ew")
        self.browse_folder_button = ctk.CTkButton(self.button_frame, text="Scan Folder", command=self.browse_folder, fg_color=COLOR_PALETTE["button"], hover_color=COLOR_PALETTE["button_hover"], font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_PALETTE["background"])
        self.browse_folder_button.grid(row=0, column=1, padx=5, sticky="ew")

        # --- Progress Bar and Scan Status Label Frame ---
        self.progress_frame = ctk.CTkFrame(scan_tab, fg_color="transparent")
        # This frame will be placed at row=4 by start_scan

        # Progress Bar
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, orientation="horizontal", mode="determinate", progress_color=COLOR_PALETTE["accent_cyan"])
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=0, sticky="ew", padx=(0, 10)) # Add padding to separate

        # --- NEW: Currently Scanning Label ---
        self.currently_scanning_label = ctk.CTkLabel(self.progress_frame, text="", font=ctk.CTkFont(size=11), text_color=COLOR_PALETTE["text_dark_accent"], anchor="w", wraplength=WINDOW_WIDTH - 60) # Adjust wraplength as needed
        self.currently_scanning_label.grid(row=1, column=0, sticky="ew", pady=(5,0))

        # Make progress bar column expand
        self.progress_frame.grid_columnconfigure(0, weight=1)


        # --- Results Dashboard Frame ---
        self.results_dashboard_frame = ctk.CTkFrame(scan_tab, fg_color="transparent")
        self.results_dashboard_frame.grid(row=5, column=0, sticky="nsew", padx=20, pady=(10, 20))
        self.results_dashboard_frame.grid_columnconfigure(0, weight=1); self.results_dashboard_frame.grid_rowconfigure(1, weight=1)
        # Status Card
        self.status_card = ctk.CTkFrame(self.results_dashboard_frame, fg_color=COLOR_PALETTE["background"], corner_radius=10, border_width=0)
        self.status_card.grid(row=0, column=0, sticky="ew"); self.status_card.grid_columnconfigure(1, weight=1)
        self.status_icon = ctk.CTkLabel(self.status_card, text="", font=ctk.CTkFont(size=30, weight="bold")); self.status_icon.grid(row=0, column=0, padx=(20, 10), pady=15)
        self.status_text = ctk.CTkLabel(self.status_card, text="", font=ctk.CTkFont(size=20, weight="bold")); self.status_text.grid(row=0, column=1, padx=10, pady=15, sticky="w")
        # Accordion Frame (Single File)
        self.accordion_frame = ctk.CTkFrame(self.results_dashboard_frame, fg_color="transparent"); self.accordion_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0)); self.accordion_frame.grid_columnconfigure(0, weight=1)
        # Accordion Items...
        self.entropy_button = ctk.CTkButton(self.accordion_frame, text="[+] Entropy Analysis", fg_color=COLOR_PALETTE["background"], hover_color=COLOR_PALETTE["drop_hover"], anchor="w", font=ctk.CTkFont(weight="bold"), command=lambda: self.toggle_accordion(self.entropy_content, self.entropy_button)); self.entropy_button.grid(row=0, column=0, sticky="ew")
        self.entropy_content = ctk.CTkFrame(self.accordion_frame, fg_color=COLOR_PALETTE["background"]); self.entropy_label = ctk.CTkLabel(self.entropy_content, text="", font=ctk.CTkFont(size=13), anchor="w", justify="left"); self.entropy_label.pack(pady=10, padx=20, fill="x")
        self.imports_button = ctk.CTkButton(self.accordion_frame, text="[+] Import Analysis", fg_color=COLOR_PALETTE["background"], hover_color=COLOR_PALETTE["drop_hover"], anchor="w", font=ctk.CTkFont(weight="bold"), command=lambda: self.toggle_accordion(self.imports_content, self.imports_button)); self.imports_button.grid(row=2, column=0, sticky="ew", pady=(5,0))
        self.imports_content = ctk.CTkFrame(self.accordion_frame, fg_color=COLOR_PALETTE["background"]); self.imports_label = ctk.CTkLabel(self.imports_content, text="", font=ctk.CTkFont(size=13), anchor="w", justify="left"); self.imports_label.pack(pady=10, padx=20, fill="x")
        self.header_button = ctk.CTkButton(self.accordion_frame, text="[+] Header Analysis", fg_color=COLOR_PALETTE["background"], hover_color=COLOR_PALETTE["drop_hover"], anchor="w", font=ctk.CTkFont(weight="bold"), command=lambda: self.toggle_accordion(self.header_content, self.header_button)); self.header_button.grid(row=4, column=0, sticky="ew", pady=(5,0))
        self.header_content = ctk.CTkFrame(self.accordion_frame, fg_color=COLOR_PALETTE["background"]); self.header_label = ctk.CTkLabel(self.header_content, text="", font=ctk.CTkFont(size=13), anchor="w", justify="left"); self.header_label.pack(pady=10, padx=20, fill="x")
        # Directory Results Frame (Folder Scan)
        self.dir_results_frame = ctk.CTkFrame(self.results_dashboard_frame, fg_color="transparent"); self.dir_results_frame.grid(row=1, column=0, sticky="nsew", pady=(10, 0)); self.dir_results_frame.grid_columnconfigure(0, weight=1); self.dir_results_frame.grid_rowconfigure(1, weight=1)
        self.dir_results_label = ctk.CTkLabel(self.dir_results_frame, text="", font=ctk.CTkFont(size=14, weight="bold"), text_color=COLOR_PALETTE["accent_red"], anchor="w"); self.dir_results_label.grid(row=0, column=0, sticky="ew")
        self.dir_results_list = ctk.CTkTextbox(self.dir_results_frame, fg_color=COLOR_PALETTE["background"], font=ctk.CTkFont(size=13), state="disabled", wrap="word"); self.dir_results_list.grid(row=1, column=0, sticky="nsew", pady=(5,0))
        self.dir_results_list.tag_config("heading", foreground=COLOR_PALETTE["accent_cyan"]); self.dir_results_list.tag_config("normal", foreground=COLOR_PALETTE["text"]); self.dir_results_list.tag_config("red", foreground=COLOR_PALETTE["accent_red"])
        # Hide results initially
        self.results_dashboard_frame.grid_remove()

    # --- Builds History Tab ---
    def _build_history_tab(self):
        # ... (same as before) ...
        history_tab = self.tab_view.tab("History & Stats")
        history_title = ctk.CTkLabel(history_tab, text="Scan History", font=ctk.CTkFont(size=20, weight="bold"), text_color=COLOR_PALETTE["text"])
        history_title.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        self.history_scroll_frame = ctk.CTkScrollableFrame(history_tab, fg_color=COLOR_PALETTE["background"])
        self.history_scroll_frame.grid(row=1, column=0, sticky="nsew", padx=(20, 10), pady=(0, 20))
        self.history_scroll_frame.grid_columnconfigure(0, weight=1)
        chart_area_frame = ctk.CTkFrame(history_tab, fg_color=COLOR_PALETTE["background"])
        chart_area_frame.grid(row=1, column=1, sticky="nsew", padx=(10, 20), pady=(0, 20))
        chart_area_frame.grid_rowconfigure(1, weight=1); chart_area_frame.grid_columnconfigure(0, weight=1)
        chart_title = ctk.CTkLabel(chart_area_frame, text="Scan Statistics", font=ctk.CTkFont(size=20, weight="bold"), text_color=COLOR_PALETTE["text"])
        chart_title.grid(row=0, column=0, padx=10, pady=(0, 10), sticky="w")
        self.chart_frame = ctk.CTkFrame(chart_area_frame, fg_color=COLOR_PALETTE["history_card_bg"])
        self.chart_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.update_history_tab()

    # --- Micro-interactions & UI Logic ---
    def on_drop_hover(self, event): self.drop_label.configure(fg_color=COLOR_PALETTE["drop_hover"])
    def on_drop_leave(self, event): self.drop_label.configure(fg_color=COLOR_PALETTE["background"])
    def toggle_accordion(self, content_frame, button):
        if content_frame.winfo_viewable(): content_frame.grid_remove(); button.configure(text=button.cget("text").replace("[-]", "[+]"))
        else: content_frame.grid(row=int(button.grid_info()["row"]) + 1, column=0, sticky="ew", padx=10); button.configure(text=button.cget("text").replace("[+]", "[-]"))

    # --- Progress Bar Animation ---
    def animate_progress_fill(self):
        if not self.scan_in_progress: return
        current_val = self.progress_bar.get()
        if current_val < 0.8: increment = 0.02
        elif current_val < 0.95: increment = 0.005
        else:
            self.progress_bar.set(0.95)
            # Use 'after' to ensure UI updates before blocking scan starts
            self.after(50, self.run_the_actual_scan) # Slightly delay the trigger
            return
        new_val = current_val + increment
        self.progress_bar.set(new_val)
        self.after(PROGRESS_BAR_FILL_INCREMENT_MS, self.animate_progress_fill) # Use constant

    # --- NEW: Callback for Scan Progress ---
    def _update_scan_progress_display(self, current_filepath):
        if current_filepath is None: # Scan finished signal
            self.currently_scanning_label.configure(text="Analysis complete...")
        else:
            filename = os.path.basename(current_filepath)
            self.currently_scanning_label.configure(text=f"Scanning: {filename}")
        self.update_idletasks() # Force UI update immediately

    # --- Scan Initiation ---
    def handle_file_drop(self, event): self.start_scan(event.data.strip('{}'))
    def browse_file(self):
        filepath = filedialog.askopenfilename(title="Select File", filetypes=(("Executables", "*.exe;*.dll"), ("All files", "*.*")))
        if filepath: self.start_scan(filepath)
    def browse_folder(self):
        dirpath = filedialog.askdirectory(title="Select Folder")
        if dirpath: self.start_scan(dirpath)

    def start_scan(self, path):
        if self.scan_in_progress: return
        # Reset UI
        self.status_card.configure(border_width=0)
        self.progress_bar.set(0)
        self.drop_label.configure(text="Drag & Drop a File or Folder Here")
        self.scan_path_label.configure(text=f"Scan Target: {path}") # Show target path
        self.results_dashboard_frame.grid_remove()
        self.currently_scanning_label.configure(text="") # Clear previous scan file

        # Start Progress Bar & Status Label Frame
        scan_tab = self.tab_view.tab("Scan")
        self.progress_frame.grid(row=4, column=0, sticky="ew", padx=20, pady=10, in_=scan_tab) # Show frame
        self.scan_in_progress = True
        self.path_to_scan = path
        self.is_directory_scan = os.path.isdir(path)
        self.animate_progress_fill()

    # --- Scan Execution & Result Display ---
    def run_the_actual_scan(self):
        # Call the engine, passing the callback for directory scans
        if self.is_directory_scan:
            results = kavach_engine.scan_directory(self.path_to_scan, progress_callback=self._update_scan_progress_display)
        else:
            # For single file, briefly show "Scanning..." then "Analysis complete..."
            self._update_scan_progress_display(self.path_to_scan)
            results = kavach_engine.run_scan(self.path_to_scan)
            self._update_scan_progress_display(None) # Signal completion

        self.scan_in_progress = False
        self.progress_bar.set(1.0)
        # Hide progress bar and status label slightly later
        self.after(700, lambda: self.progress_frame.grid_forget())
        self.after(700, lambda: self.progress_bar.set(0.0))
        self.after(700, lambda: self.currently_scanning_label.configure(text="")) # Clear label

        self._save_scan_to_history(results)
        if self.is_directory_scan: self._display_directory_results(results)
        else: self._display_file_results(results)

    # --- Save to History ---
    def _save_scan_to_history(self, results):
        # ... (same as before) ...
        entry = { "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  "path": self.path_to_scan, "is_directory": self.is_directory_scan,
                  "results": results }
        self.scan_history.insert(0, entry)
        self.update_history_tab()

    # --- Display Directory Results (with Typing) ---
    def _display_directory_results(self, results):
        # ... (same logic, prepares lines_to_type) ...
        threat_count = len(results["threats_found"]); files_scanned = results["files_scanned"]
        lines_to_type = []
        result_color = COLOR_PALETTE["accent_green"]
        if threat_count == 0:
            self.status_icon.configure(text="✓", text_color=result_color)
            self.status_text.configure(text=f"FOLDER CLEAN ({files_scanned} files scanned)", text_color=result_color)
            self.dir_results_label.configure(text="")
            self.dir_results_list.grid_remove()
        else:
            result_color = COLOR_PALETTE["accent_red"]
            self.status_icon.configure(text="X", text_color=result_color)
            self.status_text.configure(text=f"DANGER: {threat_count} THREAT(S) FOUND", text_color=result_color)
            self.dir_results_label.configure(text=f"Detected Threats ({threat_count}):")
            self.dir_results_list.grid()
            for threat in results["threats_found"]:
                filename = os.path.basename(threat['filepath'])
                lines_to_type.append((f"File: {filename}\n", "heading"))
                e_status, e_data = threat['entropy']
                if e_status == "HIGH": lines_to_type.append((f"   - High Entropy: {e_data}\n", "red"))
                i_status, i_data = threat['imports']
                if i_status == "SUSPICIOUS": lines_to_type.append((f"   - Suspicious Imports ({len(i_data)})\n", "red"))
                h_status, h_data = threat['header']
                if h_status == "SUSPICIOUS": lines_to_type.append((f"   - Header Anomalies ({len(h_data)})\n", "red"))
                lines_to_type.append(("--------------------------------\n", "normal"))

            self.dir_results_list.configure(state="normal"); self.dir_results_list.delete("1.0", "end")
            self.type_out_results(lines_to_type, target_widget=self.dir_results_list)

        self.status_card.configure(border_color=result_color, border_width=2)
        self.results_dashboard_frame.grid()
        self.accordion_frame.grid_remove(); self.dir_results_frame.grid()
        self.update_idletasks()


    # --- Display File Results (Accordion) ---
    def _display_file_results(self, results):
        # ... (same logic as before) ...
        result_color = COLOR_PALETTE["frame_border"]
        if "error" in results:
            result_color = COLOR_PALETTE["accent_red"]
            self.status_icon.configure(text="X", text_color=result_color); self.status_text.configure(text="SCAN FAILED", text_color=result_color)
            self.entropy_button.configure(text="[+] Entropy (Error)"); self.entropy_label.configure(text=results["error"])
            self.imports_button.configure(text="[+] Imports (Error)"); self.imports_label.configure(text=results["error"])
            self.header_button.configure(text="[+] Header (Error)"); self.header_label.configure(text=results["error"])
        else:
            risk = results['risk_score']
            if risk == 0: result_color = COLOR_PALETTE["accent_green"]; self.status_icon.configure(text="✓", text_color=result_color); self.status_text.configure(text="FILE CLEAN", text_color=result_color)
            elif risk <= 2: result_color = COLOR_PALETTE["accent_yellow"]; self.status_icon.configure(text="!", text_color=result_color); self.status_text.configure(text="SUSPICIOUS FILE", text_color=result_color)
            else: result_color = COLOR_PALETTE["accent_red"]; self.status_icon.configure(text="X", text_color=result_color); self.status_text.configure(text="HIGH DANGER", text_color=result_color)

            entropy_status, entropy_data = results['entropy']; self.entropy_label.configure(text=f"   {entropy_data}"); self.entropy_button.configure(text=f"[+] Entropy ({entropy_status})", text_color=COLOR_PALETTE["accent_red"] if entropy_status == "HIGH" else COLOR_PALETTE["text"])
            import_status, import_data = results['imports']; data_str = "\n   • ".join(import_data) if isinstance(import_data, list) else f"   {import_data}"; self.imports_label.configure(text=data_str); self.imports_button.configure(text=f"[+] Imports ({import_status})", text_color=COLOR_PALETTE["accent_red"] if import_status == "SUSPICIOUS" else COLOR_PALETTE["text"])
            header_status, header_data = results['header']; data_str = "\n   • ".join(header_data) if isinstance(header_data, list) else f"   {header_data}"; self.header_label.configure(text=data_str); self.header_button.configure(text=f"[+] Header ({header_status})", text_color=COLOR_PALETTE["accent_red"] if header_status == "SUSPICIOUS" else COLOR_PALETTE["text"])
            for btn, content in [(self.entropy_button, self.entropy_content), (self.imports_button, self.imports_content), (self.header_button, self.header_content)]:
                 btn.configure(text=btn.cget("text").replace("[-]", "[+]")); content.grid_remove()

        self.status_card.configure(border_color=result_color, border_width=2)
        self.results_dashboard_frame.grid()
        self.accordion_frame.grid(); self.dir_results_frame.grid_remove()
        self.update_idletasks()

    # --- Typing Animation ---
    def type_out_results(self, lines, line_index=0, target_widget=None):
        # ... (same as before) ...
        if target_widget is None: print("Error: type_out_results needs a target_widget!"); return
        if line_index < len(lines):
            text, tag = lines[line_index]
            target_widget.insert("end", text, tag)
            target_widget.see("end")
            self.after(TYPE_SPEED_MS, self.type_out_results, lines, line_index + 1, target_widget)
        else:
            if isinstance(target_widget, ctk.CTkTextbox): target_widget.configure(state="disabled")

    # --- Update History Tab (List + Chart) ---
    def update_history_tab(self):
        # ... (same as before) ...
        for widget in self.history_scroll_frame.winfo_children(): widget.destroy()
        if not self.scan_history:
            ctk.CTkLabel(self.history_scroll_frame, text="No scans performed yet.", font=ctk.CTkFont(size=14), text_color=COLOR_PALETTE["text"]).grid(row=0, column=0, padx=10, pady=10)
        else:
            for i, entry in enumerate(self.scan_history):
                card = ctk.CTkFrame(self.history_scroll_frame, fg_color=COLOR_PALETTE["history_card_bg"], corner_radius=10)
                card.grid(row=i, column=0, sticky="ew", padx=10, pady=5); card.grid_columnconfigure(1, weight=1)
                status_text = "Error"; status_color = COLOR_PALETTE["accent_yellow"]; threat_count = 0
                if entry["is_directory"]:
                     if "threats_found" in entry["results"]:
                        threat_count = len(entry["results"]["threats_found"])
                        if threat_count == 0: status_text = "Clean (Folder)"; status_color = COLOR_PALETTE["accent_green"]
                        else: status_text = f"{threat_count} Threat(s) (Folder)"; status_color = COLOR_PALETTE["accent_red"]
                     else: status_text = "Scan Error (Folder)"; status_color = COLOR_PALETTE["accent_red"]
                else: # File scan
                    if "error" in entry["results"]: status_text = "Scan Error (File)"; status_color = COLOR_PALETTE["accent_red"]
                    elif entry["results"]["risk_score"] == 0: status_text = "Clean (File)"; status_color = COLOR_PALETTE["accent_green"]
                    elif entry["results"]["risk_score"] <= 2: status_text = "Suspicious (File)"; status_color = COLOR_PALETTE["accent_yellow"]
                    else: status_text = "Danger (File)"; status_color = COLOR_PALETTE["accent_red"]
                ctk.CTkLabel(card, text=status_text, text_color=status_color, font=ctk.CTkFont(weight="bold")).grid(row=0, column=0, padx=15, pady=(10,5), sticky="w")
                ctk.CTkLabel(card, text=entry["path"], text_color=COLOR_PALETTE["text"], font=ctk.CTkFont(size=12), wraplength=400).grid(row=1, column=0, columnspan=2, padx=15, pady=(0,5), sticky="w")
                ctk.CTkLabel(card, text=entry["timestamp"], text_color=COLOR_PALETTE["text_dark_accent"], font=ctk.CTkFont(size=10)).grid(row=2, column=1, padx=15, pady=(0,10), sticky="e")
        self._update_chart()

    # --- Update Chart Function ---
    def _update_chart(self):
        # ... (same chart logic as before) ...
        if self.chart_canvas: self.chart_canvas.get_tk_widget().destroy(); self.chart_canvas = None
        for widget in self.chart_frame.winfo_children(): widget.destroy()
        if not self.scan_history:
             ctk.CTkLabel(self.chart_frame, text="No scan data for chart.", text_color=COLOR_PALETTE["text_dark_accent"]).grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
             self.chart_frame.grid_rowconfigure(0, weight=1); self.chart_frame.grid_columnconfigure(0, weight=1)
             return

        counts = {"Clean": 0, "Suspicious": 0, "Danger": 0, "Error": 0}
        for entry in self.scan_history:
            if entry["is_directory"]:
                 if "threats_found" in entry["results"]:
                    threat_count = len(entry["results"]["threats_found"])
                    if threat_count == 0: counts["Clean"] += 1
                    else: counts["Danger"] += 1
                 else: counts["Error"] += 1
            else: # File scan
                if "error" in entry["results"]: counts["Error"] += 1
                elif entry["results"]["risk_score"] == 0: counts["Clean"] += 1
                elif entry["results"]["risk_score"] <= 2: counts["Suspicious"] += 1
                else: counts["Danger"] += 1

        labels = []; sizes = []; colors = []
        if counts["Clean"] > 0: labels.append("Clean"); sizes.append(counts["Clean"]); colors.append(COLOR_PALETTE["accent_green"])
        if counts["Suspicious"] > 0: labels.append("Suspicious"); sizes.append(counts["Suspicious"]); colors.append(COLOR_PALETTE["accent_yellow"])
        if counts["Danger"] > 0: labels.append("Danger"); sizes.append(counts["Danger"]); colors.append(COLOR_PALETTE["accent_red"])
        if counts["Error"] > 0: labels.append("Errors"); sizes.append(counts["Error"]); colors.append(COLOR_PALETTE["text_dark_accent"])

        if not sizes:
             ctk.CTkLabel(self.chart_frame, text="Not enough data for chart.", text_color=COLOR_PALETTE["text_dark_accent"]).grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
             self.chart_frame.grid_rowconfigure(0, weight=1); self.chart_frame.grid_columnconfigure(0, weight=1)
             return

        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(4, 4), facecolor=COLOR_PALETTE["history_card_bg"])
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors,
               wedgeprops={'edgecolor': COLOR_PALETTE["background"], 'linewidth': 1},
               textprops={'color': COLOR_PALETTE["text"]})
        ax.axis('equal')
        fig.patch.set_alpha(0.0)
        ax.set_facecolor(COLOR_PALETTE["history_card_bg"])

        self.chart_canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        self.chart_canvas.draw()
        chart_widget = self.chart_canvas.get_tk_widget()
        chart_widget.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.chart_frame.grid_rowconfigure(0, weight=1); self.chart_frame.grid_columnconfigure(0, weight=1)


# --- Entry Point ---
if __name__ == "__main__":
    app = App()
    app.mainloop()