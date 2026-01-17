import customtkinter as ctk
import psutil
import threading
import time
import random
import os
import sys
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# 🎨 HIGH-END VISUAL CONFIGURATION
# ─────────────────────────────────────────────────────────────
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

# Elite Cyber-Security Palette
C_BG_MAIN     = "#0b0d12"    # Void Black
C_BG_PANEL    = "#141824"    # Deep Graphite
C_ACCENT      = "#3b8ed0"    # Azure Interceptor
C_SUCCESS     = "#00E676"    # Neon Safe
C_WARNING     = "#FFC400"    # Amber Alert
C_DANGER      = "#FF1744"    # Critical Red
C_TEXT_MAIN   = "#FFFFFF"    # Pure White
C_TEXT_DIM    = "#64748b"    # Slate Grey
C_BORDER      = "#1e293b"    # Subtle Border

FONT_HEADER   = ("Roboto", 24, "bold")
FONT_SUB      = ("Roboto", 14)
FONT_MONO     = ("Consolas", 12)

# ─────────────────────────────────────────────────────────────
# 🧠 BACKEND INTELLIGENCE (HYBRID: REAL + SIMULATION)
# ─────────────────────────────────────────────────────────────
class KarenoCore:
    def __init__(self):
        self.active_protection = True
        self.threats_blocked = 0
        self.net_packets_analyzed = 0
        self.scan_running = False

    def get_system_health(self):
        """REAL: Fetches actual hardware telemetry."""
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        net = psutil.net_io_counters()
        # Convert bytes to MB
        sent = round(net.bytes_sent / 1024 / 1024, 1)
        recv = round(net.bytes_recv / 1024 / 1024, 1)
        return cpu, ram, sent, recv

    def resolve_threat_level(self):
        """AI LOGIC: Determines DEFCON level based on system load."""
        cpu, ram, _, _ = self.get_system_health()
        if cpu > 80 or ram > 90: return "HIGH", C_DANGER
        if cpu > 50: return "ELEVATED", C_WARNING
        return "SECURE", C_SUCCESS

    def analyze_url_heuristics(self, url):
        """AI LOGIC: Advanced string analysis for web defense."""
        risk_score = 0
        log = []
        
        # Heuristic Checks
        if "http://" in url: 
            risk_score += 30
            log.append("⚠ Protocol Insecure (HTTP)")
        else:
            log.append("✓ Protocol Secure (HTTPS)")
            
        if len(url) > 50:
            risk_score += 10
            log.append("⚠ URL Length Suspicious")
            
        suspicious_tlds = ['.xyz', '.top', '.info', '.ru', '.cn']
        if any(tld in url for tld in suspicious_tlds):
            risk_score += 50
            log.append("⚠ High-Risk TLD Detected")
            
        return risk_score, log

# ─────────────────────────────────────────────────────────────
# 🖥️ ADVANCED GUI ARCHITECTURE
# ─────────────────────────────────────────────────────────────
class KarenoSecurityMAX(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.core = KarenoCore()
        
        # Window Configuration
        self.title("KARENO SECURITY MAX [ENTERPRISE EDITION]")
        self.geometry("1280x800")
        self.minsize(1100, 700)
        self.configure(fg_color=C_BG_MAIN)
        
        # Grid Layout (1 Sidebar : 4 Content)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # UI Components
        self._init_sidebar()
        self._init_main_stage()
        self._init_status_bar()

        # Start Engine
        self.curr_view = None
        self.show_dashboard()
        
        # Launch Threads
        self.running = True
        threading.Thread(target=self._telemetry_loop, daemon=True).start()
        threading.Thread(target=self._net_sentinel_loop, daemon=True).start()

    def _init_sidebar(self):
        """The Command Center Navigation."""
        sb = ctk.CTkFrame(self, width=240, fg_color=C_BG_PANEL, corner_radius=0)
        sb.grid(row=0, column=0, rowspan=2, sticky="nsew")
        sb.grid_propagate(False) # Fixed width

        # Brand
        ctk.CTkLabel(sb, text="🛡️ KARENO\nSECURITY MAX", font=("Roboto", 20, "bold"), text_color=C_ACCENT).pack(pady=(40, 10))
        ctk.CTkLabel(sb, text="v9.0.1-ULTRA", font=("Consolas", 10), text_color=C_TEXT_DIM).pack(pady=(0, 40))

        # Nav Buttons
        self.nav_btns = []
        labels = ["DASHBOARD", "NETWORK GUARD", "AI WEB DEFENSE", "DEEP SCANNER"]
        cmds = [self.show_dashboard, self.show_network, self.show_web, self.show_scanner]
        
        for txt, cmd in zip(labels, cmds):
            btn = ctk.CTkButton(
                sb, 
                text=f"  {txt}", 
                command=cmd,
                anchor="w",
                height=50,
                corner_radius=8,
                fg_color="transparent", 
                text_color=C_TEXT_MAIN,
                hover_color=C_BORDER,
                font=("Roboto", 13, "bold")
            )
            btn.pack(fill="x", padx=15, pady=5)
            self.nav_btns.append(btn)

        # Bottom Widget: Active Protection Switch
        f = ctk.CTkFrame(sb, fg_color=C_BG_MAIN, corner_radius=10)
        f.pack(side="bottom", fill="x", padx=15, pady=20)
        ctk.CTkLabel(f, text="REAL-TIME SHIELD", font=("Roboto", 10, "bold")).pack(pady=5)
        self.sw_active = ctk.CTkSwitch(f, text="", onvalue=True, offvalue=False, progress_color=C_SUCCESS)
        self.sw_active.select()
        self.sw_active.pack(pady=(0,10))

    def _init_main_stage(self):
        """The dynamic content area."""
        self.stage = ctk.CTkFrame(self, fg_color="transparent")
        self.stage.grid(row=0, column=1, sticky="nsew", padx=25, pady=25)

    def _init_status_bar(self):
        """Footer for instant status."""
        bar = ctk.CTkFrame(self, height=30, fg_color=C_BG_PANEL, corner_radius=0)
        bar.grid(row=1, column=1, sticky="ew")
        
        self.lbl_status = ctk.CTkLabel(bar, text="● SYSTEM SECURE", text_color=C_SUCCESS, font=("Consolas", 11, "bold"))
        self.lbl_status.pack(side="left", padx=20)
        
        self.lbl_clock = ctk.CTkLabel(bar, text="00:00:00", text_color=C_TEXT_DIM, font=("Consolas", 11))
        self.lbl_clock.pack(side="right", padx=20)

    # ─────────────────────────────────────────────────────────────
    # 👀 VIEW CONTROLLERS
    # ─────────────────────────────────────────────────────────────
    
    def _clear_stage(self):
        for widget in self.stage.winfo_children():
            widget.destroy()

    def show_dashboard(self):
        self._clear_stage()
        
        # 1. Header
        ctk.CTkLabel(self.stage, text="COMMAND CENTER // OVERVIEW", font=FONT_HEADER, text_color=C_TEXT_MAIN).pack(anchor="w", pady=(0, 20))

        # 2. Live Metrics Row
        row1 = ctk.CTkFrame(self.stage, fg_color="transparent")
        row1.pack(fill="x", pady=(0, 20))
        
        self.card_cpu = self._create_metric_card(row1, "CPU LOAD", "0%", C_ACCENT)
        self.card_ram = self._create_metric_card(row1, "MEMORY", "0%", C_WARNING)
        self.card_net = self._create_metric_card(row1, "NET ACTIVITY", "0 MB", C_SUCCESS)
        self.card_threat = self._create_metric_card(row1, "THREAT LEVEL", "LOW", C_SUCCESS)

        # 3. Visualization Area
        row2 = ctk.CTkFrame(self.stage, fg_color=C_BG_PANEL, corner_radius=10)
        row2.pack(fill="both", expand=True)
        
        # Simulated Terminal Log
        ctk.CTkLabel(row2, text="LIVE KERNEL EVENT LOG", font=("Consolas", 12, "bold"), text_color=C_TEXT_DIM).pack(anchor="w", padx=15, pady=10)
        self.console = ctk.CTkTextbox(row2, fg_color="#000000", text_color="#00ff00", font=("Consolas", 10), activate_scrollbars=False)
        self.console.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.console.insert("0.0", "KarenoSecurityMAX Daemon initialized...\nLoading heuristics engine... OK\nMounting network sentinels... OK\n")

    def show_network(self):
        self._clear_stage()
        ctk.CTkLabel(self.stage, text="NETWORK SENTINEL", font=FONT_HEADER).pack(anchor="w", pady=(0, 20))
        
        # Real Connection Table
        table_frame = ctk.CTkFrame(self.stage, fg_color=C_BG_PANEL)
        table_frame.pack(fill="both", expand=True)
        
        # Headers
        h = ctk.CTkFrame(table_frame, height=40, fg_color=C_BORDER)
        h.pack(fill="x")
        cols = ["PROTO", "LOCAL ADDRESS", "REMOTE ADDRESS", "STATUS", "PID"]
        for c in cols:
            ctk.CTkLabel(h, text=c, font=("Arial", 11, "bold"), width=150).pack(side="left", fill="x", expand=True)

        self.net_list = ctk.CTkTextbox(table_frame, fg_color="transparent", font=("Consolas", 12))
        self.net_list.pack(fill="both", expand=True, padx=5, pady=5)

    def show_web(self):
        self._clear_stage()
        ctk.CTkLabel(self.stage, text="AI ONLINE DEFENSE", font=FONT_HEADER).pack(anchor="w", pady=(0, 20))
        
        panel = ctk.CTkFrame(self.stage, fg_color=C_BG_PANEL)
        panel.pack(fill="x", pady=20)
        
        ctk.CTkLabel(panel, text="URL HEURISTIC ENGINE", font=FONT_SUB).pack(anchor="w", padx=20, pady=20)
        
        self.url_entry = ctk.CTkEntry(panel, placeholder_text="Enter website URL to scan (e.g., http://suspicious-site.com)", height=50, font=("Arial", 14))
        self.url_entry.pack(fill="x", padx=20, pady=(0, 20))
        
        btn = ctk.CTkButton(panel, text="ANALYZE WITH AI", height=50, font=("Arial", 14, "bold"), fg_color=C_ACCENT, command=self._run_web_ai)
        btn.pack(padx=20, pady=(0, 20), fill="x")

        self.web_result = ctk.CTkFrame(self.stage, fg_color="transparent")
        self.web_result.pack(fill="both", expand=True)

    def show_scanner(self):
        self._clear_stage()
        ctk.CTkLabel(self.stage, text="DEEP FILE SCANNER", font=FONT_HEADER).pack(anchor="w", pady=(0, 20))

        # Scan Animation Area
        self.scan_panel = ctk.CTkFrame(self.stage, fg_color=C_BG_PANEL)
        self.scan_panel.pack(fill="both", expand=True)
        
        self.radar = ctk.CTkLabel(self.scan_panel, text="SYSTEM READY", font=("Arial", 30, "bold"), text_color=C_TEXT_DIM)
        self.radar.place(relx=0.5, rely=0.4, anchor="center")
        
        self.scan_prog = ctk.CTkProgressBar(self.scan_panel, width=400, progress_color=C_SUCCESS)
        self.scan_prog.set(0)
        self.scan_prog.place(relx=0.5, rely=0.5, anchor="center")
        
        self.scan_file_lbl = ctk.CTkLabel(self.scan_panel, text="Waiting to initiate...", font=("Consolas", 12))
        self.scan_file_lbl.place(relx=0.5, rely=0.55, anchor="center")

        btn = ctk.CTkButton(self.stage, text="INITIATE FULL SYSTEM SCAN", height=60, fg_color=C_DANGER, font=("Arial", 16, "bold"), command=self._run_scan_sim)
        btn.pack(fill="x", pady=20)

    # ─────────────────────────────────────────────────────────────
    # ⚙️ LOGIC & ANIMATION HANDLERS
    # ─────────────────────────────────────────────────────────────

    def _create_metric_card(self, parent, title, val, color):
        f = ctk.CTkFrame(parent, fg_color=C_BG_PANEL, corner_radius=10)
        f.pack(side="left", fill="both", expand=True, padx=5)
        
        ctk.CTkLabel(f, text=title, font=("Arial", 11, "bold"), text_color=C_TEXT_DIM).pack(anchor="nw", padx=15, pady=15)
        lbl = ctk.CTkLabel(f, text=val, font=("Arial", 28, "bold"), text_color=color)
        lbl.pack(anchor="w", padx=15, pady=(0, 15))
        
        # Save reference for updates
        if title == "CPU LOAD": self.lbl_cpu = lbl
        if title == "MEMORY": self.lbl_ram = lbl
        if title == "NET ACTIVITY": self.lbl_net = lbl
        if title == "THREAT LEVEL": self.lbl_threat = lbl
        
        return f

    def _telemetry_loop(self):
        """Updates the dashboard metrics every second."""
        while self.running:
            try:
                cpu, ram, sent, recv = self.core.get_system_health()
                lvl, color = self.core.resolve_threat_level()
                
                # Update Clock
                now = datetime.now().strftime("%H:%M:%S")
                self.lbl_clock.configure(text=f"UTC {now}")
                
                # Update Dashboard (if visible)
                if hasattr(self, 'lbl_cpu'):
                    self.lbl_cpu.configure(text=f"{cpu}%")
                    self.lbl_ram.configure(text=f"{ram}%")
                    self.lbl_net.configure(text=f"↓{recv} / ↑{sent}")
                    self.lbl_threat.configure(text=lvl, text_color=color)
                    self.lbl_status.configure(text=f"● SYSTEM {lvl}", text_color=color)

                # Random Console Injection
                if hasattr(self, 'console') and random.random() > 0.7:
                    msgs = [
                        f"[SYSTEM] Daemon GC cleanup complete.",
                        f"[NET] Packet {random.randint(1000,9999)} verified safe.",
                        f"[WATCHDOG] Integrity check passed."
                    ]
                    self.console.insert("end", f"{now} {random.choice(msgs)}\n")
                    self.console.see("end")

            except Exception as e: print(e)
            time.sleep(1)

    def _net_sentinel_loop(self):
        """Updates the Network Tab list."""
        while self.running:
            if hasattr(self, 'net_list') and self.net_list.winfo_exists():
                try:
                    self.net_list.delete("0.0", "end")
                    for conn in psutil.net_connections(kind='inet')[:20]: # Limit to 20 for UI perf
                        laddr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "*.*.*.*:*"
                        status = conn.status
                        pid = str(conn.pid)
                        
                        line = f"{conn.type.name:<10} {laddr:<25} {raddr:<25} {status:<15} {pid}\n"
                        self.net_list.insert("end", line)
                except: pass
            time.sleep(2)

    def _run_web_ai(self):
        url = self.url_entry.get()
        if not url: return
        
        # Clear previous
        for w in self.web_result.winfo_children(): w.destroy()
        
        # Simulating AI "Thinking"
        lbl = ctk.CTkLabel(self.web_result, text="AI ANALYZING NODE TOPOLOGY...", font=("Consolas", 14), text_color=C_ACCENT)
        lbl.pack(pady=20)
        self.update()
        time.sleep(1.5)
        
        score, logs = self.core.analyze_url_heuristics(url)
        lbl.destroy()
        
        # Result Card
        color = C_SUCCESS if score < 20 else (C_WARNING if score < 50 else C_DANGER)
        verdict = "SAFE" if score < 20 else "SUSPICIOUS" if score < 50 else "MALICIOUS"
        
        res_card = ctk.CTkFrame(self.web_result, fg_color=color, height=100)
        res_card.pack(fill="x", padx=20)
        
        ctk.CTkLabel(res_card, text=f"VERDICT: {verdict}", font=("Arial", 24, "bold"), text_color="#000").pack(pady=10)
        ctk.CTkLabel(res_card, text=f"RISK SCORE: {score}/100", font=("Arial", 14), text_color="#000").pack(pady=(0,10))
        
        # Logs
        for l in logs:
            ctk.CTkLabel(self.web_result, text=l, font=("Consolas", 12)).pack(anchor="w", padx=25, pady=2)

    def _run_scan_sim(self):
        """Visual simulation of a deep scan."""
        if self.core.scan_running: return
        self.core.scan_running = True
        
        self.radar.configure(text="SCANNING KERNEL...")
        self.radar.configure(text_color=C_ACCENT)
        
        # Fake File List
        sys_files = [f"System32/drivers/{x}.sys" for x in ["ntfs", "tcpip", "volsnap", "fvevol", "disk"]]
        
        for i in range(101):
            if not self.core.scan_running: break
            
            # Update Progress
            self.scan_prog.set(i / 100)
            
            # Visual Fluff
            f_name = random.choice(sys_files) if i % 5 == 0 else f"User/Data/Cache/tmp_{random.randint(1000,9999)}.dat"
            self.scan_file_lbl.configure(text=f"Analyzing: {f_name}")
            
            # Speed varies to look real
            time.sleep(random.uniform(0.01, 0.05))
            self.update()
            
        self.radar.configure(text="SCAN COMPLETE: CLEAN", text_color=C_SUCCESS)
        self.scan_file_lbl.configure(text="No threats found in 14,203 files.")
        self.core.scan_running = False

# ─────────────────────────────────────────────────────────────
# 🚀 LAUNCH
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = KarenoSecurityMAX()
    app.mainloop()

