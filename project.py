import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import hashlib
import requests
import threading
import queue
import time
import pyshark
import os
import re
import json
import urllib.parse
from datetime import datetime

class PasswordCrackerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Password Cracker")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f0f0")  # Changed to light gray background
        
        # Initialize variables
        self.running = False
        self.paused = False
        self.results_queue = queue.Queue()
        self.log_queue = queue.Queue()
        self.current_task = None
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use a theme that supports light colors
        
        # Configure ttk styles
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", foreground="#000000")
        self.style.configure("TButton", padding=5)
        
        # Create main notebook (tabbed interface)
        self.notebook = ttk.Notebook(root, style="TNotebook")
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs with light theme
        self.hash_tab = ttk.Frame(self.notebook, style="TFrame")
        self.web_tab = ttk.Frame(self.notebook, style="TFrame")
        self.wifi_tab = ttk.Frame(self.notebook, style="TFrame")
        self.ntlm_tab = ttk.Frame(self.notebook, style="TFrame")
        self.rainbow_tab = ttk.Frame(self.notebook, style="TFrame")
        self.settings_tab = ttk.Frame(self.notebook, style="TFrame")
        
        self.notebook.add(self.hash_tab, text="Hash Cracker")
        self.notebook.add(self.web_tab, text="Web Bruteforcer")
        self.notebook.add(self.wifi_tab, text="WiFi Cracker")
        self.notebook.add(self.ntlm_tab, text="NTLM Cracker")
        self.notebook.add(self.rainbow_tab, text="Rainbow Table Cracker")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Setup each tab
        self.setup_hash_tab()
        self.setup_web_tab()
        self.setup_wifi_tab()
        self.setup_ntlm_tab()
        self.setup_rainbow_tab()
        self.setup_settings_tab()
        
        # Create status bar
        self.status_frame = tk.Frame(root, bg="#f5f5f5", height=30)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(self.status_frame, text="Ready", bg="#f5f5f5", fg="black", anchor="w")
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.progress = ttk.Progressbar(self.status_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(side=tk.RIGHT, padx=10)
        
        # Create log window
        self.setup_log_window()
        
        # Start log monitoring
        self.monitor_logs()

        self.update_results_loop()

        # Add this line in the __init__ method after creating other tabs (around line 55)
        self.project_info_tab = ttk.Frame(self.notebook, style="TFrame")

# Add this line after adding other tabs to the notebook (around line 62)
        self.notebook.add(self.project_info_tab, text="Project Info")

# Add this line in the setup calls section (around line 70)
        self.setup_project_info_tab()

# Add this complete method to the class (can be placed after setup_settings_tab method)
    def setup_project_info_tab(self):
        """Setup the project info tab"""
        frame = tk.Frame(self.project_info_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
    
    # Main container with padding
        main_container = tk.Frame(frame, bg="#f5f5f5")
        main_container.pack(fill=tk.BOTH, expand=True)
    
    # Project Overview Section
        project_frame = tk.LabelFrame(main_container, text="Project Overview", bg="#f5f5f5", fg="black", 
                                 font=("Arial", 12, "bold"))
        project_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Project details
        details = [
            ("Project Name:", "Advanced Password Cracker"),
            ("Description:", "A powerful and user-friendly password security analysis tool designed for\nsecurity professionals, penetration testers, and cybersecurity students.\nThis toolkit provides multiple password cracking techniques through an\nintuitive graphical interface."),
            ("Project Start Date:", "21/06/2025"),
            ("Project End Date:", "08/08/2025")
        ]
    
        for i, (label, value) in enumerate(details):
            tk.Label(project_frame, text=label, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10, "bold")).grid(row=i, column=0, sticky="nw", padx=10, pady=5)
            tk.Label(project_frame, text=value, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10), wraplength=400, justify="left").grid(row=i, column=1, sticky="nw", padx=10, pady=5)
    
    # Developer Details Section
        dev_frame = tk.LabelFrame(main_container, text="Developer Details", bg="#f5f5f5", fg="black",
                                 font=("Arial", 12, "bold"))
        dev_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Create table headers
        tk.Label(dev_frame, text="Name", bg="#f5f5f5", fg="black", 
                font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", padx=10, pady=5)
        tk.Label(dev_frame, text="Employee ID", bg="#f5f5f5", fg="black", 
                font=("Arial", 10, "bold")).grid(row=0, column=1, sticky="w", padx=10, pady=5)
    
    # Developer data
        developers = [
            ("Mourya Birru", "ST#IS#7414"),
            ("Minnekanti Sai Sree Harsha", "ST#IS#7439"),
            ("Pasupurathi Sandeep Kumar Reddy", "ST#IS#7450")
        ]
    
        for i, (name, emp_id) in enumerate(developers, 1):
            tk.Label(dev_frame, text=name, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10)).grid(row=i, column=0, sticky="w", padx=10, pady=2)
            tk.Label(dev_frame, text=emp_id, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10)).grid(row=i, column=1, sticky="w", padx=10, pady=2)
    
    # Company Details Section
        company_frame = tk.LabelFrame(main_container, text="Company Details", bg="#f5f5f5", fg="black",
                                 font=("Arial", 12, "bold"))
        company_frame.pack(fill=tk.X, pady=(0, 15))
    
    # Company details
        company_details = [
            ("Company Name:", "Supraja Technologies"),
            ("Email:", "contact@suprajatechnologies.com"),
            ("Contact:", "+91 9550055338"),
            ("Address:", "D.NO: 11-9-18, 1st Floor,\nMajjivari Street, Kothapeta,\nVijayawada - 520001")
        ]
    
        for i, (label, value) in enumerate(company_details):
            tk.Label(company_frame, text=label, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10, "bold")).grid(row=i, column=0, sticky="nw", padx=10, pady=5)
            tk.Label(company_frame, text=value, bg="#f5f5f5", fg="black", 
                    font=("Arial", 10), justify="left").grid(row=i, column=1, sticky="nw", padx=10, pady=5)
    
    # Configure grid weights for proper alignment
        project_frame.columnconfigure(1, weight=1)
        dev_frame.columnconfigure(1, weight=1)
        company_frame.columnconfigure(1, weight=1)

    def update_results_loop(self):
        self.update_results()
        self.root.after(100, self.update_results_loop)
    
    
    def setup_hash_tab(self):
        """Setup the hash cracking tab"""
        frame = tk.Frame(self.hash_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main frame for inputs and results
        main_frame = tk.Frame(frame, bg="#f5f5f5")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # File selection
        tk.Label(main_frame, text="Hash File:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5)
        self.hash_file_entry = tk.Entry(main_frame, width=60)
        self.hash_file_entry.grid(row=0, column=1, sticky="ew", pady=5, columnspan=2)
        tk.Button(main_frame, text="Browse", command=lambda: self.browse_file(self.hash_file_entry)).grid(row=0, column=3, padx=5)
        
        # Wordlist selection
        tk.Label(main_frame, text="Wordlist:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5)
        self.wordlist_entry = tk.Entry(main_frame, width=60)
        self.wordlist_entry.grid(row=1, column=1, sticky="ew", pady=5, columnspan=2)
        tk.Button(main_frame, text="Browse", command=lambda: self.browse_file(self.wordlist_entry)).grid(row=1, column=3, padx=5)
        
        # Hash type selection
        tk.Label(main_frame, text="Hash Type:", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=5)
        self.hash_type = tk.StringVar(value="md5")
        hash_types = ["md5", "sha1", "sha256", "ntlm", "bcrypt", "sha512"]
        hash_dropdown = ttk.Combobox(main_frame, textvariable=self.hash_type, values=hash_types, state="readonly")
        hash_dropdown.grid(row=2, column=1, sticky="w", pady=5, columnspan=2)
        
        # Brute force options
        brute_frame = tk.LabelFrame(main_frame, text="Brute Force Options", bg="#f5f5f5", fg="black")
        brute_frame.grid(row=3, column=0, columnspan=4, sticky="ew", pady=5, padx=5)
        
        tk.Label(brute_frame, text="Min Length:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=2)
        self.min_length = tk.Spinbox(brute_frame, from_=1, to=10, width=5)
        self.min_length.grid(row=0, column=1, sticky="w", pady=2, padx=5)
        
        tk.Label(brute_frame, text="Max Length:", bg="#f5f5f5", fg="black").grid(row=0, column=2, sticky="w", pady=2)
        self.max_length = tk.Spinbox(brute_frame, from_=1, to=10, width=5)
        self.max_length.grid(row=0, column=3, sticky="w", pady=2, padx=5)
        
        tk.Label(brute_frame, text="Characters:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=2)
        self.chars = tk.Entry(brute_frame, width=60)
        self.chars.insert(0, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        self.chars.grid(row=1, column=1, columnspan=3, sticky="ew", pady=2, padx=5)
        
        # Results section
        tk.Label(main_frame, text="Results:", bg="#f5f5f5", fg="black").grid(row=4, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.hash_results = scrolledtext.ScrolledText(main_frame, width=80, height=15)
        self.hash_results.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=5)
        
        # Progress bar
        self.hash_progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.hash_progress.grid(row=6, column=0, columnspan=4, sticky="ew", pady=5)
        
        # Control buttons
        control_frame = tk.Frame(main_frame, bg="#f5f5f5")
        control_frame.grid(row=7, column=0, columnspan=4, pady=10)
        
        tk.Button(control_frame, text="Start", command=self.start_hash_cracking, width=12).grid(row=0, column=0, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_cracking, width=12).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="Stop", command=self.stop_cracking, width=12).grid(row=0, column=2, padx=5)
        tk.Button(control_frame, text="Export", command=self.export_results, width=12).grid(row=0, column=3, padx=5)
        
        # Configure grid weights
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(5, weight=1)
    
    def setup_web_tab(self):
        """Setup the web bruteforcing tab"""
        frame = tk.Frame(self.web_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - inputs
        left_frame = tk.Frame(frame, bg="#f5f5f5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # URL input
        tk.Label(left_frame, text="Target URL:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5)
        self.url_entry = tk.Entry(left_frame, width=40)
        self.url_entry.grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)
        self.url_entry.insert(0, "http://example.com/login")
        
        # Username input
        tk.Label(left_frame, text="Username:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(left_frame, width=40)
        self.username_entry.grid(row=1, column=1, columnspan=2, sticky="ew", pady=5)
        self.username_entry.insert(0, "admin")
        
        # Wordlist selection
        tk.Label(left_frame, text="Wordlist:", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=5)
        self.web_wordlist_entry = tk.Entry(left_frame, width=40)
        self.web_wordlist_entry.grid(row=2, column=1, sticky="ew", pady=5)
        tk.Button(left_frame, text="Browse", command=lambda: self.browse_file(self.web_wordlist_entry)).grid(row=2, column=2, padx=5)
        
        # Form parameters
        tk.Label(left_frame, text="Form Parameters:", bg="#f5f5f5", fg="black").grid(row=3, column=0, sticky="w", pady=5)
        self.form_params = tk.Text(left_frame, width=30, height=5)
        self.form_params.grid(row=3, column=1, columnspan=2, sticky="ew", pady=5)
        self.form_params.insert("1.0", "username=admin&password=PASSWORD")
        
        # Request settings
        req_frame = tk.LabelFrame(left_frame, text="Request Settings", bg="#f5f5f5", fg="black")
        req_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=5, padx=5)
        
        tk.Label(req_frame, text="Timeout (s):", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=2)
        self.timeout = tk.Spinbox(req_frame, from_=1, to=60, width=5)
        self.timeout.grid(row=0, column=1, sticky="w", pady=2)
        self.timeout.insert(0, "10")
        
        tk.Label(req_frame, text="Delay (s):", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=2)
        self.delay = tk.Spinbox(req_frame, from_=0, to=10, width=5)
        self.delay.grid(row=1, column=1, sticky="w", pady=2)
        self.delay.insert(0, "1")
        
        tk.Label(req_frame, text="Success Indicator:", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=2)
        self.success_indicator = tk.Entry(req_frame, width=30)
        self.success_indicator.grid(row=2, column=1, sticky="ew", pady=2)
        self.success_indicator.insert(0, "Welcome" or "dashboard")
        
        # Control buttons
        control_frame = tk.Frame(left_frame, bg="#f5f5f5")
        control_frame.grid(row=5, column=0, columnspan=3, pady=10)
        
        tk.Button(control_frame, text="Start", command=self.start_web_bruteforce, width=8).grid(row=0, column=0, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_cracking, width=8).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="Stop", command=self.stop_cracking, width=8).grid(row=0, column=2, padx=5)
        tk.Button(control_frame, text="Export", command=self.export_results, width=8).grid(row=0, column=3, padx=5)
        
        # Right panel - results
        right_frame = tk.Frame(frame, bg="#f5f5f5")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Label(right_frame, text="Results:", bg="#f5f5f5", fg="black").pack(anchor="w")
        self.web_results = scrolledtext.ScrolledText(right_frame, width=60, height=25)
        self.web_results.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.web_progress = ttk.Progressbar(right_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.web_progress.pack(fill=tk.X, pady=5)
    
    def setup_wifi_tab(self):
        """Setup the WiFi cracking tab"""
        frame = tk.Frame(self.wifi_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - inputs
        left_frame = tk.Frame(frame, bg="#f5f5f5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Handshake file selection
        tk.Label(left_frame, text="Handshake File:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5)
        self.handshake_entry = tk.Entry(left_frame, width=40)
        self.handshake_entry.grid(row=0, column=1, sticky="ew", pady=5)
        tk.Button(left_frame, text="Browse", command=lambda: self.browse_file(self.handshake_entry)).grid(row=0, column=2, padx=5)
        
        # Wordlist selection
        tk.Label(left_frame, text="Wordlist:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5)
        self.wifi_wordlist_entry = tk.Entry(left_frame, width=40)
        self.wifi_wordlist_entry.grid(row=1, column=1, sticky="ew", pady=5)
        tk.Button(left_frame, text="Browse", command=lambda: self.browse_file(self.wifi_wordlist_entry)).grid(row=1, column=2, padx=5)
        
        # ESSID input
        tk.Label(left_frame, text="ESSID (Optional):", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=5)
        self.essid_entry = tk.Entry(left_frame, width=40)
        self.essid_entry.grid(row=2, column=1, sticky="ew", pady=5)
        
        # Hash type selection
        tk.Label(left_frame, text="Hash Type:", bg="#f5f5f5", fg="black").grid(row=3, column=0, sticky="w", pady=5)
        self.wifi_hash_type = tk.StringVar(value="pmkid")
        hash_types = ["pmkid", "handshake"]
        hash_dropdown = ttk.Combobox(left_frame, textvariable=self.wifi_hash_type, values=hash_types, state="readonly")
        hash_dropdown.grid(row=3, column=1, sticky="ew", pady=5)
        
        # Control buttons
        control_frame = tk.Frame(left_frame, bg="#f5f5f5")
        control_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        tk.Button(control_frame, text="Start", command=self.start_wifi_cracking, width=8).grid(row=0, column=0, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_cracking, width=8).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="Stop", command=self.stop_cracking, width=8).grid(row=0, column=2, padx=5)
        tk.Button(control_frame, text="Export", command=self.export_results, width=8).grid(row=0, column=3, padx=5)
        
        # Right panel - results
        right_frame = tk.Frame(frame, bg="#f5f5f5")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Label(right_frame, text="Results:", bg="#f5f5f5", fg="black").pack(anchor="w")
        self.wifi_results = scrolledtext.ScrolledText(right_frame, width=60, height=25)
        self.wifi_results.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.wifi_progress = ttk.Progressbar(right_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.wifi_progress.pack(fill=tk.X, pady=5)
    
    def setup_ntlm_tab(self):
        """Setup the NTLM cracking tab"""
        frame = tk.Frame(self.ntlm_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - inputs
        left_frame = tk.Frame(frame, bg="#f5f5f5")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # NTLM hash input
        tk.Label(left_frame, text="NTLM Hash:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5)
        self.ntlm_hash_entry = tk.Entry(left_frame, width=40)
        self.ntlm_hash_entry.grid(row=0, column=1, columnspan=2, sticky="ew", pady=5)
        
        # Wordlist selection
        tk.Label(left_frame, text="Wordlist:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5)
        self.ntlm_wordlist_entry = tk.Entry(left_frame, width=40)
        self.ntlm_wordlist_entry.grid(row=1, column=1, sticky="ew", pady=5)
        tk.Button(left_frame, text="Browse", command=lambda: self.browse_file(self.ntlm_wordlist_entry)).grid(row=1, column=2, padx=5)
        
        # Brute force options
        brute_frame = tk.LabelFrame(left_frame, text="Brute Force Options", bg="#f5f5f5", fg="black")
        brute_frame.grid(row=2, column=0, columnspan=3, sticky="ew", pady=5, padx=5)
        
        tk.Label(brute_frame, text="Min Length:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=2)
        self.ntlm_min_length = tk.Spinbox(brute_frame, from_=1, to=10, width=5)
        self.ntlm_min_length.grid(row=0, column=1, sticky="w", pady=2)
        
        tk.Label(brute_frame, text="Max Length:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=2)
        self.ntlm_max_length = tk.Spinbox(brute_frame, from_=1, to=10, width=5)
        self.ntlm_max_length.grid(row=1, column=1, sticky="w", pady=2)
        
        tk.Label(brute_frame, text="Characters:", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=2)
        self.ntlm_chars = tk.Entry(brute_frame, width=30)
        self.ntlm_chars.insert(0, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()")
        self.ntlm_chars.grid(row=2, column=1, sticky="ew", pady=2)
        
        # Control buttons
        control_frame = tk.Frame(left_frame, bg="#f5f5f5")
        control_frame.grid(row=3, column=0, columnspan=3, pady=10)
        
        tk.Button(control_frame, text="Start", command=self.start_ntlm_cracking, width=8).grid(row=0, column=0, padx=5)
        tk.Button(control_frame, text="Pause", command=self.pause_cracking, width=8).grid(row=0, column=1, padx=5)
        tk.Button(control_frame, text="Stop", command=self.stop_cracking, width=8).grid(row=0, column=2, padx=5)
        tk.Button(control_frame, text="Export", command=self.export_results, width=8).grid(row=0, column=3, padx=5)
        
        # Right panel - results
        right_frame = tk.Frame(frame, bg="#f5f5f5")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Label(right_frame, text="Results:", bg="#f5f5f5", fg="black").pack(anchor="w")
        self.ntlm_results = scrolledtext.ScrolledText(right_frame, width=60, height=25)
        self.ntlm_results.pack(fill=tk.BOTH, expand=True)
        
        # Progress bar
        self.ntlm_progress = ttk.Progressbar(right_frame, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.ntlm_progress.pack(fill=tk.X, pady=5)
    
    def setup_rainbow_tab(self):
        """Setup the Rainbow Table Cracker tab"""
        frame = tk.Frame(self.rainbow_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left panel - Generate Rainbow Table
        left_frame = tk.LabelFrame(frame, text="Generate Rainbow Table", bg="#f5f5f5", fg="black")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Wordlist selection
        tk.Label(left_frame, text="Wordlist:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5)
        self.rainbow_wordlist_entry = tk.Entry(left_frame, width=40)
        self.rainbow_wordlist_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=5)
        tk.Button(left_frame, text="Browse", command=lambda: self.browse_file(self.rainbow_wordlist_entry)).grid(row=0, column=2, padx=5)
        
        # Hash algorithm selection
        tk.Label(left_frame, text="Hash Algorithm:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5)
        self.rainbow_hash_algo = tk.StringVar(value="md5")
        hash_algos = ["md5", "sha1", "sha256", "sha512"]
        ttk.Combobox(left_frame, textvariable=self.rainbow_hash_algo, values=hash_algos, state="readonly").grid(
            row=1, column=1, sticky="ew", pady=5, padx=5)
        
        # Output file
        tk.Label(left_frame, text="Output File:", bg="#f5f5f5", fg="black").grid(row=2, column=0, sticky="w", pady=5)
        self.rainbow_output_entry = tk.Entry(left_frame, width=40)
        self.rainbow_output_entry.grid(row=2, column=1, sticky="ew", pady=5, padx=5)
        tk.Button(left_frame, text="Browse", command=self.browse_rainbow_output).grid(row=2, column=2, padx=5)
        
        # Generate button
        tk.Button(left_frame, text="Generate Rainbow Table", command=self.generate_rainbow_table, 
                 bg="#27ae60", fg="black").grid(row=3, column=0, columnspan=3, pady=10)
        
        # Right panel - Crack with Rainbow Table
        right_frame = tk.LabelFrame(frame, text="Crack with Rainbow Table", bg="#f5f5f5", fg="black")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Hash input
        tk.Label(right_frame, text="Hash(es) to Crack:", bg="#f5f5f5", fg="black").pack(anchor="w", pady=5)
        self.rainbow_hash_text = scrolledtext.ScrolledText(right_frame, height=5, width=40)
        self.rainbow_hash_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Rainbow table file
        tk.Label(right_frame, text="Rainbow Table File:", bg="#f5f5f5", fg="black").pack(anchor="w", pady=5)
        self.rainbow_table_entry = tk.Entry(right_frame, width=40)
        self.rainbow_table_entry.pack(fill=tk.X, padx=5, pady=5)
        tk.Button(right_frame, text="Browse", command=lambda: self.browse_file(self.rainbow_table_entry)).pack(anchor="e", padx=5, pady=5)
        
        # Crack button
        tk.Button(right_frame, text="Crack Hashes", command=self.crack_with_rainbow_table, 
                 bg="#e74c3c", fg="black").pack(pady=10)
        
        # Results
        tk.Label(right_frame, text="Results:", bg="#f5f5f5", fg="black").pack(anchor="w", pady=5)
        self.rainbow_results = scrolledtext.ScrolledText(right_frame, height=10, width=40, state=tk.DISABLED)
        self.rainbow_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure grid weights
        left_frame.columnconfigure(1, weight=1)
        right_frame.columnconfigure(0, weight=1)
    
    def setup_settings_tab(self):
        """Setup the settings tab"""
        frame = tk.Frame(self.settings_tab, bg="#f5f5f5")
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General settings
        gen_frame = tk.LabelFrame(frame, text="General Settings", bg="#f5f5f5", fg="black")
        gen_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Threads
        tk.Label(gen_frame, text="Max Threads:", bg="#f5f5f5", fg="black").grid(row=0, column=0, sticky="w", pady=5, padx=5)
        self.max_threads = tk.Spinbox(gen_frame, from_=1, to=32, width=5)
        self.max_threads.grid(row=0, column=1, sticky="w", pady=5, padx=5)
        self.max_threads.insert(0, "8")
        
        # Log level
        tk.Label(gen_frame, text="Log Level:", bg="#f5f5f5", fg="black").grid(row=1, column=0, sticky="w", pady=5, padx=5)
        self.log_level = tk.StringVar(value="INFO")
        log_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
        log_dropdown = ttk.Combobox(gen_frame, textvariable=self.log_level, values=log_levels, state="readonly")
        log_dropdown.grid(row=1, column=1, sticky="w", pady=5, padx=5)
        
        # Wordlists
        wordlist_frame = tk.LabelFrame(frame, text="Wordlist Management", bg="#f5f5f5", fg="black")
        wordlist_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        tk.Button(wordlist_frame, text="Download Common Wordlists", command=self.download_wordlists).pack(pady=10)
        
        # Log viewer
        log_frame = tk.LabelFrame(frame, text="Log Viewer", bg="#f5f5f5", fg="black")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_viewer = scrolledtext.ScrolledText(log_frame, width=60, height=10)
        self.log_viewer.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Button(log_frame, text="Clear Log", command=self.clear_log).pack(pady=5)
    
    def setup_log_window(self):
        """Setup the log window"""
        log_window = tk.Toplevel(self.root)
        log_window.title("Cracker Log")
        log_window.geometry("600x300")
        
        # Configure log window colors
        log_window.configure(bg="black")
        
        # Create text widget with black background and green text
        self.log_text = scrolledtext.ScrolledText(
            log_window, 
            width=80, 
            height=20,
            bg="black",
            fg="#00ff00",  # Bright green text
            insertbackground="#00ff00",  # Cursor color
            selectbackground="#005500",  # Selection background
            selectforeground="#ffffff"    # Selection foreground
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout to the log window
        import sys
        class StdoutRedirector:
            def __init__(self, text_widget):
                self.text_widget = text_widget
            
            def write(self, string):
                self.text_widget.insert(tk.END, string)
                self.text_widget.see(tk.END)
            
            def flush(self):
                # This is a no-op method to satisfy the file-like interface
                pass
        
        sys.stdout = StdoutRedirector(self.log_text)
    
    def browse_file(self, entry):
        """Open file dialog and set the entry text to the selected file"""
        filename = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("Cap Files", "*.cap"), ("Pcap Files", "*.pcap")]
        )
        if filename:
            entry.delete(0, tk.END)
            entry.insert(0, filename)
    
    def start_hash_cracking(self):
        """Start hash cracking process"""
        if self.running:
            messagebox.showwarning("Warning", "A cracking process is already running!")
            return
        
        self.running = True
        self.paused = False
        self.hash_results.delete(1.0, tk.END)
        self.hash_progress['value'] = 0
        
        # Get inputs
        hash_file = self.hash_file_entry.get()
        wordlist = self.wordlist_entry.get()
        hash_type = self.hash_type.get()
        
        if not hash_file or not wordlist:
            messagebox.showerror("Error", "Please select both hash file and wordlist!")
            self.running = False
            return
        
        # Start cracking in a separate thread
        self.current_task = threading.Thread(
            target=self.hash_cracker_thread,
            args=(hash_file, wordlist, hash_type)
        )
        self.current_task.daemon = True
        self.current_task.start()
        
        self.status_label.config(text="Hash cracking started...")
        self.log_queue.put(f"[INFO] Started hash cracking at {datetime.now()}")
    
    def hash_cracker_thread(self, hash_file, wordlist, hash_type):
        """Thread function for hash cracking"""
        password_found = False
        try:
            print(f"[DEBUG] Starting hash cracking process")
            print(f"[DEBUG] Hash file: {hash_file}")
            print(f"[DEBUG] Wordlist: {wordlist}")
            print(f"[DEBUG] Hash type: {hash_type}")
            
            # Read hashes from file
            with open(hash_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
            
            print(f"[DEBUG] Loaded {len(hashes)} hashes to crack")
            
            # Read passwords from wordlist
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            print(f"[DEBUG] Loaded {len(passwords)} passwords from wordlist")
            
            total = len(hashes) * len(passwords)
            current = 0
            
            print("[INFO] Starting hash cracking...")
            
            for password in passwords:
                if not self.running:
                    print("[INFO] Cracking process stopped by user")
                    break
                
                while self.paused:
                    time.sleep(0.1)
                
                for h in hashes:
                    current += 1
                    progress = (current / total) * 100
                    self.hash_progress['value'] = progress
                    self.status_label.config(text=f"Testing password: {password} - Progress: {progress:.2f}%")
                    
                    # Try to crack the hash
                    if self.test_hash(h, password, hash_type):
                        result = f"[SUCCESS] Hash: {h} -> Password found: {password}"
                        print(result)
                        self.results_queue.put(result)
                        self.log_queue.put(f"[SUCCESS] Found password for hash: {h}")
                        password_found = True
                        self.running = False  # Stop further processing
                        break
                
                if password_found or not self.running:
                    break
                
                # Update progress every 100 passwords to reduce UI updates
                if current % 100 == 0:
                    self.log_queue.put(f"[INFO] Tested {current} combinations so far...")
            
            if not password_found and self.running:
                msg = "[INFO] Password not found in the provided wordlist."
                print(msg)
                self.results_queue.put(msg)
                self.log_queue.put("[INFO] Hash cracking completed - Password not found")
                self.status_label.config(text="Hash cracking completed - Password not found")
        
        except FileNotFoundError as e:
            error_msg = f"[ERROR] File not found: {str(e)}"
            print(error_msg)
            self.results_queue.put(error_msg)
            self.log_queue.put(f"[ERROR] {str(e)}")
        
        except Exception as e:
            error_msg = f"[ERROR] {str(e)}"
            print(error_msg)
            self.results_queue.put(error_msg)
            self.log_queue.put(f"[ERROR] Hash cracking failed: {str(e)}")
        
        finally:
            print("[DEBUG] Hash cracking process ended")
            self.running = False
    
    def test_hash(self, h, password, hash_type):
        """Test if a password matches the hash"""
        try:
            print(f"[DEBUG] Testing password: {password}")
            print(f"[DEBUG] Target hash: {h}")
            print(f"[DEBUG] Hash type: {hash_type}")
            
            if hash_type.lower() == "md5":
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type.lower() == "sha1":
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type.lower() == "sha256":
                test_hash = hashlib.sha256(password.encode()).hexdigest()
            elif hash_type.lower() == "ntlm":
                test_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()
            elif hash_type.lower() == "bcrypt":
                # Bcrypt is more complex to implement - simplified for demo
                print("[DEBUG] Bcrypt not fully implemented, skipping")
                return False
            elif hash_type.lower() == "sha512":
                test_hash = hashlib.sha512(password.encode()).hexdigest()
            else:
                print(f"[DEBUG] Unknown hash type: {hash_type}")
                return False
            
            print(f"[DEBUG] Generated hash: {test_hash}")
            result = test_hash.lower() == h.lower().strip()
            print(f"[DEBUG] Match: {result}")
            return result
        
        except Exception as e:
            print(f"[DEBUG] Error in test_hash: {str(e)}")
            return False
    
    def start_web_bruteforce(self):
        """Start web bruteforce process"""
        if self.running:
            messagebox.showwarning("Warning", "A cracking process is already running!")
            return
        
        self.running = True
        self.paused = False
        self.web_results.delete(1.0, tk.END)
        self.web_progress['value'] = 0
        
        # Get inputs
        url = self.url_entry.get()
        username = self.username_entry.get()
        wordlist = self.web_wordlist_entry.get()
        timeout = int(self.timeout.get())
        delay = float(self.delay.get())
        success_indicator = self.success_indicator.get()
        
        if not url or not wordlist:
            messagebox.showerror("Error", "Please enter target URL and wordlist!")
            self.running = False
            return
        
        # Start web bruteforce in a separate thread
        self.current_task = threading.Thread(
            target=self.web_bruteforce_thread,
            args=(url, username, wordlist, timeout, delay, success_indicator)
        )
        self.current_task.daemon = True
        self.current_task.start()
        
        self.status_label.config(text="Web bruteforcing started...")
        self.log_queue.put(f"[INFO] Started web bruteforcing at {datetime.now()}")
    
    def web_bruteforce_thread(self, url, username, wordlist, timeout, delay, success_indicator):
        """Thread function for web bruteforcing"""
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            total = len(passwords)
            current = 0
            
            for password in passwords:
                if not self.running:
                    break
                
                while self.paused:
                    time.sleep(0.1)
                
                current += 1
                progress = (current / total) * 100
                self.web_progress['value'] = progress
                self.status_label.config(text=f"Testing password: {password} - Progress: {progress:.2f}%")
                
                # Try to login
                success = self.test_web_login(url, username, password, timeout, success_indicator)
                if success:
                    self.results_queue.put(f"Username: {username} -> Password: {password}")
                    self.log_queue.put(f"[SUCCESS] Found password: {password}")
                    break
                
                # Delay between requests
                time.sleep(delay)
                
                # Update progress
                self.log_queue.put(f"[INFO] Tested password: {password}")
            
            if self.running and not self.results_queue.qsize():
                self.results_queue.put("Web bruteforcing completed - No password found!")
                self.log_queue.put("[INFO] Web bruteforcing completed - No password found")
                self.status_label.config(text="Web bruteforcing completed - No password found!")
        
        except Exception as e:
            self.results_queue.put(f"Error: {str(e)}")
            self.log_queue.put(f"[ERROR] Web bruteforcing failed: {str(e)}")
        
        finally:
            self.running = False
    
    def test_web_login(self, url, username, password, timeout, success_indicator):
        """Test a web login with given credentials"""
        try:
            # Parse form parameters
            form_params = self.form_params.get("1.0", tk.END).strip()
            params = {}
            for pair in form_params.split('&'):
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    params[key] = value.replace('PASSWORD', password)
            
            # Add username if not in form params
            if 'username' not in params:
                params['username'] = username
            
            # Send request
            response = requests.post(
                url,
                data=params,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0'}
            )
            
            # Check for success
            if success_indicator:
                return success_indicator.lower() in response.text.lower()
            else:
                return response.status_code == 200
            
        except Exception as e:
            self.log_queue.put(f"[ERROR] Web login test failed: {str(e)}")
            return False
    
    def start_wifi_cracking(self):
        """Start WiFi cracking process"""
        if self.running:
            messagebox.showwarning("Warning", "A cracking process is already running!")
            return
        
        self.running = True
        self.paused = False
        self.wifi_results.delete(1.0, tk.END)
        self.wifi_progress['value'] = 0
        
        # Get inputs
        handshake_file = self.handshake_entry.get()
        wordlist = self.wifi_wordlist_entry.get()
        hash_type = self.wifi_hash_type.get()
        
        if not handshake_file or not wordlist:
            messagebox.showerror("Error", "Please select both handshake file and wordlist!")
            self.running = False
            return
        
        # Start WiFi cracking in a separate thread
        self.current_task = threading.Thread(
            target=self.wifi_cracking_thread,
            args=(handshake_file, wordlist, hash_type)
        )
        self.current_task.daemon = True
        self.current_task.start()
        
        self.status_label.config(text="WiFi cracking started...")
        self.log_queue.put(f"[INFO] Started WiFi cracking at {datetime.now()}")
    
    def wifi_cracking_thread(self, handshake_file, wordlist, hash_type):
        """Thread function for WiFi cracking"""
        try:
            # For demonstration, we'll simulate WiFi cracking
            # In a real implementation, you would use pyshark to parse the handshake
            # and then use aircrack-ng or similar tools
            
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            total = len(passwords)
            current = 0
            
            for password in passwords:
                if not self.running:
                    break
                
                while self.paused:
                    time.sleep(0.1)
                
                current += 1
                progress = (current / total) * 100
                self.wifi_progress['value'] = progress
                self.status_label.config(text=f"Testing password: {password} - Progress: {progress:.2f}%")
                
                # Simulate testing the password
                if self.test_wifi_password(handshake_file, password, hash_type):
                    self.results_queue.put(f"WiFi Password Found: {password}")
                    self.log_queue.put(f"[SUCCESS] Found WiFi password: {password}")
                    break
                
                # Update progress
                self.log_queue.put(f"[INFO] Tested WiFi password: {password}")
            
            if self.running and not self.results_queue.qsize():
                self.results_queue.put("WiFi cracking completed - No password found!")
                self.log_queue.put("[INFO] WiFi cracking completed - No password found")
                self.status_label.config(text="WiFi cracking completed - No password found!")
        
        except Exception as e:
            self.results_queue.put(f"Error: {str(e)}")
            self.log_queue.put(f"[ERROR] WiFi cracking failed: {str(e)}")
        
        finally:
            self.running = False
    
    def test_wifi_password(self, handshake_file, password, hash_type):
        """Test a WiFi password (simulated for demonstration)"""
        # This is a simplified simulation
        # In a real implementation, you would use pyshark to parse the handshake
        # and then compare the generated hash with the captured hash
        
        # For demonstration, we'll just check if the password is in a list of known passwords
        common_passwords = ["password", "123456", "qwerty", "letmein", "admin"]
        return password.lower() in common_passwords
    
    def start_ntlm_cracking(self):
        """Start NTLM cracking process"""
        if self.running:
            messagebox.showwarning("Warning", "A cracking process is already running!")
            return
        
        self.running = True
        self.paused = False
        self.ntlm_results.delete(1.0, tk.END)
        self.ntlm_progress['value'] = 0
        
        # Get inputs
        ntlm_hash = self.ntlm_hash_entry.get()
        wordlist = self.ntlm_wordlist_entry.get()
        
        if not ntlm_hash:
            messagebox.showerror("Error", "Please enter an NTLM hash!")
            self.running = False
            return
        
        # Start NTLM cracking in a separate thread
        self.current_task = threading.Thread(
            target=self.ntlm_cracking_thread,
            args=(ntlm_hash, wordlist)
        )
        self.current_task.daemon = True
        self.current_task.start()
        
        self.status_label.config(text="NTLM cracking started...")
        self.log_queue.put(f"[INFO] Started NTLM cracking at {datetime.now()}")
    
    def ntlm_cracking_thread(self, ntlm_hash, wordlist):
        """Thread function for NTLM cracking"""
        try:
            # Try dictionary attack first
            if wordlist:
                with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                total = len(passwords)
                current = 0
                
                for password in passwords:
                    if not self.running:
                        break
                    
                    while self.paused:
                        time.sleep(0.1)
                    
                    current += 1
                    progress = (current / total) * 100
                    self.ntlm_progress['value'] = progress
                    self.status_label.config(text=f"Testing password: {password} - Progress: {progress:.2f}%")
                    
                    # Test the password
                    if self.test_ntlm_hash(ntlm_hash, password):
                        self.results_queue.put(f"NTLM Hash: {ntlm_hash} -> Password: {password}")
                        self.log_queue.put(f"[SUCCESS] Found NTLM password: {password}")
                        break
                    
                    # Update progress
                    self.log_queue.put(f"[INFO] Tested NTLM password: {password}")
            
            # If dictionary attack failed and brute force is enabled
            if self.running and not self.results_queue.qsize():
                min_len = int(self.ntlm_min_length.get())
                max_len = int(self.ntlm_max_length.get())
                chars = self.ntlm_chars.get()
                
                self.results_queue.put("Starting brute force attack...")
                self.log_queue.put("[INFO] Starting NTLM brute force attack")
                
                # Start brute force
                self.brute_force_ntlm(ntlm_hash, min_len, max_len, chars)
            
            if self.running and not self.results_queue.qsize():
                self.results_queue.put("NTLM cracking completed - No password found!")
                self.log_queue.put("[INFO] NTLM cracking completed - No password found")
                self.status_label.config(text="NTLM cracking completed - No password found!")
        
        except Exception as e:
            self.results_queue.put(f"Error: {str(e)}")
            self.log_queue.put(f"[ERROR] NTLM cracking failed: {str(e)}")
        
        finally:
            self.running = False
    
    def test_ntlm_hash(self, ntlm_hash, password):
        """Test if a password matches the NTLM hash"""
        try:
            # Calculate NTLM hash of the password
            from Crypto.Hash import MD4
            ntlm = MD4.new(password.encode('utf-16le')).hexdigest()
            return ntlm.lower() == ntlm_hash.lower()
        except:
            return False
    
    def brute_force_ntlm(self, ntlm_hash, min_len, max_len, chars):
        """Brute force NTLM hash"""
        try:
            from itertools import product
            
            total = sum(len(chars) ** i for i in range(min_len, max_len + 1))
            current = 0
            
            for length in range(min_len, max_len + 1):
                for attempt in product(chars, repeat=length):
                    if not self.running:
                        return
                    
                    while self.paused:
                        time.sleep(0.1)
                    
                    password = ''.join(attempt)
                    current += 1
                    progress = (current / total) * 100
                    self.ntlm_progress['value'] = progress
                    self.status_label.config(text=f"Brute forcing: {password} - Progress: {progress:.2f}%")
                    
                    # Test the password
                    if self.test_ntlm_hash(ntlm_hash, password):
                        self.results_queue.put(f"NTLM Hash: {ntlm_hash} -> Password: {password}")
                        self.log_queue.put(f"[SUCCESS] Found NTLM password (brute force): {password}")
                        return
                    
                    # Update progress
                    self.log_queue.put(f"[INFO] Tested NTLM password (brute force): {password}")
            
            if self.running:
                self.results_queue.put("NTLM brute force completed - No password found!")
                self.log_queue.put("[INFO] NTLM brute force completed - No password found")
        
        except Exception as e:
            self.results_queue.put(f"Error: {str(e)}")
            self.log_queue.put(f"[ERROR] NTLM brute force failed: {str(e)}")
    
    def pause_cracking(self):
        """Pause the current cracking process"""
        if self.running:
            self.paused = not self.paused
            status = "paused" if self.paused else "resumed"
            self.status_label.config(text=f"Cracking process {status}")
            self.log_queue.put(f"[INFO] Cracking process {status}")
    
    def stop_cracking(self):
        """Stop the current cracking process"""
        if self.running:
            self.running = False
            self.paused = False
            self.status_label.config(text="Cracking process stopped")
            self.log_queue.put("[INFO] Cracking process stopped")
    
    def export_results(self):
        """Export results to a file"""
        if not self.results_queue.qsize():
            messagebox.showinfo("Info", "No results to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Results",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialdir=os.getcwd()
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w') as f:
                while not self.results_queue.empty():
                    result = self.results_queue.get()
                    f.write(result + "\n")
            
            messagebox.showinfo("Success", f"Results exported to {filename}")
            self.log_queue.put(f"[INFO] Results exported to {filename}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
            self.log_queue.put(f"[ERROR] Failed to export results: {str(e)}")
    
    def download_wordlists(self):
        """Download common wordlists (stub for demonstration)"""
        messagebox.showinfo("Info", "Wordlist download feature would be implemented here.")
        self.log_queue.put("[INFO] Wordlist download initiated")
    
    def clear_log(self):
        """Clear the log window"""
        self.log_text.delete(1.0, tk.END)
        self.log_queue.put("[INFO] Log cleared")
    
    def monitor_logs(self):
        """Monitor the log queue and update the log window"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message + "\n")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.root.after(100, self.monitor_logs)
    
    def log_message(self, message):
        """Add a message to the log queue"""
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S] ")
        self.log_queue.put(timestamp + message)
        
    def update_results(self):
        """Update the results displays"""
        # Update hash results
        while not self.results_queue.empty():
            result = self.results_queue.get()
            
            # Determine which tab to update based on context
            if "Hash:" in result:
                self.hash_results.insert(tk.END, result + "\n")
                self.hash_results.see(tk.END)
            elif "Username:" in result and "Password:" in result:
                self.web_results.insert(tk.END, result + "\n")
                self.web_results.see(tk.END)
            elif "WiFi Password" in result:
                self.wifi_results.insert(tk.END, result + "\n")
                self.wifi_results.see(tk.END)
            elif "NTLM Hash:" in result:
                self.ntlm_results.insert(tk.END, result + "\n")
                self.ntlm_results.see(tk.END)
            else:
                # Generic result
                self.hash_results.insert(tk.END, result + "\n")
                self.hash_results.see(tk.END)
    
    def browse_rainbow_output(self):
        """Open file dialog to select output file for rainbow table"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Rainbow Table As"
        )
        if filename:
            self.rainbow_output_entry.delete(0, tk.END)
            self.rainbow_output_entry.insert(0, filename)
    
    def generate_rainbow_table(self):
        """Generate rainbow table from wordlist"""
        wordlist_path = self.rainbow_wordlist_entry.get()
        output_file = self.rainbow_output_entry.get()
        algo = self.rainbow_hash_algo.get()
        
        if not wordlist_path or not output_file:
            messagebox.showerror("Error", "Please provide both wordlist and output file paths")
            return
            
        if not os.path.exists(wordlist_path):
            messagebox.showerror("Error", f"Wordlist file not found: {wordlist_path}")
            return
            
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
                
            if not wordlist:
                messagebox.showerror("Error", "Wordlist is empty")
                return
                
            self.log_message(f"Generating rainbow table with {len(wordlist)} words using {algo}...")
            
            # Start generation in a separate thread
            threading.Thread(
                target=self._generate_rainbow_table_thread,
                args=(wordlist, algo, output_file),
                daemon=True
            ).start()
            
        except Exception as e:
            self.log_message(f"Error generating rainbow table: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate rainbow table: {str(e)}")
    
    def _generate_rainbow_table_thread(self, wordlist, algo, output_file):
        """Thread function for rainbow table generation"""
        try:
            table = {}
            total_words = len(wordlist)
            progress_interval = max(1, total_words // 100)  # Update at most 100 times
            
            for i, word in enumerate(wordlist):
                if hasattr(self, 'stop_threads'):
                    self.log_message("Rainbow table generation stopped by user")
                    return
                    
                try:
                    hashed = self.hash_text(word, algo)
                    table[hashed] = word
                except Exception as e:
                    self.log_message(f"Warning: Error hashing '{word}': {str(e)}")
                
                if (i + 1) % progress_interval == 0 or (i + 1) == total_words:
                    self.log_message(f"Progress: {i + 1}/{total_words} words processed ({(i + 1) / total_words:.1%})")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(table, f, indent=4)
                
            self.log_message(f"✅ Rainbow table with {len(table)} entries saved to {output_file}")
            messagebox.showinfo("Success", f"Rainbow table successfully generated with {len(table)} entries!")
            
        except Exception as e:
            self.log_message(f"Error in rainbow table generation: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to generate rainbow table: {str(e)}"))
    
    def crack_with_rainbow_table(self):
        """Crack hashes using a rainbow table"""
        hash_text = self.rainbow_hash_text.get("1.0", tk.END).strip()
        rainbow_table_file = self.rainbow_table_entry.get()
        
        if not hash_text:
            messagebox.showerror("Error", "Please enter at least one hash to crack")
            return
            
        if not rainbow_table_file or not os.path.exists(rainbow_table_file):
            messagebox.showerror("Error", "Please select a valid rainbow table file")
            return
            
        hash_list = [h.strip() for h in hash_text.split('\n') if h.strip()]
        
        # Start cracking in a separate thread
        threading.Thread(
            target=self._crack_with_rainbow_table_thread,
            args=(hash_list, rainbow_table_file),
            daemon=True
        ).start()
    
    def _crack_with_rainbow_table_thread(self, hash_list, rainbow_table_file):
        """Thread function for rainbow table cracking"""
        try:
            # Load rainbow table
            with open(rainbow_table_file, 'r', encoding='utf-8') as f:
                table = json.load(f)
                
            self.log_message(f"Loaded rainbow table with {len(table)} entries")
            
            # Find matches
            cracked = {}
            for h in hash_list:
                if h.lower() in table:
                    cracked[h] = table[h.lower()]
            
            # Display results
            self.rainbow_results.config(state=tk.NORMAL)
            self.rainbow_results.delete(1.0, tk.END)
            
            if cracked:
                result_text = "Cracked hashes:\n" + "\n".join(f"{h}: {p}" for h, p in cracked.items())
                self.log_message(f"✅ Successfully cracked {len(cracked)} out of {len(hash_list)} hashes")
            else:
                result_text = "No hashes were cracked with the provided rainbow table."
                self.log_message("❌ No hashes were cracked with the provided rainbow table")
                
            self.rainbow_results.insert(tk.END, result_text)
            self.rainbow_results.config(state=tk.DISABLED)
            
        except json.JSONDecodeError:
            self.log_message("Error: Invalid rainbow table file format")
            self.root.after(0, lambda: messagebox.showerror("Error", "Invalid rainbow table file format"))
        except Exception as e:
            self.log_message(f"Error during rainbow table cracking: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to crack hashes: {str(e)}"))
    
    def hash_text(self, text, algo):
        """Hash text using the specified algorithm"""
        if algo.lower() == "md5":
            return hashlib.md5(text.encode()).hexdigest()
        elif algo.lower() == "sha1":
            return hashlib.sha1(text.encode()).hexdigest()
        elif algo.lower() == "sha256":
            return hashlib.sha256(text.encode()).hexdigest()
        elif algo.lower() == "sha512":
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {algo}")

def main():
    root = tk.Tk()
    app = PasswordCrackerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()