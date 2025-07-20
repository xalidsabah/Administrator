#!/usr/bin/env python3
"""
Subdomain Searcher GUI - Modern Edition
A sleek, modern desktop application with advanced subdomain enumeration capabilities.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import dns.resolver
import dns.exception
import threading
import time
import os
import sys
import socket
import requests
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, quote
import ssl
import OpenSSL.crypto
import webbrowser

class ModernSubdomainSearcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Subdomain Searcher Pro")
        self.root.geometry("1200x800")
        self.root.configure(bg='#1a1a1a')
        
        # Set modern theme
        self.setup_modern_theme()
        
        # Variables
        self.domain_var = tk.StringVar()
        self.threads_var = tk.IntVar(value=15)
        self.timeout_var = tk.IntVar(value=8)
        self.output_file_var = tk.StringVar(value="output/found.txt")
        
        # Method checkboxes with modern styling
        self.methods = {
            'ct': tk.BooleanVar(value=True),
            'search': tk.BooleanVar(value=True),
            'passive': tk.BooleanVar(value=True),
            'brute': tk.BooleanVar(value=True)
        }
        
        # Scan state
        self.is_scanning = False
        self.scan_thread = None
        self.found_subdomains = []
        self.start_time = 0
        self.scan_stats = {
            'total_tested': 0,
            'total_found': 0,
            'method_results': {}
        }
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]
        
        # Create main container
        self.create_main_container()
        self.setup_ui()
        
    def setup_modern_theme(self):
        """Setup modern dark theme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure basic colors
        style.configure('TFrame', background='#1a1a1a')
        style.configure('TLabel', 
                       background='#2d2d2d', 
                       foreground='#ffffff', 
                       font=('Segoe UI', 10))
        style.configure('TButton', 
                       background='#00d4ff', 
                       foreground='#ffffff',
                       font=('Segoe UI', 10, 'bold'),
                       padding=(20, 10))
        style.configure('TCheckbutton', 
                       background='#2d2d2d', 
                       foreground='#ffffff',
                       font=('Segoe UI', 10))
        style.configure('TEntry', 
                       fieldbackground='#3d3d3d', 
                       foreground='#ffffff',
                       font=('Segoe UI', 10))
        style.configure('TSpinbox', 
                       fieldbackground='#3d3d3d', 
                       foreground='#ffffff',
                       font=('Segoe UI', 10))
        
        # Configure progress bar colors
        style.configure('Horizontal.TProgressbar', 
                       background='#00d4ff', 
                       troughcolor='#3d3d3d',
                       bordercolor='#3d3d3d',
                       lightcolor='#00d4ff',
                       darkcolor='#00d4ff')
        
    def create_main_container(self):
        """Create the main container with modern styling."""
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Configure grid weights
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(1, weight=1)
        
    def setup_ui(self):
        """Setup the modern user interface."""
        # Header section
        self.create_header()
        
        # Main content area
        self.create_main_content()
        
        # Status bar
        self.create_status_bar()
        
    def create_header(self):
        """Create the header section."""
        header_frame = ttk.Frame(self.main_container)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        header_frame.columnconfigure(1, weight=1)
        
        # Title and subtitle
        title_label = ttk.Label(header_frame, 
                               text="🔍 Subdomain Searcher Pro", 
                               font=('Segoe UI', 24, 'bold'),
                               foreground='#00d4ff')
        title_label.grid(row=0, column=0, columnspan=3, pady=(20, 5))
        
        subtitle_label = ttk.Label(header_frame, 
                                  text="Advanced subdomain enumeration with multiple discovery methods", 
                                  font=('Segoe UI', 10),
                                  foreground='#cccccc')
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
    def create_main_content(self):
        """Create the main content area."""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 20))
        
        # Scan tab
        self.create_scan_tab()
        
        # Results tab
        self.create_results_tab()
        
        # Settings tab
        self.create_settings_tab()
        
    def create_scan_tab(self):
        """Create the scan configuration tab."""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="🚀 Scan")
        
        # Domain input section
        domain_frame = ttk.Frame(scan_frame)
        domain_frame.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(domain_frame, text="Target Domain:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        domain_input_frame = ttk.Frame(domain_frame)
        domain_input_frame.pack(fill=tk.X)
        
        domain_entry = ttk.Entry(domain_input_frame, 
                                textvariable=self.domain_var, 
                                font=('Segoe UI', 12))
        domain_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        domain_entry.insert(0, "example.com")
        
        # Quick scan button
        self.quick_scan_btn = ttk.Button(domain_input_frame, 
                                        text="🔍 Quick Scan", 
                                        command=self.quick_scan)
        self.quick_scan_btn.pack(side=tk.RIGHT)
        
        # Methods section
        methods_frame = ttk.Frame(scan_frame)
        methods_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Label(methods_frame, text="Discovery Methods:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        method_descriptions = {
            'ct': '🔐 Certificate Transparency Logs',
            'search': '🌐 Search Engine Dorking',
            'passive': '📊 Passive DNS Databases',
            'brute': '⚡ DNS Brute Force'
        }
        
        methods_grid = ttk.Frame(methods_frame)
        methods_grid.pack(fill=tk.X)
        
        for i, (method, desc) in enumerate(method_descriptions.items()):
            row = i // 2
            col = i % 2
            
            method_frame = ttk.Frame(methods_grid)
            method_frame.grid(row=row, column=col, sticky=(tk.W, tk.E), padx=(0, 20), pady=5)
            
            ttk.Checkbutton(method_frame, text=desc, variable=self.methods[method]).pack(anchor=tk.W)
        
        # Control buttons
        control_frame = ttk.Frame(scan_frame)
        control_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        # Start scan button
        self.start_btn = ttk.Button(control_frame, 
                                   text="🚀 Start Full Scan", 
                                   command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop scan button
        self.stop_btn = ttk.Button(control_frame, 
                                  text="⏹️ Stop Scan", 
                                  command=self.stop_scan,
                                  state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear results button
        self.clear_btn = ttk.Button(control_frame, 
                                   text="🗑️ Clear Results", 
                                   command=self.clear_results)
        self.clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress section
        progress_frame = ttk.Frame(scan_frame)
        progress_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Label(progress_frame, text="Scan Progress:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        self.progress_var = tk.StringVar(value="Ready to scan")
        ttk.Label(progress_frame, textvariable=self.progress_var,
                 font=('Segoe UI', 10),
                 foreground='#cccccc').pack(anchor=tk.W, pady=(0, 10))
        
        self.progress_bar = ttk.Progressbar(progress_frame, 
                                           mode='indeterminate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 10))
        
        # Stats section
        stats_frame = ttk.Frame(scan_frame)
        stats_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        ttk.Label(stats_frame, text="Live Statistics:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 10))
        
        self.stats_text = tk.StringVar(value="Subdomains found: 0 | Time elapsed: 0s | Methods completed: 0/4")
        ttk.Label(stats_frame, textvariable=self.stats_text,
                 font=('Segoe UI', 12, 'bold'),
                 foreground='#00ff88').pack(anchor=tk.W)
        
    def create_results_tab(self):
        """Create the results display tab."""
        results_frame = ttk.Frame(self.notebook)
        self.notebook.add(results_frame, text="📊 Results")
        
        # Results header
        results_header = ttk.Frame(results_frame)
        results_header.pack(fill=tk.X, padx=20, pady=20)
        
        ttk.Label(results_header, text="Scan Results:", 
                 font=('Segoe UI', 18, 'bold')).pack(side=tk.LEFT)
        
        # Export button
        self.export_btn = ttk.Button(results_header, 
                                    text="💾 Export Results", 
                                    command=self.export_results)
        self.export_btn.pack(side=tk.RIGHT)
        
        # Results text area with modern styling
        text_frame = ttk.Frame(results_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Create text widget with custom styling
        self.results_text = tk.Text(text_frame, 
                                   height=20, 
                                   width=80,
                                   bg='#2d2d2d',
                                   fg='#ffffff',
                                   insertbackground='#ffffff',
                                   selectbackground='#00d4ff',
                                   font=('Consolas', 10),
                                   relief=tk.FLAT,
                                   padx=15,
                                   pady=15)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscrollcommand=scrollbar.set)
        
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_settings_tab(self):
        """Create the settings configuration tab."""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Settings content
        settings_content = ttk.Frame(settings_frame)
        settings_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Performance settings
        perf_frame = ttk.Frame(settings_content)
        perf_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(perf_frame, text="Performance Settings:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        # Threads setting
        threads_frame = ttk.Frame(perf_frame)
        threads_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(threads_frame, text="Threads:", 
                 font=('Segoe UI', 10),
                 foreground='#cccccc').pack(side=tk.LEFT)
        
        threads_spinbox = ttk.Spinbox(threads_frame, 
                                     from_=1, to=100, 
                                     textvariable=self.threads_var, 
                                     width=10)
        threads_spinbox.pack(side=tk.RIGHT)
        
        # Timeout setting
        timeout_frame = ttk.Frame(perf_frame)
        timeout_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(timeout_frame, text="Timeout (seconds):", 
                 font=('Segoe UI', 10),
                 foreground='#cccccc').pack(side=tk.LEFT)
        
        timeout_spinbox = ttk.Spinbox(timeout_frame, 
                                     from_=1, to=60, 
                                     textvariable=self.timeout_var, 
                                     width=10)
        timeout_spinbox.pack(side=tk.RIGHT)
        
        # Output settings
        output_frame = ttk.Frame(settings_content)
        output_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(output_frame, text="Output Settings:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        # Output file
        output_file_frame = ttk.Frame(output_frame)
        output_file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_file_frame, text="Output File:", 
                 font=('Segoe UI', 10),
                 foreground='#cccccc').pack(side=tk.LEFT)
        
        output_entry = ttk.Entry(output_file_frame, 
                                textvariable=self.output_file_var)
        output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 10))
        
        browse_btn = ttk.Button(output_file_frame, 
                               text="Browse", 
                               command=self.browse_output_file)
        browse_btn.pack(side=tk.RIGHT)
        
        # Help section
        help_frame = ttk.Frame(settings_content)
        help_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(help_frame, text="Help & Support:", 
                 font=('Segoe UI', 18, 'bold')).pack(anchor=tk.W, pady=(0, 15))
        
        help_btn = ttk.Button(help_frame, 
                             text="📖 View Documentation", 
                             command=self.open_documentation)
        help_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        about_btn = ttk.Button(help_frame, 
                              text="ℹ️ About", 
                              command=self.show_about)
        about_btn.pack(side=tk.LEFT)
        
    def create_status_bar(self):
        """Create the status bar."""
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.main_container, 
                              textvariable=self.status_var, 
                              relief=tk.SUNKEN,
                              background='#2d2d2d',
                              foreground='#ffffff',
                              font=('Segoe UI', 9))
        status_bar.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
    def browse_output_file(self):
        """Browse for output file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Results As"
        )
        if filename:
            self.output_file_var.set(filename)
            
    def get_random_user_agent(self):
        """Get a random user agent."""
        import random
        return random.choice(self.user_agents)
        
    def log_message(self, message, level="INFO"):
        """Log a message to the results area."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        if level == "ERROR":
            color = "#ff4757"
        elif level == "SUCCESS":
            color = "#00ff88"
        elif level == "WARNING":
            color = "#ffa502"
        else:
            color = "#00d4ff"
        
        formatted_message = f"[{timestamp}] {level}: {message}\n"
        
        self.results_text.insert(tk.END, formatted_message)
        
        # Apply color to the last line
        last_line_start = self.results_text.index("end-2c linestart")
        last_line_end = self.results_text.index("end-1c")
        self.results_text.tag_add(f"color_{level}", last_line_start, last_line_end)
        self.results_text.tag_config(f"color_{level}", foreground=color)
        
        self.results_text.see(tk.END)
        self.root.update_idletasks()
        
    def update_progress(self, message):
        """Update progress message."""
        self.progress_var.set(message)
        self.root.update_idletasks()
        
    def update_stats(self):
        """Update statistics display."""
        elapsed = time.time() - self.start_time if self.start_time > 0 else 0
        completed_methods = sum(1 for method in self.scan_stats['method_results'].values() if method.get('completed', False))
        total_methods = len([m for m in self.methods if self.methods[m].get()])
        
        stats = f"Subdomains found: {len(self.found_subdomains)} | Time elapsed: {elapsed:.1f}s | Methods completed: {completed_methods}/{total_methods}"
        self.stats_text.set(stats)
        
    def quick_scan(self):
        """Perform a quick scan with passive methods only."""
        domain = self.domain_var.get().strip()
        if not domain or '.' not in domain:
            messagebox.showerror("Error", "Please enter a valid domain")
            return
            
        # Set only passive methods for quick scan
        for method in self.methods:
            if method in ['ct', 'passive']:
                self.methods[method].set(True)
            else:
                self.methods[method].set(False)
        
        self.start_scan()
        
    def certificate_transparency_search(self):
        """Search for subdomains using Certificate Transparency logs."""
        self.log_message("Starting Certificate Transparency search...", "INFO")
        self.scan_stats['method_results']['ct'] = {'status': 'running', 'found': 0}
        
        ct_apis = [
            f"https://crt.sh/?q=%.{self.domain_var.get()}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain_var.get()}&include_subdomains=true&expand=dns_names"
        ]
        
        subdomains = set()
        
        for api_url in ct_apis:
            if not self.is_scanning:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=self.timeout_var.get())
                
                if response.status_code == 200:
                    if 'crt.sh' in api_url:
                        data = response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{self.domain_var.get()}') and '*' not in name:
                                        subdomains.add(name)
                    
                    elif 'certspotter' in api_url:
                        data = response.json()
                        for cert in data:
                            if 'dns_names' in cert:
                                for dns_name in cert['dns_names']:
                                    dns_name = dns_name.lower()
                                    if dns_name.endswith(f'.{self.domain_var.get()}') and '*' not in dns_name:
                                        subdomains.add(dns_name)
                                        
            except Exception as e:
                self.log_message(f"CT search failed for {api_url}: {e}", "ERROR")
        
        self.scan_stats['method_results']['ct'] = {'status': 'completed', 'found': len(subdomains), 'completed': True}
        self.log_message(f"Certificate Transparency found {len(subdomains)} subdomains", "SUCCESS")
        return subdomains

    def search_engine_dorking(self):
        """Search for subdomains using search engine dorks."""
        self.log_message("Starting search engine dorking...", "INFO")
        self.scan_stats['method_results']['search'] = {'status': 'running', 'found': 0}
        
        search_engines = [
            f"https://www.google.com/search?q=site:{self.domain_var.get()}",
            f"https://www.bing.com/search?q=site:{self.domain_var.get()}"
        ]
        
        subdomains = set()
        
        for search_url in search_engines:
            if not self.is_scanning:
                break
                
            try:
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                response = requests.get(search_url, headers=headers, timeout=self.timeout_var.get())
                
                if response.status_code == 200:
                    content = response.text.lower()
                    pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(self.domain_var.get())}'
                    matches = re.findall(pattern, content)
                    
                    for match in matches:
                        if match[0].endswith(f'.{self.domain_var.get()}') and '*' not in match[0]:
                            subdomains.add(match[0])
                            
            except Exception as e:
                self.log_message(f"Search engine dorking failed for {search_url}: {e}", "ERROR")
        
        self.scan_stats['method_results']['search'] = {'status': 'completed', 'found': len(subdomains), 'completed': True}
        self.log_message(f"Search engine dorking found {len(subdomains)} subdomains", "SUCCESS")
        return subdomains

    def passive_dns_search(self):
        """Search for subdomains using passive DNS services."""
        self.log_message("Starting passive DNS search...", "INFO")
        self.scan_stats['method_results']['passive'] = {'status': 'running', 'found': 0}
        
        passive_dns_apis = [
            f"https://dns.bufferover.run/dns?q=.{self.domain_var.get()}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain_var.get()}"
        ]
        
        subdomains = set()
        
        for api_url in passive_dns_apis:
            if not self.is_scanning:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=self.timeout_var.get())
                
                if response.status_code == 200:
                    content = response.text
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and '.' in line:
                            if ',' in line:
                                parts = line.split(',')
                                if len(parts) >= 1:
                                    subdomain = parts[0].lower()
                                    if subdomain.endswith(f'.{self.domain_var.get()}') and '*' not in subdomain:
                                        subdomains.add(subdomain)
                            else:
                                if line.endswith(f'.{self.domain_var.get()}') and '*' not in line:
                                    subdomains.add(line.lower())
                                    
            except Exception as e:
                self.log_message(f"Passive DNS search failed for {api_url}: {e}", "ERROR")
        
        self.scan_stats['method_results']['passive'] = {'status': 'completed', 'found': len(subdomains), 'completed': True}
        self.log_message(f"Passive DNS found {len(subdomains)} subdomains", "SUCCESS")
        return subdomains

    def dns_brute_force(self):
        """DNS brute force method."""
        self.log_message("Starting DNS brute force...", "INFO")
        self.scan_stats['method_results']['brute'] = {'status': 'running', 'found': 0}
        
        default_subdomains = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'dns1', 'dns2', 'admin', 'forum', 'blog', 'dev', 'test', 'stage', 'api',
            'cdn', 'static', 'media', 'img', 'images', 'css', 'js', 'assets',
            'm', 'mobile', 'wap', 'app', 'apps', 'secure', 'ssl', 'vpn', 'remote',
            'support', 'help', 'docs', 'wiki', 'status', 'monitor', 'stats', 'analytics',
            'auth', 'login', 'logout', 'signin', 'signout', 'register', 'signup',
            'dashboard', 'panel', 'admin', 'administrator', 'root', 'master', 'control',
            'manage', 'management', 'console', 'terminal', 'shell', 'ssh', 'telnet',
            'rdp', 'vnc', 'remote', 'gateway', 'proxy', 'cache', 'loadbalancer',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'memcached',
            'jenkins', 'gitlab', 'github', 'bitbucket', 'jira', 'confluence', 'docker',
            'kubernetes', 'k8s', 'prometheus', 'grafana', 'kibana', 'logstash'
        ]
        
        found_subdomains = set()
        
        def check_subdomain(subdomain):
            if not self.is_scanning:
                return None
                
            full_domain = f"{subdomain}.{self.domain_var.get()}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads_var.get()) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain 
                                 for subdomain in default_subdomains}
            
            for future in as_completed(future_to_subdomain):
                if not self.is_scanning:
                    break
                    
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        self.scan_stats['method_results']['brute'] = {'status': 'completed', 'found': len(found_subdomains), 'completed': True}
        self.log_message(f"DNS brute force found {len(found_subdomains)} subdomains", "SUCCESS")
        return found_subdomains

    def run_scan(self):
        """Run the subdomain enumeration."""
        try:
            self.start_time = time.time()
            all_subdomains = set()
            
            # Run selected methods
            if self.methods['ct'].get() and self.is_scanning:
                self.update_progress("Certificate Transparency search...")
                ct_results = self.certificate_transparency_search()
                all_subdomains.update(ct_results)

            if self.methods['search'].get() and self.is_scanning:
                self.update_progress("Search engine dorking...")
                search_results = self.search_engine_dorking()
                all_subdomains.update(search_results)

            if self.methods['passive'].get() and self.is_scanning:
                self.update_progress("Passive DNS search...")
                passive_results = self.passive_dns_search()
                all_subdomains.update(passive_results)

            if self.methods['brute'].get() and self.is_scanning:
                self.update_progress("DNS brute force...")
                brute_results = self.dns_brute_force()
                all_subdomains.update(brute_results)

            # Update results
            self.found_subdomains = list(all_subdomains)
            
            # Display results
            self.log_message(f"Scan completed! Found {len(self.found_subdomains)} unique subdomains", "SUCCESS")
            
            if self.found_subdomains:
                self.log_message("Found subdomains:", "INFO")
                for subdomain in sorted(self.found_subdomains):
                    self.log_message(f"  {subdomain}", "SUCCESS")
            
        except Exception as e:
            self.log_message(f"Scan error: {e}", "ERROR")
        finally:
            self.scan_finished()
            
    def scan_finished(self):
        """Called when scan is finished."""
        self.is_scanning = False
        self.progress_bar.stop()
        self.update_progress("Scan completed")
        self.update_stats()
        
        # Update button states
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        self.status_var.set("Scan completed")
        
        # Switch to results tab
        self.notebook.select(1)
        
    def start_scan(self):
        """Start the subdomain scan."""
        domain = self.domain_var.get().strip()
        if not domain or '.' not in domain:
            messagebox.showerror("Error", "Please enter a valid domain")
            return
            
        # Check if at least one method is selected
        if not any(self.methods[method].get() for method in self.methods):
            messagebox.showerror("Error", "Please select at least one discovery method")
            return
            
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.found_subdomains = []
        self.scan_stats = {'total_tested': 0, 'total_found': 0, 'method_results': {}}
        
        # Start scan
        self.is_scanning = True
        self.start_time = time.time()
        
        # Update UI
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress_bar.start()
        self.update_progress("Starting scan...")
        self.status_var.set("Scanning...")
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop the current scan."""
        self.is_scanning = False
        self.log_message("Scan stopped by user", "WARNING")
        self.scan_finished()
        
    def clear_results(self):
        """Clear the results area."""
        self.results_text.delete(1.0, tk.END)
        self.found_subdomains = []
        self.scan_stats = {'total_tested': 0, 'total_found': 0, 'method_results': {}}
        self.update_stats()
        self.status_var.set("Results cleared")
        
    def export_results(self):
        """Export results to file."""
        if not self.found_subdomains:
            messagebox.showwarning("Warning", "No results to export")
            return
            
        try:
            output_file = self.output_file_var.get()
            
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_file)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_file, 'w') as f:
                f.write(f"# Subdomain enumeration results for {self.domain_var.get()}\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total found: {len(self.found_subdomains)}\n")
                f.write(f"# Methods used: {', '.join([m for m in self.methods if self.methods[m].get()])}\n\n")
                
                for subdomain in sorted(self.found_subdomains):
                    f.write(f"{subdomain}\n")
                    
            messagebox.showinfo("Success", f"Results exported to {output_file}")
            self.status_var.set(f"Results exported to {output_file}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {e}")
            
    def open_documentation(self):
        """Open documentation in browser."""
        webbrowser.open("https://github.com/your-repo/subdomain-searcher")
        
    def show_about(self):
        """Show about dialog."""
        about_text = """
🔍 Subdomain Searcher Pro v2.0

A modern, comprehensive subdomain enumeration tool with multiple discovery methods.

Features:
• Certificate Transparency logs
• Search engine dorking
• Passive DNS databases
• DNS brute force
• Modern GUI interface
• Real-time progress tracking
• Export capabilities

Built with Python and tkinter
        """
        messagebox.showinfo("About", about_text)

def main():
    """Main function."""
    root = tk.Tk()
    
    # Set window icon (if available)
    try:
        root.iconbitmap('icon.ico')
    except:
        pass
    
    app = ModernSubdomainSearcherGUI(root)
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
    y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
    root.geometry(f"+{x}+{y}")
    
    # Make window resizable
    root.resizable(True, True)
    
    root.mainloop()

if __name__ == "__main__":
    main() 