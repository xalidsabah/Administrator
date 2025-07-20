#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Subdomain Searcher Web Interface
A modern web-based interface for subdomain enumeration with real-time results.
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
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
import uuid
from urllib.parse import urlparse, quote
import ssl
import OpenSSL.crypto

app = Flask(__name__)
app.secret_key = 'subdomain_searcher_secret_key'

# Global storage for scan results
scan_results = {}

class WebSubdomainSearcher:
    def __init__(self, domain, scan_id, methods=None):
        self.domain = domain
        self.scan_id = scan_id
        self.methods = methods or ['ct', 'search', 'passive', 'reverse', 'brute']
        self.found_subdomains = set()
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.is_running = True
        
        # User agents for web requests
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    def get_random_user_agent(self):
        """Get a random user agent."""
        import random
        return random.choice(self.user_agents)

    def update_progress(self, method, status, count=0):
        """Update scan progress."""
        if self.scan_id in scan_results:
            scan_results[self.scan_id]['progress'][method] = {
                'status': status,
                'count': count,
                'timestamp': datetime.now().isoformat()
            }

    def certificate_transparency_search(self):
        """Search for subdomains using Certificate Transparency logs."""
        self.update_progress('ct', 'running')
        
        ct_apis = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        subdomains = set()
        
        for api_url in ct_apis:
            if not self.is_running:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    if 'crt.sh' in api_url:
                        data = response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{self.domain}') and '*' not in name:
                                        subdomains.add(name)
                    
                    elif 'certspotter' in api_url:
                        data = response.json()
                        for cert in data:
                            if 'dns_names' in cert:
                                for dns_name in cert['dns_names']:
                                    dns_name = dns_name.lower()
                                    if dns_name.endswith(f'.{self.domain}') and '*' not in dns_name:
                                        subdomains.add(dns_name)
                                        
            except Exception as e:
                print(f"CT search failed for {api_url}: {e}")
        
        self.update_progress('ct', 'completed', len(subdomains))
        return subdomains

    def search_engine_dorking(self):
        """Search for subdomains using search engine dorks."""
        self.update_progress('search', 'running')
        
        search_engines = [
            f"https://www.google.com/search?q=site:{self.domain}",
            f"https://www.bing.com/search?q=site:{self.domain}"
        ]
        
        subdomains = set()
        
        for search_url in search_engines:
            if not self.is_running:
                break
                
            try:
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                response = requests.get(search_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    content = response.text.lower()
                    pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(self.domain)}'
                    matches = re.findall(pattern, content)
                    
                    for match in matches:
                        if match[0].endswith(f'.{self.domain}') and '*' not in match[0]:
                            subdomains.add(match[0])
                            
            except Exception as e:
                print(f"Search engine dorking failed for {search_url}: {e}")
        
        self.update_progress('search', 'completed', len(subdomains))
        return subdomains

    def passive_dns_search(self):
        """Search for subdomains using passive DNS services."""
        self.update_progress('passive', 'running')
        
        passive_dns_apis = [
            f"https://dns.bufferover.run/dns?q=.{self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        
        subdomains = set()
        
        for api_url in passive_dns_apis:
            if not self.is_running:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=10)
                
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
                                    if subdomain.endswith(f'.{self.domain}') and '*' not in subdomain:
                                        subdomains.add(subdomain)
                            else:
                                if line.endswith(f'.{self.domain}') and '*' not in line:
                                    subdomains.add(line.lower())
                                    
            except Exception as e:
                print(f"Passive DNS search failed for {api_url}: {e}")
        
        self.update_progress('passive', 'completed', len(subdomains))
        return subdomains

    def dns_brute_force(self):
        """DNS brute force method."""
        self.update_progress('brute', 'running')
        
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
            if not self.is_running:
                return None
                
            full_domain = f"{subdomain}.{self.domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain 
                                 for subdomain in default_subdomains}
            
            for future in as_completed(future_to_subdomain):
                if not self.is_running:
                    break
                    
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        self.update_progress('brute', 'completed', len(found_subdomains))
        return found_subdomains

    def run(self):
        """Run the subdomain enumeration."""
        method_results = {}
        
        if 'ct' in self.methods:
            ct_results = self.certificate_transparency_search()
            method_results['Certificate Transparency'] = ct_results
            self.found_subdomains.update(ct_results)

        if 'search' in self.methods and self.is_running:
            search_results = self.search_engine_dorking()
            method_results['Search Engine Dorking'] = search_results
            self.found_subdomains.update(search_results)

        if 'passive' in self.methods and self.is_running:
            passive_results = self.passive_dns_search()
            method_results['Passive DNS'] = passive_results
            self.found_subdomains.update(passive_results)

        if 'brute' in self.methods and self.is_running:
            brute_results = self.dns_brute_force()
            method_results['DNS Brute Force'] = brute_results
            self.found_subdomains.update(brute_results)

        # Update final results
        if self.scan_id in scan_results:
            scan_results[self.scan_id]['status'] = 'completed'
            scan_results[self.scan_id]['total_found'] = len(self.found_subdomains)
            scan_results[self.scan_id]['subdomains'] = list(self.found_subdomains)
            scan_results[self.scan_id]['method_results'] = {k: list(v) for k, v in method_results.items()}
            scan_results[self.scan_id]['elapsed_time'] = time.time() - self.start_time

    def stop(self):
        """Stop the scan."""
        self.is_running = False

@app.route('/')
def index():
    """Main page."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new subdomain scan."""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    methods = data.get('methods', ['ct', 'search', 'passive', 'brute'])
    
    if not domain or '.' not in domain:
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Initialize scan results
    scan_results[scan_id] = {
        'domain': domain,
        'methods': methods,
        'status': 'running',
        'progress': {},
        'total_found': 0,
        'subdomains': [],
        'method_results': {},
        'elapsed_time': 0,
        'start_time': datetime.now().isoformat()
    }
    
    # Initialize progress for each method
    for method in methods:
        scan_results[scan_id]['progress'][method] = {
            'status': 'pending',
            'count': 0,
            'timestamp': datetime.now().isoformat()
        }
    
    # Start scan in background thread
    searcher = WebSubdomainSearcher(domain, scan_id, methods)
    thread = threading.Thread(target=searcher.run)
    thread.daemon = True
    thread.start()
    
    return jsonify({'scan_id': scan_id, 'status': 'started'})

@app.route('/api/scan/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status and results."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    return jsonify(scan_results[scan_id])

@app.route('/api/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_results[scan_id]['status'] = 'stopped'
    return jsonify({'status': 'stopped'})

@app.route('/api/scans')
def list_scans():
    """List all scans."""
    return jsonify({
        'scans': [
            {
                'id': scan_id,
                'domain': data['domain'],
                'status': data['status'],
                'total_found': data['total_found'],
                'start_time': data['start_time']
            }
            for scan_id, data in scan_results.items()
        ]
    })

if __name__ == '__main__':
    # Fix Windows encoding issues
    import sys
    import locale
    
    # Set UTF-8 encoding for stdout/stderr
    if sys.platform.startswith('win'):
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    
    # Create templates directory and HTML file
    os.makedirs('templates', exist_ok=True)
    
    html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Searcher Web</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 30px;
        }
        
        .scan-form {
            background: #f8f9fa;
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }
        
        .form-group input[type="text"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input[type="text"]:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .methods-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 10px;
        }
        
        .method-checkbox {
            display: flex;
            align-items: center;
            padding: 10px;
            background: white;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .method-checkbox:hover {
            border-color: #667eea;
            background: #f8f9ff;
        }
        
        .method-checkbox input[type="checkbox"] {
            margin-right: 10px;
            transform: scale(1.2);
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .results-section {
            margin-top: 30px;
        }
        
        .progress-container {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        
        .progress-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #e1e5e9;
        }
        
        .progress-item:last-child {
            border-bottom: none;
        }
        
        .status-badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .status-pending { background: #ffeaa7; color: #d63031; }
        .status-running { background: #74b9ff; color: white; }
        .status-completed { background: #00b894; color: white; }
        .status-error { background: #e17055; color: white; }
        
        .subdomains-list {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .subdomain-item {
            padding: 8px 12px;
            background: white;
            margin-bottom: 8px;
            border-radius: 6px;
            border-left: 4px solid #667eea;
            font-family: 'Courier New', monospace;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .stat-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .hidden {
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Subdomain Searcher</h1>
            <p>Advanced subdomain enumeration with multiple discovery methods</p>
        </div>
        
        <div class="content">
            <div class="scan-form">
                <div class="form-group">
                    <label for="domain">Target Domain:</label>
                    <input type="text" id="domain" placeholder="example.com" value="google.com">
                </div>
                
                <div class="form-group">
                    <label>Discovery Methods:</label>
                    <div class="methods-grid">
                        <div class="method-checkbox">
                            <input type="checkbox" id="ct" value="ct" checked>
                            <label for="ct">Certificate Transparency</label>
                        </div>
                        <div class="method-checkbox">
                            <input type="checkbox" id="search" value="search" checked>
                            <label for="search">Search Engines</label>
                        </div>
                        <div class="method-checkbox">
                            <input type="checkbox" id="passive" value="passive" checked>
                            <label for="passive">Passive DNS</label>
                        </div>
                        <div class="method-checkbox">
                            <input type="checkbox" id="brute" value="brute" checked>
                            <label for="brute">DNS Brute Force</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn" id="startScan">🚀 Start Scan</button>
                <button class="btn" id="stopScan" style="display: none; background: #e17055;">⏹️ Stop Scan</button>
            </div>
            
            <div class="results-section hidden" id="resultsSection">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number" id="totalFound">0</div>
                        <div class="stat-label">Subdomains Found</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="elapsedTime">0s</div>
                        <div class="stat-label">Time Elapsed</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" id="scanStatus">Idle</div>
                        <div class="stat-label">Scan Status</div>
                    </div>
                </div>
                
                <div class="progress-container">
                    <h3>📊 Scan Progress</h3>
                    <div id="progressContainer"></div>
                </div>
                
                <div class="subdomains-list">
                    <h3>🎯 Found Subdomains</h3>
                    <div id="subdomainsList"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentScanId = null;
        let statusInterval = null;
        
        document.getElementById('startScan').addEventListener('click', startScan);
        document.getElementById('stopScan').addEventListener('click', stopScan);
        
        function startScan() {
            const domain = document.getElementById('domain').value.trim();
            if (!domain) {
                alert('Please enter a domain');
                return;
            }
            
            const methods = Array.from(document.querySelectorAll('input[type="checkbox"]:checked'))
                .map(cb => cb.value);
            
            if (methods.length === 0) {
                alert('Please select at least one discovery method');
                return;
            }
            
            // Update UI
            document.getElementById('startScan').style.display = 'none';
            document.getElementById('stopScan').style.display = 'inline-block';
            document.getElementById('resultsSection').classList.remove('hidden');
            
            // Start scan
            fetch('/api/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    methods: methods
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.scan_id) {
                    currentScanId = data.scan_id;
                    startStatusPolling();
                } else {
                    alert('Error starting scan: ' + data.error);
                    resetUI();
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error starting scan');
                resetUI();
            });
        }
        
        function stopScan() {
            if (currentScanId) {
                fetch(`/api/scan/${currentScanId}/stop`, {
                    method: 'POST'
                })
                .then(response => response.json())
                .then(data => {
                    console.log('Scan stopped');
                })
                .catch(error => {
                    console.error('Error stopping scan:', error);
                });
            }
            resetUI();
        }
        
        function startStatusPolling() {
            if (statusInterval) {
                clearInterval(statusInterval);
            }
            
            statusInterval = setInterval(() => {
                if (currentScanId) {
                    fetch(`/api/scan/${currentScanId}`)
                        .then(response => response.json())
                        .then(data => {
                            updateUI(data);
                            
                            if (data.status === 'completed' || data.status === 'stopped') {
                                clearInterval(statusInterval);
                                resetUI();
                            }
                        })
                        .catch(error => {
                            console.error('Error fetching status:', error);
                        });
                }
            }, 2000);
        }
        
        function updateUI(data) {
            // Update stats
            document.getElementById('totalFound').textContent = data.total_found || 0;
            document.getElementById('elapsedTime').textContent = 
                data.elapsed_time ? Math.round(data.elapsed_time) + 's' : '0s';
            document.getElementById('scanStatus').textContent = data.status || 'Idle';
            
            // Update progress
            const progressContainer = document.getElementById('progressContainer');
            progressContainer.innerHTML = '';
            
            if (data.progress) {
                Object.entries(data.progress).forEach(([method, progress]) => {
                    const progressItem = document.createElement('div');
                    progressItem.className = 'progress-item';
                    progressItem.innerHTML = `
                        <div>
                            <strong>${method}</strong>
                            <span class="status-badge status-${progress.status}">${progress.status}</span>
                        </div>
                        <div>${progress.count} subdomains</div>
                    `;
                    progressContainer.appendChild(progressItem);
                });
            }
            
            // Update subdomains list
            const subdomainsList = document.getElementById('subdomainsList');
            subdomainsList.innerHTML = '';
            
            if (data.subdomains && data.subdomains.length > 0) {
                data.subdomains.forEach(subdomain => {
                    const subdomainItem = document.createElement('div');
                    subdomainItem.className = 'subdomain-item';
                    subdomainItem.textContent = subdomain;
                    subdomainsList.appendChild(subdomainItem);
                });
            } else {
                subdomainsList.innerHTML = '<p>No subdomains found yet...</p>';
            }
        }
        
        function resetUI() {
            document.getElementById('startScan').style.display = 'inline-block';
            document.getElementById('stopScan').style.display = 'none';
            currentScanId = null;
            
            if (statusInterval) {
                clearInterval(statusInterval);
                statusInterval = null;
            }
        }
    </script>
</body>
</html>'''
    
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    print("Starting Subdomain Searcher Web Interface...")
    print("Open your browser and go to: http://localhost:5000")
    print("The web interface provides a modern UI for subdomain enumeration")
    
    app.run(debug=True, host='0.0.0.0', port=5000) 