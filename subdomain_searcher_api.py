#!/usr/bin/env python3
"""
Subdomain Searcher API
RESTful API for subdomain enumeration that can be integrated with other tools.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
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
import argparse

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Global storage for scan results with thread safety
scan_results = {}
scan_results_lock = threading.Lock()

class APISubdomainSearcher:
    def __init__(self, domain, scan_id, methods=None, wordlist=None):
        self.domain = domain
        self.scan_id = scan_id
        self.methods = methods or ['ct', 'search', 'passive', 'brute']
        self.wordlist = wordlist or []
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

    def update_progress(self, method, status, count=0, details=None):
        """Update scan progress."""
        with scan_results_lock:
            if self.scan_id in scan_results:
                scan_results[self.scan_id]['progress'][method] = {
                    'status': status,
                    'count': count,
                    'details': details or {},
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
        details = {'sources': []}
        
        for api_url in ct_apis:
            if not self.is_running:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    source_name = 'crt.sh' if 'crt.sh' in api_url else 'certspotter'
                    source_count = 0
                    
                    if 'crt.sh' in api_url:
                        data = response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{self.domain}') and '*' not in name:
                                        subdomains.add(name)
                                        source_count += 1
                    
                    elif 'certspotter' in api_url:
                        data = response.json()
                        for cert in data:
                            if 'dns_names' in cert:
                                for dns_name in cert['dns_names']:
                                    dns_name = dns_name.lower()
                                    if dns_name.endswith(f'.{self.domain}') and '*' not in dns_name:
                                        subdomains.add(dns_name)
                                        source_count += 1
                    
                    details['sources'].append({
                        'name': source_name,
                        'url': api_url,
                        'count': source_count,
                        'status': 'success'
                    })
                else:
                    details['sources'].append({
                        'name': source_name,
                        'url': api_url,
                        'count': 0,
                        'status': f'error_{response.status_code}'
                    })
                                        
            except Exception as e:
                source_name = 'crt.sh' if 'crt.sh' in api_url else 'certspotter'
                details['sources'].append({
                    'name': source_name,
                    'url': api_url,
                    'count': 0,
                    'status': f'error_{str(e)}'
                })
        
        self.update_progress('ct', 'completed', len(subdomains), details)
        return subdomains

    def search_engine_dorking(self):
        """Search for subdomains using search engine dorks."""
        self.update_progress('search', 'running')
        
        search_engines = [
            f"https://www.google.com/search?q=site:{self.domain}",
            f"https://www.bing.com/search?q=site:{self.domain}"
        ]
        
        subdomains = set()
        details = {'sources': []}
        
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
                    
                    source_count = 0
                    for match in matches:
                        if match[0].endswith(f'.{self.domain}') and '*' not in match[0]:
                            subdomains.add(match[0])
                            source_count += 1
                    
                    source_name = 'google' if 'google' in search_url else 'bing'
                    details['sources'].append({
                        'name': source_name,
                        'url': search_url,
                        'count': source_count,
                        'status': 'success'
                    })
                else:
                    source_name = 'google' if 'google' in search_url else 'bing'
                    details['sources'].append({
                        'name': source_name,
                        'url': search_url,
                        'count': 0,
                        'status': f'error_{response.status_code}'
                    })
                            
            except Exception as e:
                source_name = 'google' if 'google' in search_url else 'bing'
                details['sources'].append({
                    'name': source_name,
                    'url': search_url,
                    'count': 0,
                    'status': f'error_{str(e)}'
                })
        
        self.update_progress('search', 'completed', len(subdomains), details)
        return subdomains

    def passive_dns_search(self):
        """Search for subdomains using passive DNS services."""
        self.update_progress('passive', 'running')
        
        passive_dns_apis = [
            f"https://dns.bufferover.run/dns?q=.{self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        
        subdomains = set()
        details = {'sources': []}
        
        for api_url in passive_dns_apis:
            if not self.is_running:
                break
                
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    content = response.text
                    lines = content.split('\n')
                    source_count = 0
                    
                    for line in lines:
                        line = line.strip()
                        if line and '.' in line:
                            if ',' in line:
                                parts = line.split(',')
                                if len(parts) >= 1:
                                    subdomain = parts[0].lower()
                                    if subdomain.endswith(f'.{self.domain}') and '*' not in subdomain:
                                        subdomains.add(subdomain)
                                        source_count += 1
                            else:
                                if line.endswith(f'.{self.domain}') and '*' not in line:
                                    subdomains.add(line.lower())
                                    source_count += 1
                    
                    source_name = 'bufferover' if 'bufferover' in api_url else 'hackertarget'
                    details['sources'].append({
                        'name': source_name,
                        'url': api_url,
                        'count': source_count,
                        'status': 'success'
                    })
                else:
                    source_name = 'bufferover' if 'bufferover' in api_url else 'hackertarget'
                    details['sources'].append({
                        'name': source_name,
                        'url': api_url,
                        'count': 0,
                        'status': f'error_{response.status_code}'
                    })
                                    
            except Exception as e:
                source_name = 'bufferover' if 'bufferover' in api_url else 'hackertarget'
                details['sources'].append({
                    'name': source_name,
                    'url': api_url,
                    'count': 0,
                    'status': f'error_{str(e)}'
                })
        
        self.update_progress('passive', 'completed', len(subdomains), details)
        return subdomains

    def dns_brute_force(self):
        """DNS brute force method."""
        self.update_progress('brute', 'running')
        
        # Use provided wordlist or default
        if self.wordlist:
            subdomains_to_test = self.wordlist
        else:
            subdomains_to_test = [
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
        details = {'tested': len(subdomains_to_test), 'found': 0}
        
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
            # Only submit tasks if scan is still running
            if self.is_running:
                future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain 
                                     for subdomain in subdomains_to_test}
                
                for future in as_completed(future_to_subdomain):
                    if not self.is_running:
                        # Cancel remaining futures to stop execution quickly
                        for remaining_future in future_to_subdomain.keys():
                            remaining_future.cancel()
                        break
                        
                    result = future.result()
                    if result:
                        found_subdomains.add(result)
                        details['found'] += 1
        
        self.update_progress('brute', 'completed', len(found_subdomains), details)
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
        with scan_results_lock:
            if self.scan_id in scan_results:
                scan_results[self.scan_id]['status'] = 'completed'
                scan_results[self.scan_id]['total_found'] = len(self.found_subdomains)
                scan_results[self.scan_id]['subdomains'] = list(self.found_subdomains)
                scan_results[self.scan_id]['method_results'] = {k: list(v) for k, v in method_results.items()}
                scan_results[self.scan_id]['elapsed_time'] = time.time() - self.start_time

    def stop(self):
        """Stop the scan."""
        self.is_running = False
        # Update status in scan results
        with scan_results_lock:
            if self.scan_id in scan_results:
                scan_results[self.scan_id]['status'] = 'stopped'

# API Routes

@app.route('/api/v1/scan', methods=['POST'])
def start_scan():
    """Start a new subdomain scan."""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    domain = data.get('domain', '').strip()
    methods = data.get('methods', ['ct', 'search', 'passive', 'brute'])
    wordlist = data.get('wordlist', [])
    
    if not domain or '.' not in domain:
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Validate methods
    valid_methods = ['ct', 'search', 'passive', 'brute']
    invalid_methods = [m for m in methods if m not in valid_methods]
    if invalid_methods:
        return jsonify({'error': f'Invalid methods: {invalid_methods}'}), 400
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Initialize scan results
    with scan_results_lock:
        scan_results[scan_id] = {
            'domain': domain,
            'methods': methods,
            'wordlist_size': len(wordlist),
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
                'details': {},
                'timestamp': datetime.now().isoformat()
            }
    
    # Start scan in background thread
    searcher = APISubdomainSearcher(domain, scan_id, methods, wordlist)
    thread = threading.Thread(target=searcher.run)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'domain': domain,
        'methods': methods,
        'message': 'Scan started successfully'
    })

@app.route('/api/v1/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get scan status and results."""
    with scan_results_lock:
        if scan_id not in scan_results:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify(scan_results[scan_id])

@app.route('/api/v1/scan/<scan_id>/stop', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan."""
    with scan_results_lock:
        if scan_id not in scan_results:
            return jsonify({'error': 'Scan not found'}), 404
        
        scan_results[scan_id]['status'] = 'stopped'
    return jsonify({'status': 'stopped', 'message': 'Scan stopped successfully'})

@app.route('/api/v1/scans', methods=['GET'])
def list_scans():
    """List all scans."""
    return jsonify({
        'scans': [
            {
                'id': scan_id,
                'domain': data['domain'],
                'status': data['status'],
                'total_found': data['total_found'],
                'start_time': data['start_time'],
                'elapsed_time': data.get('elapsed_time', 0)
            }
            for scan_id, data in scan_results.items()
        ],
        'total_scans': len(scan_results)
    })

@app.route('/api/v1/scan/<scan_id>/subdomains', methods=['GET'])
def get_subdomains(scan_id):
    """Get just the subdomains for a scan."""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan not found'}), 404
    
    data = scan_results[scan_id]
    return jsonify({
        'scan_id': scan_id,
        'domain': data['domain'],
        'subdomains': data['subdomains'],
        'total_found': data['total_found']
    })

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len([s for s in scan_results.values() if s['status'] == 'running'])
    })

@app.route('/api/v1/methods', methods=['GET'])
def get_available_methods():
    """Get available enumeration methods."""
    return jsonify({
        'methods': [
            {
                'id': 'ct',
                'name': 'Certificate Transparency',
                'description': 'Search certificate transparency logs for subdomains',
                'passive': True
            },
            {
                'id': 'search',
                'name': 'Search Engine Dorking',
                'description': 'Use search engines to find subdomains',
                'passive': True
            },
            {
                'id': 'passive',
                'name': 'Passive DNS',
                'description': 'Query passive DNS databases',
                'passive': True
            },
            {
                'id': 'brute',
                'name': 'DNS Brute Force',
                'description': 'Brute force subdomains using DNS queries',
                'passive': False
            }
        ]
    })

@app.route('/api/v1/wordlist/default', methods=['GET'])
def get_default_wordlist():
    """Get the default wordlist."""
    default_wordlist = [
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
    
    return jsonify({
        'wordlist': default_wordlist,
        'count': len(default_wordlist)
    })

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Subdomain Searcher API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5001, help='Port to bind to (default: 5001)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    print("🚀 Starting Subdomain Searcher API Server...")
    print(f"📡 API will be available at: http://{args.host}:{args.port}")
    print("📚 API Documentation:")
    print("   POST /api/v1/scan - Start a new scan")
    print("   GET  /api/v1/scan/<id> - Get scan status")
    print("   POST /api/v1/scan/<id>/stop - Stop a scan")
    print("   GET  /api/v1/scans - List all scans")
    print("   GET  /api/v1/health - Health check")
    print("   GET  /api/v1/methods - Available methods")
    print("   GET  /api/v1/wordlist/default - Default wordlist")
    
    app.run(debug=args.debug, host=args.host, port=args.port) 