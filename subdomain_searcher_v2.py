#!/usr/bin/env python3
"""
Subdomain Searcher V2 - Multi-Method Enumeration
Advanced subdomain enumeration using multiple techniques:
1. Certificate Transparency Logs
2. Search Engine Dorking
3. Passive DNS
4. DNS Brute Force (original method)
5. Reverse IP Lookup
"""

import argparse
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
import colorama
from colorama import Fore, Back, Style
from urllib.parse import urlparse, quote
import ssl
import OpenSSL.crypto

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class AdvancedSubdomainSearcher:
    def __init__(self, domain, threads=10, output_file="output/advanced_found.txt", timeout=10):
        self.domain = domain
        self.threads = threads
        self.output_file = output_file
        self.timeout = timeout
        self.found_subdomains = set()  # Use set to avoid duplicates
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
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

    def certificate_transparency_search(self):
        """Search for subdomains using Certificate Transparency logs."""
        print(f"{Fore.CYAN}[INFO] Searching Certificate Transparency logs...")
        
        ct_apis = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
        ]
        
        subdomains = set()
        
        for api_url in ct_apis:
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    if 'crt.sh' in api_url:
                        # Parse crt.sh JSON response
                        data = response.json()
                        for entry in data:
                            if 'name_value' in entry:
                                names = entry['name_value'].split('\n')
                                for name in names:
                                    name = name.strip().lower()
                                    if name.endswith(f'.{self.domain}') and '*' not in name:
                                        subdomains.add(name)
                    
                    elif 'certspotter' in api_url:
                        # Parse certspotter JSON response
                        data = response.json()
                        for cert in data:
                            if 'dns_names' in cert:
                                for dns_name in cert['dns_names']:
                                    dns_name = dns_name.lower()
                                    if dns_name.endswith(f'.{self.domain}') and '*' not in dns_name:
                                        subdomains.add(dns_name)
                                        
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] CT search failed for {api_url}: {e}")
        
        return subdomains

    def search_engine_dorking(self):
        """Search for subdomains using search engine dorks."""
        print(f"{Fore.CYAN}[INFO] Performing search engine dorking...")
        
        search_engines = [
            f"https://www.google.com/search?q=site:{self.domain}",
            f"https://www.bing.com/search?q=site:{self.domain}",
            f"https://search.yahoo.com/search?p=site:{self.domain}"
        ]
        
        subdomains = set()
        
        for search_url in search_engines:
            try:
                headers = {
                    'User-Agent': self.get_random_user_agent(),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                }
                
                response = requests.get(search_url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Extract subdomains from search results
                    content = response.text.lower()
                    
                    # Look for subdomain patterns
                    pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(self.domain)}'
                    matches = re.findall(pattern, content)
                    
                    for match in matches:
                        if match[0].endswith(f'.{self.domain}') and '*' not in match[0]:
                            subdomains.add(match[0])
                            
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Search engine dorking failed for {search_url}: {e}")
        
        return subdomains

    def passive_dns_search(self):
        """Search for subdomains using passive DNS services."""
        print(f"{Fore.CYAN}[INFO] Searching passive DNS databases...")
        
        passive_dns_apis = [
            f"https://dns.bufferover.run/dns?q=.{self.domain}",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        ]
        
        subdomains = set()
        
        for api_url in passive_dns_apis:
            try:
                headers = {'User-Agent': self.get_random_user_agent()}
                response = requests.get(api_url, headers=headers, timeout=self.timeout)
                
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract subdomains from response
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if line and '.' in line:
                            # Handle different response formats
                            if ',' in line:
                                # Format: subdomain,ip
                                parts = line.split(',')
                                if len(parts) >= 1:
                                    subdomain = parts[0].lower()
                                    if subdomain.endswith(f'.{self.domain}') and '*' not in subdomain:
                                        subdomains.add(subdomain)
                            else:
                                # Format: subdomain
                                if line.endswith(f'.{self.domain}') and '*' not in line:
                                    subdomains.add(line.lower())
                                    
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Passive DNS search failed for {api_url}: {e}")
        
        return subdomains

    def reverse_ip_lookup(self):
        """Perform reverse IP lookup to find subdomains."""
        print(f"{Fore.CYAN}[INFO] Performing reverse IP lookup...")
        
        subdomains = set()
        
        try:
            # Get IP of main domain
            main_ip = socket.gethostbyname(self.domain)
            
            # Use reverse IP lookup services
            reverse_apis = [
                f"https://api.hackertarget.com/reverseiplookup/?q={main_ip}",
                f"https://domains.yougetsignal.com/domains.php?remoteAddress={main_ip}"
            ]
            
            for api_url in reverse_apis:
                try:
                    headers = {'User-Agent': self.get_random_user_agent()}
                    response = requests.get(api_url, headers=headers, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # Extract domains from response
                        pattern = rf'([a-zA-Z0-9]([a-zA-Z0-9\-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(self.domain)}'
                        matches = re.findall(pattern, content)
                        
                        for match in matches:
                            if match[0].endswith(f'.{self.domain}') and '*' not in match[0]:
                                subdomains.add(match[0].lower())
                                
                except Exception as e:
                    print(f"{Fore.YELLOW}[WARNING] Reverse IP lookup failed for {api_url}: {e}")
                    
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Could not resolve main domain IP: {e}")
        
        return subdomains

    def dns_brute_force(self, wordlist_file=None):
        """Original DNS brute force method."""
        print(f"{Fore.CYAN}[INFO] Performing DNS brute force...")
        
        # Default wordlist
        default_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'dns1', 'dns2', 'admin', 'forum', 'blog', 'dev', 'test', 'stage', 'api',
            'cdn', 'static', 'media', 'img', 'images', 'css', 'js', 'assets', 'cdn1',
            'cdn2', 'cdn3', 'cdn4', 'cdn5', 'cdn6', 'cdn7', 'cdn8', 'cdn9', 'cdn10',
            'm', 'mobile', 'wap', 'app', 'apps', 'secure', 'ssl', 'vpn', 'remote',
            'support', 'help', 'docs', 'wiki', 'status', 'monitor', 'stats', 'analytics',
            'tracking', 'track', 'pixel', 'beacon', 'webhook', 'hook', 'callback',
            'auth', 'login', 'logout', 'signin', 'signout', 'register', 'signup',
            'dashboard', 'panel', 'admin', 'administrator', 'root', 'master', 'control',
            'manage', 'management', 'console', 'terminal', 'shell', 'ssh', 'telnet',
            'rdp', 'vnc', 'remote', 'gateway', 'proxy', 'cache', 'loadbalancer',
            'lb', 'loadbalancer1', 'loadbalancer2', 'loadbalancer3', 'loadbalancer4',
            'db', 'database', 'mysql', 'postgres', 'mongo', 'redis', 'memcached',
            'elasticsearch', 'solr', 'kafka', 'rabbitmq', 'jenkins', 'gitlab', 'github',
            'bitbucket', 'jira', 'confluence', 'sonar', 'nexus', 'artifactory', 'docker',
            'kubernetes', 'k8s', 'helm', 'prometheus', 'grafana', 'kibana', 'logstash'
        ]
        
        # Load wordlist
        if wordlist_file and os.path.exists(wordlist_file):
            try:
                with open(wordlist_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                print(f"{Fore.YELLOW}[WARNING] Failed to load wordlist, using default: {e}")
                subdomains = default_subdomains
        else:
            subdomains = default_subdomains
        
        found_subdomains = set()
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    return full_domain
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {executor.submit(check_subdomain, subdomain): subdomain 
                                 for subdomain in subdomains}
            
            for future in as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    found_subdomains.add(result)
        
        return found_subdomains

    def verify_subdomain(self, subdomain):
        """Verify if a subdomain is actually accessible."""
        try:
            # DNS resolution
            answers = dns.resolver.resolve(subdomain, 'A')
            if answers:
                ip_addresses = [str(answer) for answer in answers]
                
                # HTTP connectivity check
                for protocol in ['https', 'http']:
                    try:
                        url = f"{protocol}://{subdomain}"
                        response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                        if response.status_code < 400:
                            return True, subdomain, ip_addresses, f"{protocol.upper()}_{response.status_code}"
                    except:
                        continue
                
                return True, subdomain, ip_addresses, "DNS_ONLY"
                
        except:
            pass
        
        return False, subdomain, [], "NOT_FOUND"

    def display_results(self, method, subdomains):
        """Display results for a specific method."""
        if subdomains:
            print(f"{Fore.GREEN}[+] {method}: Found {len(subdomains)} subdomains")
            for subdomain in sorted(subdomains)[:5]:  # Show first 5
                print(f"   {Fore.CYAN}{subdomain}")
            if len(subdomains) > 5:
                print(f"   {Fore.YELLOW}... and {len(subdomains) - 5} more")
        else:
            print(f"{Fore.YELLOW}[-] {method}: No subdomains found")

    def save_results(self):
        """Save all found subdomains to output file."""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"# Advanced subdomain enumeration results for {self.domain}\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total unique subdomains found: {len(self.found_subdomains)}\n")
                f.write(f"# Methods used: CT Logs, Search Engines, Passive DNS, Reverse IP, DNS Brute Force\n\n")
                
                for subdomain in sorted(self.found_subdomains):
                    f.write(f"{subdomain}\n")
            
            print(f"\n{Fore.GREEN}[SUCCESS] Results saved to: {self.output_file}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save results: {e}")

    def run(self, methods=None):
        """Run the advanced subdomain enumeration."""
        if methods is None:
            methods = ['ct', 'search', 'passive', 'reverse', 'brute']
        
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}    ADVANCED SUBDOMAIN SEARCHER V2")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}Target Domain: {Fore.YELLOW}{self.domain}")
        print(f"{Fore.WHITE}Threads: {Fore.YELLOW}{self.threads}")
        print(f"{Fore.WHITE}Methods: {Fore.YELLOW}{', '.join(methods)}")
        print(f"{Fore.WHITE}Output File: {Fore.YELLOW}{self.output_file}")
        print(f"{Fore.CYAN}{'='*70}\n")

        # Run each method
        method_results = {}
        
        if 'ct' in methods:
            ct_results = self.certificate_transparency_search()
            method_results['Certificate Transparency'] = ct_results
            self.found_subdomains.update(ct_results)
            self.display_results('Certificate Transparency', ct_results)
            print()

        if 'search' in methods:
            search_results = self.search_engine_dorking()
            method_results['Search Engine Dorking'] = search_results
            self.found_subdomains.update(search_results)
            self.display_results('Search Engine Dorking', search_results)
            print()

        if 'passive' in methods:
            passive_results = self.passive_dns_search()
            method_results['Passive DNS'] = passive_results
            self.found_subdomains.update(passive_results)
            self.display_results('Passive DNS', passive_results)
            print()

        if 'reverse' in methods:
            reverse_results = self.reverse_ip_lookup()
            method_results['Reverse IP Lookup'] = reverse_results
            self.found_subdomains.update(reverse_results)
            self.display_results('Reverse IP Lookup', reverse_results)
            print()

        if 'brute' in methods:
            brute_results = self.dns_brute_force()
            method_results['DNS Brute Force'] = brute_results
            self.found_subdomains.update(brute_results)
            self.display_results('DNS Brute Force', brute_results)
            print()

        # Display summary
        elapsed_time = time.time() - self.start_time
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}Enumeration completed!")
        print(f"{Fore.WHITE}Total unique subdomains found: {Fore.GREEN}{len(self.found_subdomains)}")
        print(f"{Fore.WHITE}Time elapsed: {Fore.YELLOW}{elapsed_time:.2f} seconds")
        
        # Show breakdown by method
        print(f"\n{Fore.WHITE}Results by method:")
        for method, results in method_results.items():
            print(f"  {Fore.CYAN}{method}: {Fore.YELLOW}{len(results)} subdomains")
        
        print(f"{Fore.CYAN}{'='*70}")

        # Save results
        if self.found_subdomains:
            self.save_results()
        else:
            print(f"\n{Fore.YELLOW}[INFO] No subdomains found for {self.domain}")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Subdomain Searcher V2 - Multi-method enumeration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Methods:
  ct      - Certificate Transparency logs
  search  - Search engine dorking
  passive - Passive DNS databases
  reverse - Reverse IP lookup
  brute   - DNS brute force

Examples:
  python subdomain_searcher_v2.py example.com
  python subdomain_searcher_v2.py example.com --methods ct,search,passive
  python subdomain_searcher_v2.py example.com --methods brute -t 20
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('--methods', default='ct,search,passive,reverse,brute',
                       help='Comma-separated list of methods to use (default: all)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', default='output/advanced_found.txt', 
                       help='Output file path (default: output/advanced_found.txt)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for requests in seconds (default: 10)')
    
    args = parser.parse_args()
    
    # Validate domain format
    if not args.domain or '.' not in args.domain:
        print(f"{Fore.RED}[ERROR] Invalid domain format. Please provide a valid domain (e.g., example.com)")
        sys.exit(1)
    
    # Parse methods
    methods = [m.strip() for m in args.methods.split(',')]
    valid_methods = ['ct', 'search', 'passive', 'reverse', 'brute']
    invalid_methods = [m for m in methods if m not in valid_methods]
    
    if invalid_methods:
        print(f"{Fore.RED}[ERROR] Invalid methods: {', '.join(invalid_methods)}")
        print(f"{Fore.YELLOW}Valid methods: {', '.join(valid_methods)}")
        sys.exit(1)
    
    # Create and run searcher
    searcher = AdvancedSubdomainSearcher(
        domain=args.domain,
        threads=args.threads,
        output_file=args.output,
        timeout=args.timeout
    )
    
    try:
        searcher.run(methods)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Enumeration interrupted by user")
        if searcher.found_subdomains:
            searcher.save_results()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 