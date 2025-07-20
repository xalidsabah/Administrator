#!/usr/bin/env python3
"""
Subdomain Searcher MVP
A fully interactive subdomain enumeration tool with DNS brute-force capabilities.
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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import colorama
from colorama import Fore, Back, Style

# Initialize colorama for cross-platform colored output
colorama.init(autoreset=True)

class SubdomainSearcher:
    def __init__(self, domain, wordlist_file=None, threads=10, output_file="output/found.txt", check_http=True, timeout=5):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.threads = threads
        self.output_file = output_file
        self.check_http = check_http
        self.timeout = timeout
        self.found_subdomains = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Default wordlist if none provided
        self.default_subdomains = [
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
            'elasticsearch', 'solr', 'kafka', 'rabbitmq', 'redis1', 'redis2', 'redis3',
            'redis4', 'redis5', 'redis6', 'redis7', 'redis8', 'redis9', 'redis10',
            'mysql1', 'mysql2', 'mysql3', 'mysql4', 'mysql5', 'mysql6', 'mysql7',
            'mysql8', 'mysql9', 'mysql10', 'postgres1', 'postgres2', 'postgres3',
            'postgres4', 'postgres5', 'postgres6', 'postgres7', 'postgres8', 'postgres9',
            'postgres10', 'mongo1', 'mongo2', 'mongo3', 'mongo4', 'mongo5', 'mongo6',
            'mongo7', 'mongo8', 'mongo9', 'mongo10', 'elasticsearch1', 'elasticsearch2',
            'elasticsearch3', 'elasticsearch4', 'elasticsearch5', 'elasticsearch6',
            'elasticsearch7', 'elasticsearch8', 'elasticsearch9', 'elasticsearch10',
            'solr1', 'solr2', 'solr3', 'solr4', 'solr5', 'solr6', 'solr7', 'solr8',
            'solr9', 'solr10', 'kafka1', 'kafka2', 'kafka3', 'kafka4', 'kafka5',
            'kafka6', 'kafka7', 'kafka8', 'kafka9', 'kafka10', 'rabbitmq1', 'rabbitmq2',
            'rabbitmq3', 'rabbitmq4', 'rabbitmq5', 'rabbitmq6', 'rabbitmq7', 'rabbitmq8',
            'rabbitmq9', 'rabbitmq10', 'memcached1', 'memcached2', 'memcached3',
            'memcached4', 'memcached5', 'memcached6', 'memcached7', 'memcached8',
            'memcached9', 'memcached10', 'jenkins', 'gitlab', 'github', 'bitbucket',
            'jira', 'confluence', 'sonar', 'nexus', 'artifactory', 'docker', 'kubernetes',
            'k8s', 'helm', 'prometheus', 'grafana', 'kibana', 'logstash', 'filebeat',
            'metricbeat', 'packetbeat', 'heartbeat', 'auditbeat', 'functionbeat',
            'apm-server', 'elasticsearch', 'kibana', 'logstash', 'beats', 'x-pack',
            'security', 'monitoring', 'alerting', 'reporting', 'graph', 'ml', 'watcher',
            'rollup', 'transform', 'index-lifecycle-management', 'snapshot-lifecycle-management',
            'cross-cluster-replication', 'cross-cluster-search', 'remote-clusters',
            'remote-cluster', 'remote', 'cluster', 'node', 'nodes', 'master', 'data',
            'client', 'coordinating', 'ingest', 'ml', 'transform', 'rollup', 'watcher',
            'security', 'monitoring', 'alerting', 'reporting', 'graph', 'ml', 'watcher',
            'rollup', 'transform', 'index-lifecycle-management', 'snapshot-lifecycle-management',
            'cross-cluster-replication', 'cross-cluster-search', 'remote-clusters',
            'remote-cluster', 'remote', 'cluster', 'node', 'nodes', 'master', 'data',
            'client', 'coordinating', 'ingest', 'ml', 'transform', 'rollup', 'watcher'
        ]

    def load_wordlist(self):
        """Load subdomains from wordlist file or use default list."""
        if self.wordlist_file and os.path.exists(self.wordlist_file):
            try:
                with open(self.wordlist_file, 'r') as f:
                    return [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to load wordlist: {e}")
                return self.default_subdomains
        else:
            if self.wordlist_file:
                print(f"{Fore.YELLOW}[WARNING] Wordlist file not found, using default list")
            return self.default_subdomains

    def check_subdomain(self, subdomain):
        """Check if a subdomain exists using DNS resolution and optionally HTTP connectivity."""
        full_domain = f"{subdomain}.{self.domain}"
        
        # First check DNS resolution
        try:
            answers = dns.resolver.resolve(full_domain, 'A')
            if answers:
                ip_addresses = [str(answer) for answer in answers]
                
                # If HTTP checking is enabled, verify connectivity
                if self.check_http:
                    http_status = self.check_http_connectivity(full_domain, ip_addresses[0])
                    return True, full_domain, ip_addresses, http_status
                else:
                    return True, full_domain, ip_addresses, "DNS_ONLY"
                    
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException:
            pass
        except Exception as e:
            pass
        
        return False, full_domain, [], "NOT_FOUND"

    def check_http_connectivity(self, domain, ip_address):
        """Check if the subdomain is accessible via HTTP/HTTPS."""
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{domain}"
                response = requests.get(url, timeout=self.timeout, allow_redirects=True)
                if response.status_code < 400:  # 2xx and 3xx status codes
                    return f"{protocol.upper()}_{response.status_code}"
            except requests.exceptions.SSLError:
                # SSL error but connection established
                return f"{protocol.upper()}_SSL_ERROR"
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        # Try socket connection as fallback
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, 80))
            sock.close()
            if result == 0:
                return "SOCKET_80"
        except:
            pass
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, 443))
            sock.close()
            if result == 0:
                return "SOCKET_443"
        except:
            pass
        
        return "NO_HTTP"

    def process_subdomain(self, subdomain):
        """Process a single subdomain and display results."""
        exists, full_domain, ip_addresses, http_status = self.check_subdomain(subdomain)
        
        if exists:
            with self.lock:
                self.found_subdomains.append((full_domain, ip_addresses, http_status))
                elapsed_time = time.time() - self.start_time
                
                # Color code based on HTTP status
                if http_status.startswith(('HTTPS_', 'HTTP_')) and http_status != 'HTTP_SSL_ERROR':
                    status_color = Fore.GREEN
                    status_icon = "🌐"
                elif http_status in ['SOCKET_80', 'SOCKET_443']:
                    status_color = Fore.YELLOW
                    status_icon = "🔌"
                elif http_status == 'DNS_ONLY':
                    status_color = Fore.BLUE
                    status_icon = "📡"
                else:
                    status_color = Fore.RED
                    status_icon = "❌"
                
                print(f"{Fore.GREEN}[+] {Fore.WHITE}{full_domain} {Fore.CYAN}({', '.join(ip_addresses)}) {status_color}[{http_status}] {status_icon} {Fore.YELLOW}[{elapsed_time:.2f}s]")
        
        return exists, full_domain, ip_addresses, http_status

    def save_results(self):
        """Save found subdomains to output file."""
        try:
            with open(self.output_file, 'w') as f:
                f.write(f"# Subdomain enumeration results for {self.domain}\n")
                f.write(f"# Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Total found: {len(self.found_subdomains)}\n")
                f.write(f"# HTTP checking: {'Enabled' if self.check_http else 'Disabled'}\n\n")
                
                for subdomain, ip_addresses, http_status in self.found_subdomains:
                    f.write(f"{subdomain} - {', '.join(ip_addresses)} - {http_status}\n")
            
            print(f"\n{Fore.GREEN}[SUCCESS] Results saved to: {self.output_file}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save results: {e}")

    def run(self):
        """Main execution method."""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}    SUBDOMAIN SEARCHER MVP")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Target Domain: {Fore.YELLOW}{self.domain}")
        print(f"{Fore.WHITE}Threads: {Fore.YELLOW}{self.threads}")
        print(f"{Fore.WHITE}HTTP Checking: {Fore.YELLOW}{'Enabled' if self.check_http else 'Disabled'}")
        print(f"{Fore.WHITE}Timeout: {Fore.YELLOW}{self.timeout}s")
        print(f"{Fore.WHITE}Output File: {Fore.YELLOW}{self.output_file}")
        print(f"{Fore.CYAN}{'='*60}\n")

        # Load wordlist
        subdomains = self.load_wordlist()
        print(f"{Fore.WHITE}Loaded {Fore.YELLOW}{len(subdomains)}{Fore.WHITE} subdomains to test\n")
        
        # Start enumeration
        print(f"{Fore.CYAN}[INFO] Starting subdomain enumeration...\n")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all subdomain checks
            future_to_subdomain = {executor.submit(self.process_subdomain, subdomain): subdomain 
                                 for subdomain in subdomains}
            
            # Process completed tasks
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Exception processing {subdomain}: {e}")

        # Display summary
        elapsed_time = time.time() - self.start_time
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Enumeration completed!")
        print(f"{Fore.WHITE}Total subdomains tested: {Fore.YELLOW}{len(subdomains)}")
        print(f"{Fore.WHITE}Subdomains found: {Fore.GREEN}{len(self.found_subdomains)}")
        print(f"{Fore.WHITE}Time elapsed: {Fore.YELLOW}{elapsed_time:.2f} seconds")
        
        # Show status breakdown
        if self.found_subdomains:
            status_counts = {}
            for _, _, status in self.found_subdomains:
                status_counts[status] = status_counts.get(status, 0) + 1
            
            print(f"\n{Fore.WHITE}Status Breakdown:")
            for status, count in status_counts.items():
                if status.startswith(('HTTPS_', 'HTTP_')) and status != 'HTTP_SSL_ERROR':
                    color = Fore.GREEN
                elif status in ['SOCKET_80', 'SOCKET_443']:
                    color = Fore.YELLOW
                elif status == 'DNS_ONLY':
                    color = Fore.BLUE
                else:
                    color = Fore.RED
                print(f"  {color}{status}: {count}")
        
        print(f"{Fore.CYAN}{'='*60}")

        # Save results
        if self.found_subdomains:
            self.save_results()
        else:
            print(f"\n{Fore.YELLOW}[INFO] No subdomains found for {self.domain}")

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Searcher MVP - DNS brute-force subdomain enumeration tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_searcher.py example.com
  python subdomain_searcher.py example.com -w wordlist.txt
  python subdomain_searcher.py example.com -t 20 -o results.txt
        """
    )
    
    parser.add_argument('domain', help='Target domain (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Path to wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', default='output/found.txt', help='Output file path (default: output/found.txt)')
    parser.add_argument('--no-http', action='store_true', help='Disable HTTP connectivity checking (DNS only)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout for HTTP requests in seconds (default: 5)')
    
    args = parser.parse_args()
    
    # Validate domain format
    if not args.domain or '.' not in args.domain:
        print(f"{Fore.RED}[ERROR] Invalid domain format. Please provide a valid domain (e.g., example.com)")
        sys.exit(1)
    
    # Create and run searcher
    searcher = SubdomainSearcher(
        domain=args.domain,
        wordlist_file=args.wordlist,
        threads=args.threads,
        output_file=args.output,
        check_http=not args.no_http,
        timeout=args.timeout
    )
    
    try:
        searcher.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Enumeration interrupted by user")
        if searcher.found_subdomains:
            searcher.save_results()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 