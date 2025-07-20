#!/usr/bin/env python3
"""
Demo script for Subdomain Searcher MVP
This script demonstrates all the features of the subdomain searcher.
"""

import subprocess
import sys
import os
import time

def run_demo():
    """Run a comprehensive demonstration of the subdomain searcher."""
    
    print("=" * 60)
    print("    SUBDOMAIN SEARCHER MVP - DEMONSTRATION")
    print("=" * 60)
    
    # Test domains
    test_domains = [
        ("google.com", "Basic scan with default wordlist"),
        ("github.com", "Scan with custom wordlist"),
        ("microsoft.com", "High-thread scan")
    ]
    
    for domain, description in test_domains:
        print(f"\n{'='*40}")
        print(f"Testing: {domain}")
        print(f"Description: {description}")
        print(f"{'='*40}")
        
        # Build command
        if domain == "github.com":
            cmd = [sys.executable, "subdomain_searcher.py", domain, "-w", "wordlist.txt", "-t", "5", "-o", f"{domain}_demo.txt"]
        elif domain == "microsoft.com":
            cmd = [sys.executable, "subdomain_searcher.py", domain, "-t", "15", "-o", f"{domain}_demo.txt"]
        else:
            cmd = [sys.executable, "subdomain_searcher.py", domain, "-t", "5"]
        
        print(f"Command: {' '.join(cmd)}")
        print()
        
        try:
            # Run the command
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            elapsed_time = time.time() - start_time
            
            if result.returncode == 0:
                print("✅ SUCCESS")
                print(f"⏱️  Time taken: {elapsed_time:.2f} seconds")
                
                # Show some results
                lines = result.stdout.split('\n')
                found_lines = [line for line in lines if '[+]' in line]
                if found_lines:
                    print(f"🔍 Found {len(found_lines)} subdomains:")
                    for line in found_lines[:3]:  # Show first 3
                        print(f"   {line.strip()}")
                    if len(found_lines) > 3:
                        print(f"   ... and {len(found_lines) - 3} more")
            else:
                print("❌ FAILED")
                print(f"Error: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print("⏰ TIMEOUT - Scan took too long")
        except Exception as e:
            print(f"❌ ERROR: {e}")
        
        print()
        time.sleep(1)  # Brief pause between tests
    
    print("=" * 60)
    print("    DEMONSTRATION COMPLETED")
    print("=" * 60)
    print("\n📁 Generated files:")
    
    # List generated files
    for file in os.listdir('.'):
        if file.endswith('_demo.txt') or file.endswith('found.txt'):
            size = os.path.getsize(file)
            print(f"   📄 {file} ({size} bytes)")
    
    if os.path.exists('output'):
        for file in os.listdir('output'):
            if file.endswith('.txt'):
                size = os.path.getsize(os.path.join('output', file))
                print(f"   📄 output/{file} ({size} bytes)")
    
    print("\n🎉 All features demonstrated successfully!")
    print("\n💡 Try running:")
    print("   python subdomain_searcher.py --help")
    print("   python subdomain_searcher.py your-domain.com")

if __name__ == "__main__":
    run_demo() 