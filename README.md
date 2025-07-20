# Subdomain Searcher MVP

A fully interactive subdomain enumeration tool with DNS brute-force capabilities, built in Python.

## 🚀 Features

- **Simple CLI Interface**: Easy-to-use command-line interface
- **DNS Brute-Force**: Subdomain enumeration via DNS resolution
- **Custom Wordlists**: Support for custom wordlist files
- **Real-time Results**: Live display with colored output
- **File Logging**: Automatic saving of results to output files
- **Multi-threading**: Fast enumeration with configurable thread count
- **Cross-platform**: Works on Windows, macOS, and Linux

## 📋 Requirements

- Python 3.7 or higher
- Internet connection for DNS resolution

## 🛠️ Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install dnspython colorama
   ```

## 🎯 Usage

### Basic Usage

```bash
python subdomain_searcher.py example.com
```

### Advanced Usage

```bash
# Use custom wordlist
python subdomain_searcher.py example.com -w wordlist.txt

# Set number of threads
python subdomain_searcher.py example.com -t 20

# Custom output file
python subdomain_searcher.py example.com -o results.txt

# Combine all options
python subdomain_searcher.py example.com -w wordlist.txt -t 15 -o output/domains.txt
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `domain` | Target domain (required) | - |
| `-w, --wordlist` | Path to wordlist file | Built-in list |
| `-t, --threads` | Number of threads | 10 |
| `-o, --output` | Output file path | `output/found.txt` |

## 📁 Project Structure

```
subdomain_searcher/
├── subdomain_searcher.py    # Main script
├── requirements.txt         # Python dependencies
├── wordlist.txt            # Sample wordlist
├── README.md               # This file
└── output/                 # Results directory (auto-created)
    └── found.txt           # Default output file
```

## 🔧 How It Works

1. **Input Processing**: Validates the target domain
2. **Wordlist Loading**: Loads subdomains from file or uses built-in list
3. **DNS Resolution**: Checks each subdomain using DNS A record queries
4. **Real-time Display**: Shows found subdomains with IP addresses
5. **Result Saving**: Saves all findings to the specified output file

## 📊 Output Format

### Console Output
```
============================================================
    SUBDOMAIN SEARCHER MVP
============================================================
Target Domain: example.com
Threads: 10
Output File: output/found.txt
============================================================

Loaded 150 subdomains to test

[INFO] Starting subdomain enumeration...

[+] www.example.com (93.184.216.34) [1.23s]
[+] mail.example.com (93.184.216.35) [2.45s]
[+] api.example.com (93.184.216.36) [3.67s]

============================================================
Enumeration completed!
Total subdomains tested: 150
Subdomains found: 3
Time elapsed: 15.23 seconds
============================================================

[SUCCESS] Results saved to: output/found.txt
```

### File Output
```
# Subdomain enumeration results for example.com
# Generated on: 2024-01-15 14:30:25
# Total found: 3

www.example.com - 93.184.216.34
mail.example.com - 93.184.216.35
api.example.com - 93.184.216.36
```

## 🎨 Color Coding

- **Green [+]** : Found subdomains
- **Cyan** : IP addresses
- **Yellow** : Timestamps and counts
- **Red** : Errors
- **White** : General information

## ⚡ Performance Tips

- **Increase threads** for faster scanning (e.g., `-t 20`)
- **Use custom wordlists** for targeted enumeration
- **Monitor network** to avoid rate limiting
- **Test on small domains** first to verify functionality

## 🛡️ Legal Notice

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to scan the target domain. The authors are not responsible for any misuse of this tool.

## 🔍 Example Scenarios

### Scenario 1: Basic Domain Scan
```bash
python subdomain_searcher.py google.com
```

### Scenario 2: Custom Wordlist Scan
```bash
python subdomain_searcher.py github.com -w wordlist.txt -t 25
```

### Scenario 3: High-Thread Scan
```bash
python subdomain_searcher.py microsoft.com -t 50 -o microsoft_subdomains.txt
```

## 🐛 Troubleshooting

### Common Issues

1. **"Module not found" errors**
   - Install dependencies: `pip install -r requirements.txt`

2. **Slow performance**
   - Increase thread count: `-t 20`
   - Check internet connection

3. **No results found**
   - Verify domain is correct
   - Try with different wordlist
   - Check if domain has subdomains

4. **Permission errors**
   - Run as administrator (Windows)
   - Check file permissions

## 📈 Future Enhancements

- [ ] CNAME record support
- [ ] Wildcard detection
- [ ] Rate limiting options
- [ ] Proxy support
- [ ] JSON/CSV output formats
- [ ] Recursive subdomain discovery
- [ ] Integration with public APIs

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this tool.

## 📄 License

This project is open source and available under the MIT License. 