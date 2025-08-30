# BountyScope - Reconnaissance Framework

![BountyScope](https://img.shields.io/badge/BountyScope-Recon%20Framework-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-1.0.0-orange)

A user-friendly web-based reconnaissance framework designed for bug bounty hunters and penetration testers. Build powerful, automated workflows with ease and kickstart your security assessments.

## 🚀 Features

- **Multi-Phase Workflow**: 15 comprehensive reconnaissance phases
- **Tool Selection**: Choose from 50+ security tools
- **Preset Workflows**: Quick access to common scan types (Passive, Quick, Deep, Web Vuln, Full)
- **Script Generation**: Automatically generate custom bash automation scripts
- **Dependency Management**: View installation commands for required tools
- **Search Functionality**: Quickly find tools and phases
- **Modern UI**: Responsive design with smooth animations
- **Export Options**: Copy or download generated scripts

## 📋 Reconnaissance Phases

1. **Domain Intelligence & Technology Profiling** - WHOIS, DNS records, technology stack analysis
2. **Comprehensive Subdomain Discovery** - Multiple subdomain enumeration techniques
3. **DNS Resolution & Live Service Detection** - Host validation and probing
4. **Visual Reconnaissance & Screenshot Analysis** - Web application screenshot capture
5. **Network Scanning & Service Enumeration** - Port scanning and service detection
6. **Web Crawling & URL Harvesting** - URL discovery from multiple sources
7. **Content Discovery & Directory Fuzzing** - Hidden directory and file discovery
8. **JavaScript Analysis & API Discovery** - JS file analysis and endpoint extraction
9. **Parameter Discovery & Fuzzing** - Hidden parameter identification
10. **Cloud Asset & Storage Discovery** - Cloud infrastructure enumeration
11. **Git Repository & Source Code Analysis** - Secret and credential discovery
12. **Vulnerability Scanning & Template-Based Testing** - Common vulnerability detection
13. **Specialized Vulnerability Hunting** - XSS, SQLi, SSRF, and other specific tests
14. **CMS & Framework Security Assessment** - CMS-specific vulnerability scanning
15. **Essential Resources & Wordlists** - Curated security resources

## 🛠️ Installation

No installation required! BountyScope runs directly in your web browser.

1. **Clone or download** the project files:
   ```bash
   git clone <repository-url>
   cd BountyScope
   ```

2. **Open** `index.html` in your web browser:
   ```bash
   # On macOS
   open index.html
   
   # On Linux
   xdg-open index.html
   
   # On Windows
   start index.html
   ```

3. **Start using** BountyScope immediately!

## 📖 Usage

### Basic Workflow

1. **Set Target**: Enter your target domain in the input field
2. **Select Tools**: Choose individual tools or load preset workflows
3. **Generate Script**: Click "Generate Script" to create your automation script
4. **Review**: Check the generated bash script
5. **Export**: Copy to clipboard or download the script
6. **Execute**: Run the script on your penetration testing machine

### Preset Workflows

- **Passive Scan**: Basic information gathering without direct interaction
- **Quick Scan**: Fast reconnaissance with essential tools
- **Deep Scan**: Comprehensive enumeration and discovery
- **Web Vuln Scan**: Focused web application vulnerability testing
- **Full Scan**: Complete reconnaissance with all available tools

### Tool Dependencies

The generated scripts require various security tools. Use the "View Dependencies" button to see installation commands for:

- **Package Managers**: apt, brew, pip, gem, go install
- **Source Installation**: git clone and manual compilation
- **Platform-Specific**: Recommendations based on your operating system

## 🗂️ Project Structure

```
BountyScope/
├── index.html          # Main application interface
├── style.css          # Styling and animations
├── script.js          # Application logic and functionality
└── README.md          # This documentation file
```

## 🔧 Supported Tools

BountyScope supports a wide range of security tools including:

- **Subdomain Discovery**: Subfinder, Assetfinder, Amass, Findomain, Chaos DB
- **DNS Tools**: dnsx, DNSRecon, PureDNS, dig
- **HTTP Probing**: httpx, httprobe
- **Visual Recon**: Gowitness, Aquatone, WebScreenshot
- **Port Scanning**: Naabu, Masscan, Nmap, RustScan
- **Web Crawling**: Katana, Gospider, Waybackurls, Gau
- **Content Discovery**: ffuf, Gobuster, Feroxbuster, Dirsearch
- **JS Analysis**: subjs, LinkFinder, SecretFinder
- **Parameter Discovery**: ParamSpider, Arjun, x8, GF Patterns
- **Vulnerability Scanning**: Nuclei, testssl.sh, WPScan, Nikto
- **Specialized Testing**: Dalfox, SQLMap, SSRFmap, Commix
- **Cloud & S3**: S3Scanner, Cloud_enum, CloudBrute
- **Secret Scanning**: TruffleHog, GitLeaks, GitHound

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed information
2. **Suggest Features**: Propose new tools or improvements
3. **Add Tools**: Contribute support for additional security tools
4. **Improve Documentation**: Help make the project more accessible

### Development Setup

1. Fork the repository
2. Make your changes
3. Test thoroughly
4. Submit a pull request

## 📝 License

This project is open source. Please add appropriate licensing information based on your preferences.

## ⚠️ Disclaimer

BountyScope is designed for educational and authorized security testing purposes only. Always ensure you have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 📞 Support

For questions, issues, or suggestions:
- Open an issue on the GitHub repository
- Check the documentation for common questions

## 🔄 Changelog

### v1.0.0
- Initial release with 15 reconnaissance phases
- Support for 50+ security tools
- Preset workflow configurations
- Script generation and export functionality
- Dependency management system
- Modern responsive UI

---

**Happy Hunting!** 🎯

*BountyScope - Making reconnaissance workflows accessible to everyone*
