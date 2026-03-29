# Dark Security Tool

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-yellow.svg)

**Dark Security Tool** is a comprehensive, multi-functional CLI security assessment utility designed for penetration testers and security researchers. It provides a suite of tools for vulnerability scanning, network reconnaissance, password analysis, and data encoding.

## 📋 Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Modules](#modules)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## ✨ Features

- **Web Vulnerability Scanner**: Automated checks for XSS, SQLi, CSRF, and more.
- **Advanced Port Scanner**: Multi-threaded scanner with service detection and progress tracking.
- **Password Toolkit**: Entropy analysis, crack time estimation, and secure generation.
- **Base64 Utility**: Fast encoding/decoding for text and files.
- **Reporting**: Generates detailed reports in Text and JSON formats.
- **Logging**: detailed activity logging for audit trails.

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/TeamDark2-O/Dark.git
   ```
2. Navigate to the project directory:
   ```bash
   cd Dark
   ```
3. Run the tool:
   ```bash
   python dark_tool.py
   ```

## 🛠 Usage

Upon launching the tool, you will be presented with an interactive menu:

1. **Select a Module**: Enter the number corresponding to the tool you wish to use.
2. **Follow Prompts**: Input targets, select modes, or provide data as requested.
3. **View Reports**: Check the `reports/` directory for saved output.

## � Project Structure

```text
Dark/
├── reports/             # Scan reports (JSON/Text)
├── .gitignore           # Git ignore rules
├── CONTRIBUTING.md      # Contribution guidelines
├── LICENSE              # MIT License
├── README.md            # Project documentation
├── dark_tool.log        # Activity log file
├── dark_tool.py         # Main source code
└── requirements.txt     # Dependencies
```

## �📦 Modules

### 1. Vulnerability Scanner
Performs heuristic checks for common web vulnerabilities:
- Cross-Site Scripting (Reflected XSS)
- Cross-Site Request Forgery (CSRF)
- Directory Traversal
- Command Injection
- Buffer Overflow
- Insecure Direct Object References (IDOR)
- Broken Authentication (Cookie flags)
- Sensitive Data Exposure (Headers)
- XML External Entity (XXE)

### 2. Port Scanner
- **Modes**: Quick Scan (Common ports) or Full Scan (1-65535).
- **Performance**: Adjustable thread count and timeout.
- **Output**: Lists open ports and identified services.

### 3. Password Tools
- **Strength Checker**: Calculates entropy and estimates brute-force time.
- **Generator**: Creates cryptographically strong passwords.

### 4. Base64 Tools
- Encode/Decode raw text strings.
- Encode/Decode binary files.

## 🤝 Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for **educational and authorized testing purposes only**. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always obtain proper authorization before scanning any network or system.

---
**Developed by [TeamDark2-O](https://github.com/TeamDark2-O)**


![image alt](https://github.com/cyberhub144/Dark-tool-kits/blob/db18445ab5f9fae4c0086bfd3585af64b86d19ec/image1.png)
