# Pal.Sniper - Multi-Security Tool

A multi-purpose security tool for penetration testers and bug bounty hunters.  
This tool includes modules for:
- Clickjacking scanning
- Subdomain enumeration
- Wayback Machine URL extraction
- Reflected XSS testing
- LFI & Log Poisoning exploitation
- Open Redirect scanning

---

## Requirements

Install all dependencies using:

```
pip install -r requirements.txt
```

You may also need to [download ChromeDriver](https://chromedriver.chromium.org/downloads) if you use the XSS module.

---

## Usage

1. **Clone or download this repository.**
2. **Navigate to the tool's folder in your terminal:**
   ```
   cd path/to/your/folder
   ```
3. **Install requirements:**
   ```
   pip install -r requirements.txt
   ```
4. **Run the tool:**
   ```
   python "Pal.Sniper - Multi-Security Tool.py"
   ```
   *(Or the script name you saved)*

5. **Follow the on-screen menu and instructions.**

---

## Notes

- For subdomain and clickjacking scans, prepare your input files as instructed in the menu.
- Results and reports will be saved in the same folder as the script.
- For XSS testing, make sure you have Chrome and ChromeDriver installed.

---

## Disclaimer

This tool is for educational and authorized testing purposes only.  
The author is not responsible for any misuse.

---

**Made with ❤️ by Pal.Sniper**