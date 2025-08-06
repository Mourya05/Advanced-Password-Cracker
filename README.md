###Advanced Password Cracker

A powerful and user-friendly password security analysis tool designed for security professionals, penetration testers, and cybersecurity students. This toolkit provides multiple password cracking techniques through an intuitive graphical interface.

## Features

### Cracking Modes
- **Hash Cracker**: Supports multiple hash algorithms (MD5, SHA1, SHA256, NTLM, bcrypt, SHA512)
- **Web Bruteforcer**: Test web application login forms for weak credentials
- **WiFi Cracker**: Analyze WiFi handshake captures (PCAP format supported)
- **NTLM Cracker**: Specialized tool for cracking NTLM hashes
- **Rainbow Table Cracker**: Generate and use rainbow tables for efficient hash cracking

### Core Functionality
- Dictionary attacks with custom wordlists
- Brute force attacks with customizable character sets
- Progress tracking and real-time updates
- Detailed logging and result export
- User-friendly Tkinter-based GUI

## Requirements

- Python 3.8 or higher
- Required Python packages:
  - tkinter
  - pyshark (for WiFi handshake analysis)
  - requests (for web requests)
  - flask (for testing web login - included demo)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/password-cracking-toolkit.git
   cd password-cracking-toolkit
   ```

2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```
   
   Or install them manually:
   ```bash
   pip install pyshark requests flask
   ```

## Usage

1. Run the main application:
   ```bash
   python project.py
   ```

2. Select the desired attack type from the tabs
3. Configure the attack parameters
4. Start the cracking process
5. View results and export if needed

### Demo Login Server
A sample Flask login server is included for testing the web bruteforcer:
```bash
python login_server.py
```
Default credentials: admin/letmein

## Project Structure

```
.
├── project.py           # Main application
├── login_server.py      # Demo web server
├── assets/              # Sample files
│   ├── wordlist.txt
│   ├── sample_hashes.txt
│   └── rainbow_table.json
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## Important Notes

- This tool is intended for educational purposes and authorized security testing only
- Always obtain proper authorization before testing any system
- The included login server is for demonstration purposes only
- Use responsibly and in compliance with all applicable laws and regulations

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Disclaimer

This software is provided for educational purposes only. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
