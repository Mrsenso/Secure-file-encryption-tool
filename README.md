Secure File Encryption Tool

A cross-platform, secure file encryption tool built with Python that provides both command-line and graphical interfaces for encrypting and decrypting files using strong encryption algorithms.
Features

    AES-256 Encryption: Industry-standard encryption using AES-256 in CBC mode

    Password-Based Key Derivation: Uses PBKDF2 with 100,000 iterations for key strengthening

    File Integrity Protection: HMAC-SHA256 verification to detect tampering

    Cross-Platform: Works on Windows, macOS, and Linux

    Dual Interface: Both command-line (CLI) and graphical (GUI) interfaces

    Progress Tracking: Real-time progress indication for large files

    Security Best Practices: Proper salting, IV generation, and key derivation

Installation
Prerequisites

    Python 3.6 or higher

    Tkinter (for GUI interface - usually included with Python)

Option 1: Using Kali Linux Package Manager
bash

sudo apt update
sudo apt install python3-pycryptodome

Option 2: Using Virtual Environment (Recommended)
bash

# Install virtual environment tools
sudo apt install python3-venv python3-pip

# Create a virtual environment
python3 -m venv encryption-env

# Activate the virtual environment
source encryption-env/bin/activate

# Install required packages
pip install pycryptodome

Option 3: Using System Packages
bash

# For Debian/Ubuntu/Kali
sudo apt install python3-pycryptodome

# For Fedora/RHEL
sudo dnf install pycryptodome

# For macOS with Homebrew
brew install pycryptodome

Usage
Command Line Interface
Encrypt a file:
bash

python secure_encrypt.py encrypt input.txt output.enc

Decrypt a file:
bash

python secure_encrypt.py decrypt input.enc output.txt

Additional options:
bash

# Specify password as argument
python secure_encrypt.py encrypt input.txt output.enc -p "your_password"

# Overwrite output file without confirmation
python secure_encrypt.py encrypt input.txt output.enc --overwrite

# Get help
python secure_encrypt.py --help

Graphical User Interface
bash

python secure_encrypt.py

The GUI provides:

    File selection via browse dialogs

    Visual progress indication

    Password confirmation for encryption

    Operation status feedback

Security Details
Encryption Process

    Key Derivation: Password is strengthened using PBKDF2 with 100,000 iterations and a random 16-byte salt

    IV Generation: A random 16-byte initialization vector is generated for each encryption

    Encryption: Data is encrypted using AES-256 in CBC mode with PKCS7 padding

    Integrity Protection: HMAC-SHA256 is computed over the ciphertext and appended to the file

File Format

Encrypted files have the following structure:
text

[16-byte Salt][16-byte IV][...Ciphertext...][32-byte HMAC]

Algorithm Specifications

    Encryption: AES-256-CBC

    Key Derivation: PBKDF2-HMAC-SHA256 with 100,000 iterations

    Integrity: HMAC-SHA256

    Salt Size: 16 bytes

    IV Size: 16 bytes

    Key Size: 32 bytes (256 bits)

    HMAC Size: 32 bytes

Examples
Basic Encryption/Decryption
bash

# Encrypt a document
python secure_encrypt.py encrypt secret.docx secret.docx.enc

# Decrypt the document
python secure_encrypt.py decrypt secret.docx.enc secret_decrypted.docx

Working with Different File Types
bash

# Encrypt a PDF
python secure_encrypt.py encrypt financial_report.pdf report.enc

# Encrypt an image
python secure_encrypt.py encrypt family_photo.jpg photo.enc

# Encrypt a directory (using tar first)
tar -czf documents.tar.gz important_documents/
python secure_encrypt.py encrypt documents.tar.gz documents.tar.gz.enc

Project Structure
text

secure_encrypt.py    # Main application file
README.md           # This file
requirements.txt    # Python dependencies

Dependencies

    pycryptodome - Cryptographic functions for Python

    tkinter - Graphical user interface (usually included with Python)

The requirements.txt file contains:
text

pycryptodome>=3.10.1

Platform Support
Platform	Status	Notes
Windows	✅ Supported	Requires Python 3.6+
macOS	✅ Supported	Requires Python 3.6+
Linux	✅ Supported	Tested on Kali, Ubuntu, Fedora
Kali Linux	✅ Supported	Use virtual environment or system packages
Security Considerations

    Strong Passwords: Use long, complex passwords for best security

    Password Management: Consider using a password manager to store encryption passwords

    Secure Deletion: Use secure deletion tools to remove original files after encryption

    Backup: Always maintain backups of important encrypted files

    Key Management: The security entirely depends on password secrecy

Limitations

    Large Files: Very large files may take significant time to process

    Memory Usage: The current implementation loads chunks into memory (64KB chunks)

    No Key Recovery: There is no password recovery mechanism - lost password means lost data

Troubleshooting
Common Issues

    "ModuleNotFoundError: No module named 'Crypto'"
    bash

# Install the required package
pip install pycryptodome

"Externally managed environment" error on Kali Linux
bash

# Use virtual environment instead
python3 -m venv myenv
source myenv/bin/activate
pip install pycryptodome

GUI not opening
bash

    # Install tkinter if missing
    sudo apt install python3-tk

    HMAC verification failed

        The file may have been corrupted or tampered with

        Ensure you're using the correct password

Performance Tips

    For very large files, consider using the command-line interface

    Close other memory-intensive applications during encryption/decryption

    Use SSD storage for faster file operations

Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

    Bug fixes

    Performance improvements

    New features

    Documentation updates

License

This project is open source and available under the MIT License.
Disclaimer

This tool is provided for educational and security purposes. The authors are not responsible for any data loss or security issues resulting from the use of this software. Always test with non-critical data first and maintain backups.
Support

For questions, issues, or suggestions:

    Check the troubleshooting section above

    Open an issue on the GitHub repository

    Ensure you include details about your environment and the problem

Version History

    v1.0 (Current)

        Initial release

        AES-256 encryption/decryption

        CLI and GUI interfaces

        Cross-platform support

        File integrity verification

Note for Security Professionals: This tool implements industry-standard cryptographic practices but should be tested in your specific environment before use with sensitive data.
