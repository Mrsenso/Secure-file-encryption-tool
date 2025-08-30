#!/usr/bin/env python3
"""
Secure File Encryption Tool
A cross-platform tool for encrypting and decrypting files with AES-256 encryption.
"""

import os
import sys
import argparse
import hashlib
import hmac
import secrets
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

# Try to import tkinter for GUI, but continue without it if not available
GUI_AVAILABLE = True
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ImportError:
    GUI_AVAILABLE = False

class SecureFileEncryptor:
    """Main class for file encryption operations"""
    
    # Encryption parameters
    SALT_SIZE = 16
    KEY_SIZE = 32  # 256 bits for AES-256
    IV_SIZE = 16   # 128 bits for AES block size
    HMAC_SIZE = 32  # 256 bits for SHA256 HMAC
    DERIVATION_ROUNDS = 100000
    
    def __init__(self):
        self.overwrite = False
    
    def derive_key(self, password, salt):
        """Derive encryption key from password using PBKDF2"""
        return PBKDF2(password, salt, dkLen=self.KEY_SIZE, count=self.DERIVATION_ROUNDS,
                     prf=lambda p, s: hashlib.sha256(p + s).digest())
    
    def encrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Encrypt a file with AES-256-CBC
        
        Args:
            input_path: Path to the file to encrypt
            output_path: Path where encrypted file will be saved
            password: Password for encryption
            progress_callback: Optional function to report progress
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Generate random salt and IV
            salt = secrets.token_bytes(self.SALT_SIZE)
            iv = secrets.token_bytes(self.IV_SIZE)
            
            # Derive encryption key
            key = self.derive_key(password.encode('utf-8'), salt)
            
            # Initialize AES cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Get file size for progress tracking
            file_size = os.path.getsize(input_path)
            bytes_processed = 0
            
            # Create HMAC for integrity verification
            hmac_key = hashlib.sha256(key + salt).digest()
            file_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
            
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write salt, IV to output file
                outfile.write(salt)
                outfile.write(iv)
                
                # Process file in chunks
                while True:
                    chunk = infile.read(64 * 1024)  # 64KB chunks
                    if len(chunk) == 0:
                        break
                    
                    # Pad the last chunk
                    if len(chunk) % AES.block_size != 0:
                        chunk = pad(chunk, AES.block_size)
                    
                    encrypted_chunk = cipher.encrypt(chunk)
                    outfile.write(encrypted_chunk)
                    file_hmac.update(encrypted_chunk)
                    
                    # Update progress if callback provided
                    bytes_processed += len(chunk)
                    if progress_callback and file_size > 0:
                        progress = (bytes_processed / file_size) * 100
                        progress_callback(progress)
                
                # Write HMAC at the end of the file
                outfile.write(file_hmac.digest())
            
            return True
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            # Clean up partially encrypted file on error
            if os.path.exists(output_path):
                os.remove(output_path)
            return False
    
    def decrypt_file(self, input_path, output_path, password, progress_callback=None):
        """
        Decrypt a file encrypted with this tool
        
        Args:
            input_path: Path to the encrypted file
            output_path: Path where decrypted file will be saved
            password: Password used for encryption
            progress_callback: Optional function to report progress
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(input_path, 'rb') as infile:
                # Read salt and IV from beginning of file
                salt = infile.read(self.SALT_SIZE)
                iv = infile.read(self.IV_SIZE)
                
                # Derive encryption key
                key = self.derive_key(password.encode('utf-8'), salt)
                
                # Initialize AES cipher
                cipher = AES.new(key, AES.MODE_CBC, iv)
                
                # Get file size for progress tracking
                file_size = os.path.getsize(input_path)
                bytes_processed = self.SALT_SIZE + self.IV_SIZE
                
                # Prepare HMAC verification
                hmac_key = hashlib.sha256(key + salt).digest()
                file_hmac = hmac.new(hmac_key, digestmod=hashlib.sha256)
                
                # Read the entire file except the HMAC at the end
                encrypted_data = infile.read()
                encrypted_content = encrypted_data[:-self.HMAC_SIZE]
                stored_hmac = encrypted_data[-self.HMAC_SIZE:]
                
                # Verify HMAC
                file_hmac.update(encrypted_content)
                if not hmac.compare_digest(file_hmac.digest(), stored_hmac):
                    print("HMAC verification failed! File may have been tampered with.")
                    return False
                
                # Process the encrypted content
                decrypted_data = cipher.decrypt(encrypted_content)
                decrypted_data = unpad(decrypted_data, AES.block_size)
                
                # Write decrypted data to output file
                with open(output_path, 'wb') as outfile:
                    outfile.write(decrypted_data)
                
                # Update progress if callback provided
                if progress_callback:
                    progress_callback(100)
            
            return True
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            # Clean up partially decrypted file on error
            if os.path.exists(output_path):
                os.remove(output_path)
            return False

def main():
    """Command-line interface for the encryption tool"""
    parser = argparse.ArgumentParser(description='Secure File Encryption Tool')
    parser.add_argument('action', choices=['encrypt', 'decrypt'], 
                       help='Action to perform: encrypt or decrypt')
    parser.add_argument('input_file', help='Input file path')
    parser.add_argument('output_file', help='Output file path')
    parser.add_argument('-p', '--password', help='Encryption/decryption password')
    parser.add_argument('--overwrite', action='store_true', 
                       help='Overwrite output file if it exists')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.input_file):
        print(f"Error: Input file '{args.input_file}' does not exist.")
        sys.exit(1)
    
    # Check if output file exists and handle overwrite
    if os.path.exists(args.output_file) and not args.overwrite:
        response = input(f"Output file '{args.output_file}' exists. Overwrite? (y/N): ")
        if response.lower() != 'y':
            print("Operation cancelled.")
            sys.exit(0)
    
    # Get password if not provided as argument
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Enter password: ")
        if not password:
            print("Password cannot be empty.")
            sys.exit(1)
    
    # Perform encryption/decryption
    encryptor = SecureFileEncryptor()
    
    def progress_callback(progress):
        print(f"\rProgress: {progress:.1f}%", end='', flush=True)
    
    print(f"{'Encrypting' if args.action == 'encrypt' else 'Decrypting'}...")
    
    if args.action == 'encrypt':
        success = encryptor.encrypt_file(
            args.input_file, args.output_file, password, progress_callback
        )
    else:
        success = encryptor.decrypt_file(
            args.input_file, args.output_file, password, progress_callback
        )
    
    print()  # New line after progress
    if success:
        print("Operation completed successfully.")
    else:
        print("Operation failed.")
        sys.exit(1)

if GUI_AVAILABLE:
    class EncryptionGUI:
        """Graphical user interface for the encryption tool"""
        
        def __init__(self, root):
            self.root = root
            self.root.title("Secure File Encryption Tool")
            self.root.geometry("500x300")
            self.root.resizable(False, False)
            
            self.encryptor = SecureFileEncryptor()
            self.input_file = tk.StringVar()
            self.output_file = tk.StringVar()
            self.password = tk.StringVar()
            self.action = tk.StringVar(value="encrypt")
            
            self.setup_ui()
        
        def setup_ui(self):
            """Set up the user interface"""
            # Main frame
            main_frame = ttk.Frame(self.root, padding="20")
            main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
            
            # Title
            title_label = ttk.Label(main_frame, text="Secure File Encryption Tool", 
                                   font=("Arial", 16, "bold"))
            title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
            
            # Action selection
            ttk.Radiobutton(main_frame, text="Encrypt", variable=self.action, 
                           value="encrypt").grid(row=1, column=0, sticky=tk.W, pady=5)
            ttk.Radiobutton(main_frame, text="Decrypt", variable=self.action, 
                           value="decrypt").grid(row=1, column=1, sticky=tk.W, pady=5)
            
            # Input file selection
            ttk.Label(main_frame, text="Input File:").grid(row=2, column=0, sticky=tk.W, pady=5)
            ttk.Entry(main_frame, textvariable=self.input_file, width=40).grid(row=2, column=1, pady=5)
            ttk.Button(main_frame, text="Browse", command=self.browse_input).grid(row=2, column=2, pady=5)
            
            # Output file selection
            ttk.Label(main_frame, text="Output File:").grid(row=3, column=0, sticky=tk.W, pady=5)
            ttk.Entry(main_frame, textvariable=self.output_file, width=40).grid(row=3, column=1, pady=5)
            ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=3, column=2, pady=5)
            
            # Password
            ttk.Label(main_frame, text="Password:").grid(row=4, column=0, sticky=tk.W, pady=5)
            ttk.Entry(main_frame, textvariable=self.password, show="*", width=40).grid(row=4, column=1, pady=5)
            
            # Progress bar
            self.progress = ttk.Progressbar(main_frame, mode='determinate')
            self.progress.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
            
            # Execute button
            self.execute_button = ttk.Button(main_frame, text="Execute", command=self.execute)
            self.execute_button.grid(row=6, column=0, columnspan=3, pady=10)
            
            # Status label
            self.status_label = ttk.Label(main_frame, text="Ready")
            self.status_label.grid(row=7, column=0, columnspan=3)
            
            # Configure grid weights
            main_frame.columnconfigure(1, weight=1)
        
        def browse_input(self):
            """Browse for input file"""
            filename = filedialog.askopenfilename(title="Select input file")
            if filename:
                self.input_file.set(filename)
                # Suggest output filename
                if not self.output_file.get():
                    action = "encrypted" if self.action.get() == "encrypt" else "decrypted"
                    base, ext = os.path.splitext(filename)
                    self.output_file.set(f"{base}.{action}{ext}")
        
        def browse_output(self):
            """Browse for output file"""
            filename = filedialog.asksaveasfilename(title="Select output file")
            if filename:
                self.output_file.set(filename)
        
        def progress_callback(self, progress):
            """Update progress bar"""
            self.progress['value'] = progress
            self.root.update_idletasks()
        
        def execute(self):
            """Execute encryption or decryption"""
            # Validate inputs
            if not self.input_file.get():
                messagebox.showerror("Error", "Please select an input file.")
                return
            
            if not self.output_file.get():
                messagebox.showerror("Error", "Please select an output file.")
                return
            
            if not self.password.get():
                messagebox.showerror("Error", "Please enter a password.")
                return
            
            # Check if output file exists
            if os.path.exists(self.output_file.get()):
                if not messagebox.askyesno("Confirm", "Output file exists. Overwrite?"):
                    return
            
            # Disable button during operation
            self.execute_button.config(state='disabled')
            self.status_label.config(text="Working...")
            
            # Perform operation in a separate thread to avoid GUI freezing
            import threading
            thread = threading.Thread(target=self.perform_operation)
            thread.daemon = True
            thread.start()
        
        def perform_operation(self):
            """Perform the encryption/decryption operation"""
            try:
                action = self.action.get()
                if action == "encrypt":
                    success = self.encryptor.encrypt_file(
                        self.input_file.get(), 
                        self.output_file.get(), 
                        self.password.get(),
                        self.progress_callback
                    )
                else:
                    success = self.encryptor.decrypt_file(
                        self.input_file.get(), 
                        self.output_file.get(), 
                        self.password.get(),
                        self.progress_callback
                    )
                
                # Update UI on completion
                self.root.after(0, self.operation_complete, success)
            except Exception as e:
                self.root.after(0, self.operation_error, str(e))
        
        def operation_complete(self, success):
            """Handle operation completion"""
            self.execute_button.config(state='normal')
            if success:
                self.status_label.config(text="Operation completed successfully!")
                messagebox.showinfo("Success", "Operation completed successfully!")
            else:
                self.status_label.config(text="Operation failed.")
                messagebox.showerror("Error", "Operation failed. Check console for details.")
        
        def operation_error(self, error_msg):
            """Handle operation error"""
            self.execute_button.config(state='normal')
            self.status_label.config(text=f"Error: {error_msg}")
            messagebox.showerror("Error", f"An error occurred: {error_msg}")

def gui_main():
    """Start the GUI application"""
    root = tk.Tk()
    app = EncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # Command line mode
        main()
    else:
        # GUI mode if available, otherwise show usage
        if GUI_AVAILABLE:
            gui_main()
        else:
            print("Secure File Encryption Tool")
            print("Usage:")
            print("  For GUI: python secure_encrypt.py")
            print("  For CLI: python secure_encrypt.py [encrypt|decrypt] input_file output_file")
            print("\nTkinter is not available. GUI mode disabled.")
            print("Install tkinter to use the graphical interface.")