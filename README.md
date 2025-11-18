# EternalKey V3

EternalKey V3 is a command-line tool designed for secure file encryption, decryption, and wiping using AES-256 GCM. It provides a simple interface to protect your sensitive files.

## Features

-   **Encrypt Files:** Securely encrypt any file using a secret key.
-   **Decrypt Files:** Decrypt encrypted files. Decrypted content is temporarily stored and automatically wiped after a set duration, enhancing security.
-   **Secure File Wiping:** Permanently delete files by overwriting their content before removal.

## Requirements

-   Python 3
-   `cryptography` library

## Installation

You can install the required `cryptography` library using pip:

```bash
pip install cryptography
```

## Usage

### Encryption

To encrypt a file, use the `encrypt` command followed by the filename. You will be prompted to enter your secret key.

```bash
python eternalkey.py encrypt <filename>
```

Example:
```bash
python eternalkey.py encrypt mysecret.txt
```

### Decryption

To decrypt a file, use the `decrypt` command followed by the filename. You will be prompted for the secret key. Decrypted files are temporarily saved and then wiped.

```bash
python eternalkey.py decrypt <filename>
```

Example:
```bash
python eternalkey.py decrypt mysecret.txt
```

#### Preventing Auto-Wipe

If you need to keep the decrypted file (e.g., for immediate use without re-encryption), you can use the `--grab-on` flag. **Use this with caution, as it bypasses the automatic wiping mechanism.**

```bash
python eternalkey.py decrypt --grab-on <filename>
```

### File Wiping

To securely wipe a file, use the `wipe` command. This will overwrite the file's content before deleting it.

```bash
python eternalkey.py wipe <filename>
```

Example:
```bash
python eternalkey.py wipe old_sensitive_data.log
```
