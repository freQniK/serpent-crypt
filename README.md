# serpent-crypt

A CLI for encryption/decryption with the Serpent Cipher



# Installation

Install the required Python pacakges

```shell
pip install pyserpent pycryptodome
```

# Usage

```shell
% python3.10 serpent_crypt.py -h 
usage: serpent_crypt.py [-h] [-e] [-d] input_file output_file

Encrypt or decrypt files using Serpent (CBC mode) with pyserpent.

positional arguments:
  input_file     Input file
  output_file    Output file

options:
  -h, --help     show this help message and exit
  -e, --encrypt  Encrypt a file
  -d, --decrypt  Decrypt a file
```

It will prompt for a key file. If this key file does not exist it will create one. Be sure to save your key file somewhere safe and not on the same computer! Also, consider encrypting the key file with GPG.
