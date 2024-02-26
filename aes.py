from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import sys
import argparse
from getpass import getpass
import time

"""
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

class AES_BASE():

  def encrypt_with_aes(self, data, session_key : str = None):

    if session_key is None:
      raise ValueError('Argument \'session_key\' is missing.')
    elif not (type(session_key) is bytes):
        session_key = bytes(session_key.encode())

    # Derive a symmetric key from the session key
    salt = os.urandom(16)  # 16 bytes for 128-bit salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  # Increased iterations for added security
        backend=default_backend()
    )
    key = kdf.derive(session_key)

    # Encrypt the data with AES
    iv = os.urandom(16)  # 16 bytes for 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    packed_data = (salt+iv+encrypted_data)
    return packed_data

  def decrypt_with_aes(self, packed_data, session_key : str = None):

    if session_key is None:
      raise ValueError('Argument \'session_key\' is missing.')
    elif not (type(session_key) is bytes):
      session_key = bytes(session_key.encode())

    salt = packed_data[:16]
    iv = packed_data[16:32]
    encrypted_data = packed_data[32:]

    # Derive the symmetric key from the session key
    kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=200000,  # Increased iterations for added security
      backend=default_backend()
    )
    key = kdf.derive(session_key)

    # Decrypt the data with AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

class AES_on_File(AES_BASE):

  def file_encrypt(self, target, output):

    with open(target, 'rb')as f:
      data_to_encrypt = f.read()

    encrypted_data = self.encrypt_with_aes(data_to_encrypt, getpass('Enter a passphase for encryption: '))

    filename = os.path.basename(target).encode()
    filename_size = len(filename)

    # Concatenate the encrypted data
    data_packed = (filename_size.to_bytes(4, 'big') + filename + encrypted_data)

    if os.path.exists(output):
      overwrite = input(f"The file '{output}' already exists. Overwrite? (y/n): ").lower()
      if overwrite != 'y':
        print("Extraction cancelled.")
        return

    with open(output, 'wb')as f:
      f.write(data_packed)

    print(f"File '{target}' has been successfully encrypted in '{output}' with AES.")

  def file_decrypt(self, ciphertext, decrypted):

    with open(ciphertext, 'rb')as f:
      data_to_unpack = f.read()

    # Extract the filename size and filename
    filename_size = int.from_bytes(data_to_unpack[:4], 'big')
    filename = data_to_unpack[4:4 + filename_size].decode()

    # Extract the encrypted data
    offset = 4 + filename_size
    encrypted_data = data_to_unpack[offset:]

    decrypted_data = self.decrypt_with_aes(encrypted_data, getpass('Enter the passphase of encryption: '))

    # If no output file path is provided, use the extracted filename
    if not decrypted:
      decrypted = os.path.join(os.getcwd(), filename)

    # Check if the file already exists and prompt the user
    if os.path.exists(decrypted):
      overwrite = input(f"The file '{decrypted}' already exists. Overwrite? (y/n): ").lower()
      if overwrite != 'y':
        print("Extraction cancelled.")
        return

    # Write the decompressed data to the output file
    with open(decrypted, 'wb') as f:
      f.write(decrypted_data)

    print(f"File extracted to {decrypted}")

def main():
  parser = argparse.ArgumentParser(description='AES Binary - Encrypt Tool', epilog="Example commands:\n"
                                            "  Encrypt: python aes.py encrypt target.txt output.txt\n"
                                            "  Decrypt: python aes.py decrypt ciphetext.txt [decrypted.txt]",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
  subparsers = parser.add_subparsers(dest='command')

  # Subparser for encrypt a file
  hide_parser = subparsers.add_parser('encrypt', help='Encrypt a file', epilog="Example: python aes.py encrypt target.txt output.txt", formatter_class=argparse.RawDescriptionHelpFormatter)
  hide_parser.add_argument('target', type=str, help='Path to the to-be-encrypted file')
  hide_parser.add_argument('output', type=str, help='Path to the output encrypted file')


  # Subparser for decrypt a file
  extract_parser = subparsers.add_parser('decrypt', help='Decrypt an encrypted file', epilog="Example: python aes.py decrypt ciphetext.txt [decrypted.txt]",
                                         formatter_class=argparse.RawDescriptionHelpFormatter)
  extract_parser.add_argument('ciphertext', type=str, help='Path to the encrypted file')
  extract_parser.add_argument('decrypted', nargs='?', type=str, default=None, help='Path to save the decrypted file (optional, defaults to the original filename)')

  if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

  args = parser.parse_args()

  if args.command == 'encrypt':
    AES_on_File().file_encrypt(args.target, args.output)
  elif args.command == 'decrypt':
    # If no output file path is provided, use None to trigger default behavior
    output_file_path = args.decrypted if args.decrypted else None
    AES_on_File().file_decrypt(args.ciphertext, output_file_path)
  else:
    parser.print_help()

if __name__ == '__main__': 
  start_time = time.time()
  main()
  print(f'\nExecution Time : {time.time()-start_time}')