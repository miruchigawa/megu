import os, pathlib, secrets, base64, getpass, argparse
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

def generate_salt(size=16):
  return secrets.token_bytes(size)
  
def derive_key(salt, password):
  kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
  return kdf.derive(password.encode())
  
def load_salt():
  return open("salt.salt", "rb").read()
  
def generate_key(password, salt_size=16, load_exsiting_salt=False, save_salt=True):
  if load_exsiting_salt:
    salt = load_salt()
  elif save_salt:
    salt = generate_salt(salt_size)
    with open("salt.salt", "wb") as file:
      file.write(salt)
  derived_key = derive_key(salt, password)
  return base64.urlsafe_b64encode(derived_key)

def encrypt(filename, key):
  fer = Fernet(key)
  with open(filename, "rb") as file:
    files = file.read()
    enc = fer.encrypt(files)
    with open(filename, "wb") as file:
      file.write(enc)
      
def decrypt(filename, key):
  fer = Fernet(key)
  with open(filename, "rb") as file:
    decr = file.read()
  try:
    files = fer.decrypt(decr)
  except cryptography.fernet.InvalidToken:
    print("[•] Invalid token, Make sure your token correct")
    return
  with open(filename, "wb") as file:
    file.write(files)

def encrypt_folder(folder, key):
  for child in pathlib.Path(folder).glob("*"):
    if child.is_file():
      print(f"[•] Encrypting {child}")
      encrypt(child, key)
    elif child.is_dir():
      encrypt_folder(child, key)
      
def decrypt_folder(folder, key):
  for child in pathlib.Path(folder).glob("*"):
    if child.is_file():
      print(f"[•] Decrypting {child}")
      decrypt(child, key)
    elif child.is_dir():
      decrypt_folder(child, key)
      
if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Encrypt Decrypt your folder")
  parser.add_argument("path", help="Path folder to encrypt/decrypt, Folder must have file inside")
  parser.add_argument("-s", "--salt-size", help="For changing salt size, Default is 16", type=int)
  parser.add_argument("-e", "--encrypt", action="store_true", help="Argument for encrypt folder")
  parser.add_argument("-d", "--decrypt", action="store_true", help="Argument for decrypt folder")
  args = parser.parse_args()
  if args.encrypt:
    password = getpass.getpass("Enter password: ")
  elif args.decrypt:
    password = getpass.getpass("Enter password: ")
  
  if args.salt_size:
    key = generate_key(password, salt_size=args.salt_size, save_salt=True)
  else:
    key = generate_key(password, load_exsiting_salt=True)
  encrypt_ = args.encrypt
  decrypt_ = args.decrypt
  if decrypt_ and encrypt_:
    raise TypeError("Invalid argument please select one decrypt or encrypt. bakaa")
  elif encrypt_:
    if os.path.isfile(args.path):
      encrypt(args.path, key)
    elif os.path.isdir(args.path):
      encrypt_folder(args.path, key)
  elif decrypt_:
    if os.path.isfile(args.path):
      decrypt(args.path, key)
    elif os.path.isdir(args.path):
      decrypt_folder(args.path, key)
  else:
    raise TypeError("Invalid argument please select one decrypt or encrypt. Bakaa")