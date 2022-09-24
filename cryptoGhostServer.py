import socketserver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class ClientHandler(socketserver.BaseRequestHandler):
    
    def handle(self) -> None:
        encrypted_key = self.request.recv(1024).strip()
        print("Implement decryption of data " + str(encrypted_key))
        
        decrypted_key = self.decrypt(encrypted_key)
        print("Decr key " + str(decrypted_key))
        self.request.sendall(decrypted_key)

    def decrypt(self, encrypted_key):
        with open("/home/tabake/Документы/keys/pub_priv_pair.key", "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None
            )
        
        decrypted_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_key


if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 8000
    client_handler = ClientHandler
    tcp_server = socketserver.TCPServer((HOST, PORT), client_handler)
    
    try:
        tcp_server.serve_forever()
    except:
        print("There was error")