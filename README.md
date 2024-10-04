# PHA4N70M C2 v0.0.2pub - Documentation

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Installation](#installation)
4. [C2 Server - Details](#c2-server---details)
    - [Asymmetric Encryption (RSA)](#asymmetric-encryption-rsa)
    - [AES Key Exchange](#aes-key-exchange)
    - [Multiple Connections and Ports](#multiple-connections-and-ports)
    - [Supported Commands](#supported-commands)
5. [Client - Details](#client---details)
    - [Multiple Hosts and Ports](#multiple-hosts-and-ports)
    - [Mirror Update](#mirror-update)
    - [Features: Screenshot Capture and Keylogger](#features-screenshot-capture-and-keylogger)
6. [Evasion and Persistence](#evasion-and-persistence)

---

## Overview

This project is an **advanced C2 (Command and Control) server**, designed to provide secure and resilient remote control over multiple clients. The system is built with a focus on:
- **Strong encryption (RSA/AES)**
- **Detection evasion**
- **Dynamic mirror updates**
- **Screenshot capture and keylogging**

The C2 server can control multiple clients simultaneously, using different ports and hosts, while maintaining secure and encrypted communication.

---

## Features

1. **Asymmetric Encryption (RSA)**: Key exchange between the client and server uses RSA to ensure secure communication of the AES key.
2. **AES for Data Encryption**: All subsequent communication between the server and client is encrypted using AES for confidentiality.
3. **Multiple Hosts and Ports**: The client attempts to connect on up to 10 different ports and configurable mirrors, ensuring resiliency and availability.
4. **Dynamic Mirror Update**: The client can periodically fetch new mirrors from a remote JSON file.
5. **Screenshot Capture and Keylogger**: The client supports remote execution of commands for screenshot capture and keylogging.
6. **Evasion and Persistence**: The client can be configured to masquerade as legitimate traffic and persist in the system.

---

## Installation

### Prerequisites

- **Python 3.x**: Ensure you have Python 3 installed.
- Install the necessary dependencies for both **client** and **server**:
    ```bash
    pip install cryptography requests pillow pynput keyboard colorama
    ```

---

## C2 Server - Details

### Asymmetric Encryption (RSA)

The C2 uses RSA encryption for authentication and key exchange. The server's public key is sent to the client, which uses it to encrypt a temporary AES key. The server then decrypts this key for use in secure communication.

- **Function**: Ensures that the AES key is securely exchanged, and that subsequent communication between the C2 and client is confidential.

### AES Key Exchange

After RSA authentication, communication between the client and server switches to **AES encryption**. AES is more efficient for encrypting large volumes of data, securing all further communication.

### Multiple Connections and Ports

The server is configured to listen on **10 different ports**, increasing system resiliency. The client will attempt multiple ports and hosts (mirrors) to ensure it can always connect to the C2.

### Supported Commands

The server can issue the following commands:

1. **`screenshot`**: Captures the client’s screen and sends the image to the server.
2. **`keylog`**: Starts a keylogger on the client to record keystrokes.
3. **Shell Commands**: Standard system commands executed on the client, returning the output to the server.

---

## Client - Details

### Multiple Hosts and Ports

The client is configured to attempt several ports and hosts. This provides **redundancy** and **failover**. The list of **10 ports** is tried sequentially until a connection is established. If all fail, the client tries another host.

- **Example list of configured ports**: 9999, 8888, 7777, 6666, etc.

### Mirror Update

The client can dynamically fetch a list of new **mirrors (hosts)** from a remote JSON file. This file can be hosted on any web server and contains a list of new hosts the client can connect to.

- **Example of JSON format:**
    ```json
    {
        "mirrors": [
            "c2.mirror1.com",
            "c2.mirror2.com",
            "c2.mirror3.com"
        ]
    }
    ```

### Features: Screenshot Capture and Keylogger

1. **Screenshot Capture (`screenshot`)**:
    - The client can capture the current screen and send the image file to the server.
    - Uses the **Pillow** library to capture the screen.
   
2. **Keylogger (`keylog`)**:
    - The client can start a keylogger to monitor and record keystrokes.
    - Uses the **keyboard** library to capture keyboard events.

---

## Evasion and Persistence

The client can be configured to operate stealthily, avoiding detection by monitoring systems. Some implemented techniques include:

1. **Traffic Obfuscation**: The traffic between the client and the server can be disguised as **legitimate HTTPS traffic**.
2. **Persistence**: The client can be configured to automatically start upon system reboots. On Windows, it can be added to the Registry. On Linux, it can be set up as a **systemd service**.

### Example of Linux Persistence
```bash
[Unit]
Description=C2 Client
After=network.target

[Service]
ExecStart=/usr/bin/python3 /path/to/client.py
Restart=always

[Install]
WantedBy=multi-user.target
