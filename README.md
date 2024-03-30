# Final Project Chat Application

## Description
This project implements a secure server-client communication system using Python. The core functionality includes a server that manages and authenticates client connections, and clients that can interact with the server. The system employs AES encryption for secure data transmission, ensuring confidentiality and integrity of the information exchanged between the server and clients.

## Files
- `AES.py`: Implements the Advanced Encryption Standard (AES) algorithm. This script is crucial for encrypting and decrypting messages exchanged between the server and clients, providing a layer of security against unauthorized access and data breaches.
- `RegisteredUsers.txt`: A text file containing a list of users who are allowed to access the server. This file is used by the server for authenticating clients. Each line in the file represents a unique user.
- `updated_client.py`: The client application script. This file contains the code for the client-side operations, including connecting to the server, sending requests, and receiving responses. The client also incorporates AES encryption for secure communication.
- `updated_server.py`: The server application script. This script sets up the server, listens for incoming client connections, and handles requests.

## Setup and Running Instructions
### Prerequisites
Python (Version 3.x) installed on your system.
Basic knowledge of terminal or command prompt usage.

### Server Setup
1. Start the server by running the `updated_server.py` script:
   python updated_server.py

### Client Setup
1. Open two separate terminal/command prompt windows.
2. In each window, start a client instance by running the `updated_client.py` script:
   python updated_client.py
3. Follow any on-screen instructions to interact with the server.

## Notes
- Ensure all files (AES.py, updated_client.py, updated_server.py) are in the same directory for the system to function correctly.
- The AES encryption implemented in AES.py is key to maintaining secure communications. Do not modify this file unless necessary and with a clear understanding of cryptographic principles.
