#!bin/bash

function get_public_dns_servers {
 
    source .env
    DNS_SERVER_LIST_URL=$DNS_SERVER_LIST_URL

    TMP_FILE=$(mktemp)
    curl -s $DNS_SERVER_LIST_URL > $TMP_FILE

    DNS_SERVERS=$(cat $TMP_FILE | grep -v '#' | awk '{print $1}')
    echo $DNS_SERVERS > dns_servers.txt
    rm $TMP_FILE
}

get_public_dns_servers