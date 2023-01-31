#!/bin/bash

if [ "$(lsmod | grep ^xt_geoip)" ]; then
    curl -s "https://raw.githubusercontent.com/0xLem0nade/GFIGeoIP/main/Aggregated_Data/agg_cidrs.csv" >/tmp/agg_cidrs.csv

    OLD_SIZE=$(wc -c </usr/libexec/0xLem0nade/agg_cidr.csv)
    NEW_SIZE=$(wc -c </tmp/agg_cidrs.csv)
    if [ "$OLD_SIZE" != "$NEW_SIZE" ]; then
        sudo mv /tmp/agg_cidrs.csv /usr/libexec/0xLem0nade/agg_cidrs.csv
        # Convert CSV database to binary format for xt_geoip
        echo -e "${B_GREEN}Newer aggregated CIDR database found, updating now... ${RESET}"
        sudo /usr/libexec/0xLem0nade/xt_geoip_build_agg -s -i /usr/libexec/0xLem0nade/agg_cidrs.csv
        # Load xt_geoip kernel module
        sudo modprobe xt_geoip
    else
        rm /tmp/agg_cidrs.csv
    fi
fi
