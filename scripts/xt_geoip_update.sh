#!/bin/bash

if [ "$(lsmod | grep ^xt_geoip)" ]; then
    curl -s "https://raw.githubusercontent.com/0xNeu/GFIGeoIP/main/Aggregated_Data/agg_cidrs.csv" >/tmp/agg_cidrs.csv

    # Check if it is newer than what we already have
    if cmp -s /usr/libexec/0xNeu/agg_cidr.csv /tmp/agg_cidrs.csv; then
        echo -e "${B_GREEN}Already on the latest database! ${RESET}"
        rm /tmp/agg_cidrs.csv
    else
        sudo mv /tmp/agg_cidrs.csv /usr/libexec/0xNeu/agg_cidrs.csv
        # Convert CSV database to binary format for xt_geoip
        echo -e "${B_GREEN}Newer aggregated CIDR database found, updating now... ${RESET}"
        sudo /usr/libexec/0xNeu/xt_geoip_build_agg -s -i /usr/libexec/0xNeu/agg_cidrs.csv
        # Load xt_geoip kernel module
        sudo modprobe xt_geoip
        lsmod | grep ^xt_geoip
    fi
fi
