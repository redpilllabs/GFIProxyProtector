#!/bin/bash

### Vars ###
VERSION="1.0"
# Platform
DISTRO="$(awk -F= '/^NAME/{print $2}' /etc/os-release)"
DISTRO_VERSION=$(echo "$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release)" | tr -d '"')
# Colors
RESET="\033[0m"
RED="\033[31m"
GREEN="\033[32m"
B_RED="\033[1;31m"
B_GREEN="\033[1;32m"

# OS check
if ! [[ "$DISTRO" =~ "Ubuntu" || "$DISTRO" =~ "Debian" ]]; then
    echo "$DISTRO"
    echo -e "${B_RED}This installer only supports Debian and Ubuntu OS!${RESET}"
    exit 0
else
    # Version check
    if [[ "$DISTRO" =~ "Ubuntu" ]]; then
        if (($(echo "$DISTRO_VERSION < 20.04" | bc -l))); then
            echo "Your version of Ubuntu is not supported! Minimum required version is 20.04"
            exit 0
        fi
    elif [[ "$DISTRO" =~ "Debian GNU/Linux" ]]; then
        if (($(echo "$DISTRO_VERSION < 11" | bc -l))); then
            echo "Your version of Debian is not supported! Minimum required version is 11"
            exit 0
        fi
    fi
fi

function fn_block_outbound_connections_to_iran() {
    echo -e "${B_GREEN}### Installing required packages for GeoIP blocking \n  ${RESET}"
    sudo apt install -y \
        xtables-addons-dkms \
        xtables-addons-common \
        libtext-csv-xs-perl \
        libmoosex-types-netaddr-ip-perl \
        pkg-config \
        iptables-persistent \
        gzip \
        wget \
        cron

    # Download the latest GeoIP database
    MON=$(date +"%m")
    YR=$(date +"%Y")
    sudo mkdir /usr/share/xt_geoip
    sudo wget "https://download.db-ip.com/free/dbip-country-lite-${YR}-${MON}.csv.gz" -O /usr/share/xt_geoip/dbip-country-lite.csv.gz
    sudo gunzip /usr/share/xt_geoip/dbip-country-lite.csv.gz

    # Convert CSV database to binary format for xt_geoip
    if [[ "$DISTRO" =~ "Ubuntu" ]]; then
        if (($(echo "$DISTRO_VERSION == 20.04" | bc -l))); then
            sudo /usr/lib/xtables-addons/xt_geoip_build -D /usr/share/xt_geoip/ -S /usr/share/xt_geoip/
        elif (($(echo "$DISTRO_VERSION == 22.04" | bc -l))); then
            sudo /usr/libexec/xtables-addons/xt_geoip_build -s -i /usr/share/xt_geoip/dbip-country-lite.csv.gz
        fi
    elif [[ "$DISTRO" =~ "Debian GNU/Linux" ]]; then
        if (($(echo "$DISTRO_VERSION == 11" | bc -l))); then
            sudo /usr/libexec/xtables-addons/xt_geoip_build -s -i /usr/share/xt_geoip/dbip-country-lite.csv.gz
        fi
    fi

    # Load xt_geoip kernel module
    modprobe xt_geoip
    lsmod | grep ^xt_geoip

    # Block outgoing connections to Iran
    sudo iptables -A OUTPUT -m geoip --dst-cc IR -j DROP

    # Save and cleanup
    sudo iptables-save | sudo tee /etc/iptables/rules.v4
    sudo ip6tables-save | sudo tee /etc/iptables/rules.v6
    sudo rm /usr/share/xt_geoip/dbip-country-lite.csv
}

function fn_enable_xtgeoip_cronjob() {
    if [ "$(lsmod | grep ^xt_geoip)" ]; then
        # Enable cronjobs service for future automatic updates
        sudo systemctl enable cron
        if [ ! "$(cat /etc/crontab | grep ^xt_geoip_update)" ]; then
            echo -e "${B_GREEN}### Adding cronjob to update xt_goip database \n  ${RESET}"
            sudo cp ./xt_geoip_update.sh /usr/share/xt_geoip/xt_geoip_update.sh
            sudo chmod +x /usr/share/xt_geoip/xt_geoip_update.sh
            sudo touch /etc/crontab
            # Run on the second day of each month
            echo "0 0 2 * * root bash /usr/share/xt_geoip/xt_geoip_update.sh >/tmp/xt_geoip_update.log" | sudo tee -a /etc/crontab >/dev/null
        else
            echo -e "${GREEN}### Cronjob already exists! \n  ${RESET}"
        fi
    else
        echo -e "${B_RED}### xt_geoip Kernel module is not loaded! \n  ${RESET}"
    fi
}

echo -e "${B_GREEN}This script will install xt_geoip Kernel module which enables GeoIP-based oprations with iptables,"
echo -e "more specifically it will configure iptables to drop any outbound connection to Iran${RESET}"
read -p "$(echo -e "Proceed to installation? (Y/n): ")" confirm
if [[ "$confirm" == [yY] || "$confirm" == [yY][eE][sS] || "$confirm" == "" ]]; then
    fn_block_outbound_connections_to_iran
    fn_enable_xtgeoip_cronjob
    echo -e "${B_GREEN}Finished installation! ${RESET}"
else
    echo -e "Okay! Come back if you changed your mind! ;)"
fi
