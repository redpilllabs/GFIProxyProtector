#!/bin/bash

### Vars ###
VERSION="1.4"
# Platform
DISTRO="$(awk -F= '/^NAME/{print $2}' /etc/os-release)"
DISTRO_VERSION=$(echo "$(awk -F= '/^VERSION_ID/{print $2}' /etc/os-release)" | tr -d '"')
# Colors
RESET="\033[0m"
RED="\033[31m"
GREEN="\033[32m"
B_RED="\033[1;31m"
B_GREEN="\033[1;32m"
B_YELLOW="\033[1;33m"
# Access control
BLOCK_IRAN_OUT_STATUS=""
BLOCK_IRAN_OUT_STATUS_COLOR=$B_RED
BLOCK_OUTSIDERS_STATUS=""
BLOCK_OUTSIDERS_STATUS_COLOR=$B_RED
BLOCK_CHINA_IN_STATUS=""
BLOCK_CHINA_IN_STATUS_COLOR=$B_RED

export DEBIAN_FRONTEND=noninteractive
trap '' INT

# OS check
if ! [[ "$DISTRO" =~ "Ubuntu" || "$DISTRO" =~ "Debian" ]]; then
    echo "$DISTRO"
    echo -e "${B_RED}This installer only supports Debian and Ubuntu OS!${RESET}"
    exit 0
else
    # Version check
    if [[ "$DISTRO" =~ "Ubuntu" ]]; then
        if [ ! "$DISTRO_VERSION" == "20.04" ] && [ ! "$DISTRO_VERSION" == "22.04" ]; then
            echo "Your version of Ubuntu is not supported! Only 20.04 and 22.04 versions are supported."
            exit 0
        fi
    elif [[ "$DISTRO" =~ "Debian GNU/Linux" ]]; then
        if [ ! "$DISTRO_VERSION" == "11" ] && [ ! "$DISTRO_VERSION" == "12" ]; then
            echo "Your version of Debian is not supported! Minimum required version is 11"
            exit 0
        fi
    fi
fi

# Root check
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./run.sh)"
    exit
fi

function fn_check_for_pkg() {
    if [ $(dpkg-query -W -f='${Status}' $1 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
        echo false
    else
        echo true
    fi
}

function fn_check_and_install_pkg() {
    local IS_INSTALLED=$(fn_check_for_pkg $1)
    if [ $IS_INSTALLED = false ]; then
        echo -e "${B_GREEN}\nInstalling '$1'... ${RESET}"
        apt install -y $1
    fi
}

function fn_update_os() {
    # Update the APT cache and installed packages
    echo -e "${B_GREEN}Updating APT cache and OS packages${RESET}"
    apt-get update
    apt-get upgrade -y
}

function fn_install_required_packages() {
    # Install pre-requisites
    echo -e "${B_GREEN}Checking for pre-required packages${RESET}"
    pkgs=("kmod" "dialog" "apt-utils" "procps" "bc" "logrotate" "net-tools")
    for pkg in ${pkgs[@]}; do
        fn_check_and_install_pkg "$pkg"
    done
}

function fn_check_for_newer_kernel() {
    if [[ "$DISTRO" =~ "Debian GNU/Linux" ]]; then
        current_kernel=$(uname -r)
        available_kernels=$(apt-cache search linux-image | grep -oP '[0-9]\.[0-9]+\.[0-9]+-[0-9]+' | sort --version-sort)
        latest_kernel=$(echo "$available_kernels" | tail -n 1)
        if [[ "$latest_kernel" > "$current_kernel" ]]; then
            fn_check_and_install_pkg linux-image-$latest_kernel-amd64
            fn_check_and_install_pkg linux-headers-$latest_kernel-amd64
            echo -e "${B_GREEN}\n\nThere's a newer kernel available for your OS: $available_kernel${RESET}"
            echo -e "${B_RED}You're server is now going to reboot to load the new kernel and the extra moduels required${RESET}"
            echo -e "${B_GREEN}After booting up, run the script again to proceed!${RESET}"
            systemctl reboot
            exit
        else
            fn_check_and_install_pkg linux-image-amd64
            fn_check_and_install_pkg linux-headers-amd64
        fi
    fi
}

function fn_logrotate_kernel() {
    # Remove kern.log from rsyslog since we're going to modify its settings
    sed -i 's!/var/log/kern.log!!g' /etc/logrotate.d/rsyslog
    sed -i '/^\s*$/d' /etc/logrotate.d/rsyslog

    if [ ! -f "/etc/logrotate.d/kernel" ]; then
        touch /etc/logrotate.d/kernel
        sh -c 'echo "/var/log/kern.log
{
	size 20M
    rotate 5
    copytruncate
	missingok
	notifempty
	compress
	delaycompress
	sharedscripts
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}" > /etc/logrotate.d/kernel'
    fi
}

function fn_install_xt_geoip_module() {
    trap - INT
    echo -e "${B_GREEN}Installing xt_geoip module ${RESET}"
    fn_check_and_install_pkg linux-headers-$(uname -r)
    fn_check_and_install_pkg xtables-addons-dkms
    fn_check_and_install_pkg xtables-addons-common
    fn_check_and_install_pkg libtext-csv-xs-perl
    fn_check_and_install_pkg libnet-cidr-lite-perl
    fn_check_and_install_pkg libmoosex-types-netaddr-ip-perl
    fn_check_and_install_pkg pkg-config
    fn_check_and_install_pkg iptables-persistent
    fn_check_and_install_pkg cron
    fn_check_and_install_pkg curl

    # Copy our builder script
    if [ ! -d "/usr/libexec/rainb0w" ]; then
        mkdir -p /usr/libexec/rainb0w
    fi
    cp $PWD/scripts/xt_geoip_build_agg /usr/libexec/rainb0w/xt_geoip_build_agg
    chmod +x /usr/libexec/rainb0w/xt_geoip_build_agg

    # Rotate kernel logs and limit them to max 100MB
    fn_logrotate_kernel

    # Add cronjob to keep the databased updated
    systemctl enable --now cron
    if [ ! -f "/etc/crontab" ]; then
        touch /etc/crontab
    fi
    if ! crontab -l | grep -q "0 1 * * * root bash /usr/libexec/rainb0w/xt_geoip_update.sh >/tmp/xt_geoip_update.log"; then
        echo -e "${B_GREEN}Adding cronjob to update xt_goip database \n  ${RESET}"
        cp $PWD/scripts/xt_geoip_update.sh /usr/libexec/rainb0w/xt_geoip_update.sh
        chmod +x /usr/libexec/rainb0w/xt_geoip_update.sh
        # Check for updates daily
        (
            crontab -l
            echo "0 1 * * * root bash /usr/libexec/rainb0w/xt_geoip_update.sh >/tmp/xt_geoip_update.log"
        ) | crontab -
    fi
}

function fn_increase_connctrack_limit() {
    local MEM=$(free | awk '/^Mem:/{print $2}' | awk '{print $1*1000}')
    local CONNTRACK_MAX=$(awk "BEGIN {print $MEM / 16384 / 2}")
    local CONNTRACK_MAX=$(bc <<<"scale=0; $CONNTRACK_MAX/1")
    if [ "$(sysctl -n net.netfilter.nf_conntrack_max)" -ne "$CONNTRACK_MAX" ]; then
        if [ ! -d "/etc/sysctl.d" ]; then
            mkdir -p /etc/sysctl.d
        fi
        if [ ! -f "/etc/sysctl.d/99-x-firewall.conf" ]; then
            echo -e "${GREEN}Increasing Connection State Tracking Limits ${RESET}"
            touch /etc/sysctl.d/99-x-firewall.conf
            echo "net.netfilter.nf_conntrack_max=$CONNTRACK_MAX" | tee -a /etc/sysctl.d/99-x-firewall.conf
            sysctl -p /etc/sysctl.d/99-x-firewall.conf
            echo -e "${B_GREEN}<<< Finished kernel tuning! >>> ${RESET}"
        fi
    fi
}

function get_latest_db() {
    # Get the latest aggregated CIDR database
    echo -e "${B_GREEN}Getting the latest aggregated database ${RESET}"
    curl -LfsS "https://github.com/redpilllabs/GFIGeoIP/releases/latest/download/agg_cidrs.csv" >/tmp/agg_cidrs.csv

    # Check if it's the first run
    if [ -f "/usr/libexec/rainb0w/agg_cidr.csv" ]; then
        # Check if it is newer than what we already have
        if cmp -s /usr/libexec/rainb0w/agg_cidr.csv /tmp/agg_cidrs.csv; then
            echo -e "${B_GREEN}Already on the latest database! ${RESET}"
            rm /tmp/agg_cidrs.csv
        else
            mv /tmp/agg_cidrs.csv /usr/libexec/rainb0w/agg_cidrs.csv
            # Convert CSV database to binary format for xt_geoip
            echo -e "${B_GREEN}Newer aggregated CIDR database found, updating now... ${RESET}"
            /usr/libexec/rainb0w/xt_geoip_build_agg -s -i /usr/libexec/rainb0w/agg_cidrs.csv
            # Load xt_geoip kernel module
            modprobe xt_geoip
            lsmod | grep ^xt_geoip
        fi
    else
        mv /tmp/agg_cidrs.csv /usr/libexec/rainb0w/agg_cidrs.csv
        # Convert CSV database to binary format for xt_geoip
        echo -e "${B_GREEN}Converting the CIDR database to binary format... ${RESET}"
        /usr/libexec/rainb0w/xt_geoip_build_agg -s -i /usr/libexec/rainb0w/agg_cidrs.csv
        # Load xt_geoip kernel module
        modprobe xt_geoip
        lsmod | grep ^xt_geoip
    fi
}

function fn_rebuild_xt_geoip_database() {
    if [ "$(fn_check_for_pkg xtables-addons-common)" = true ] &&
        [ "$(fn_check_for_pkg libtext-csv-xs-perl)" = true ]; then

        if [ ! -d "/usr/libexec/rainb0w/" ]; then
            mkdir -p /usr/libexec/rainb0w
        fi
        if [ ! -d "/usr/share/xt_geoip" ]; then
            mkdir -p /usr/share/xt_geoip
        fi
        # Copy our builder script if coming from a previous version
        cp $PWD/scripts/xt_geoip_build_agg /usr/libexec/rainb0w/xt_geoip_build_agg
        chmod +x /usr/libexec/rainb0w/xt_geoip_build_agg

        get_latest_db
    else
        fn_install_xt_geoip_module
    fi
}

function reset_firewall() {
    echo -e "\n\n${B_YELLOW}WARNING:${RESET} This will ERASE your iptables settings!\n"
    read -rp "Do you want to continue? (yes/NO): " response
    response=${response:-no}
    response_lc=$(echo "$response" | tr '[:upper:]' '[:lower:]')

    if [[ "$response_lc" == "y" || "$response_lc" == "yes" ]]; then
        echo -e "${B_GREEN}\n\nResetting iptables to default state... ${RESET}"
        sleep 1

        iptables -P INPUT ACCEPT
        ip6tables -P INPUT ACCEPT
        iptables -P FORWARD ACCEPT
        ip6tables -P FORWARD ACCEPT
        iptables -P OUTPUT ACCEPT
        ip6tables -P OUTPUT ACCEPT
        iptables -F
        iptables -X
        iptables -t nat -F
        iptables -t nat -X
        iptables -t mangle -F
        iptables -t mangle -X
        IS_DOCKER_INSTALLED=$(fn_check_for_pkg docker-ce)
        if [ "$IS_DOCKER_INSTALLED" = true ]; then
            systemctl restart docker
        fi

        iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
    else
        echo "Leaving the settings as is..."
    fi
}

function whitelist_necessary_ports() {
    modprobe xt_geoip
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        echo -e "${B_GREEN}\n\nWhitelisting necessary ports ${RESET}"
        sleep 1
        SSH_PORT=$(netstat -tlnp | grep sshd | awk '{print $4}' | awk -F ':' '{print $2}')

        # IPv4 rules
        if ! iptables -L INPUT | grep "Allow established"; then
            echo -e "${B_GREEN}>> Allow established inbound (IPv4) ${RESET}"
            iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Allow established" -j ACCEPT
            iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        fi
        if ! iptables -L OUTPUT | grep "Allow established"; then
            echo -e "${B_GREEN}>> Allow established outbound (IPv4) ${RESET}"
            iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -m comment --comment "Allow established" -j ACCEPT
            iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        fi
        if ! iptables -L INPUT | grep "Allow loopback"; then
            echo -e "${B_GREEN}>> Allow ping to IPv4 ${RESET}"
            iptables -A INPUT -i lo -m comment --comment "Allow loopback" -j ACCEPT
            iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
            iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        fi
        if ! iptables -L INPUT | grep "Allow SSH"; then
            echo -e "${B_GREEN}>> Allow SSH to port ${SSH_PORT} (IPv4) ${RESET}"
            iptables -A INPUT -p tcp --dport $SSH_PORT -m comment --comment "Allow SSH" -j ACCEPT
            iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        fi
        if ! iptables -L INPUT | grep "Allow ping"; then
            echo -e "${B_GREEN}>> Allow ping to IPv4 ${RESET}"
            iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -m comment --comment "Allow ping" -j ACCEPT
            iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        fi

        # IPv6 rules
        if ! ip6tables -L INPUT | grep "Allow established"; then
            echo -e "${B_GREEN}>> Allow established inbound (IPv6) ${RESET}"
            ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "Allow established" -j ACCEPT
            ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
        fi
        if ! ip6tables -L OUTPUT | grep "Allow established"; then
            echo -e "${B_GREEN}>> Allow established outbound (IPv6) ${RESET}"
            ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED -m comment --comment "Allow established" -j ACCEPT
            ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
        fi
        if ! ip6tables -L INPUT | grep "Allow SSH"; then
            echo -e "${B_GREEN}>> Allow SSH to port ${SSH_PORT} (IPv6) ${RESET}"
            ip6tables -A INPUT -p tcp --dport $SSH_PORT -m comment --comment "Allow SSH" -j ACCEPT
            ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
        fi
        if ! ip6tables -L INPUT | grep "Allow ping"; then
            echo -e "${B_GREEN}>> Allow ping to IPv6 ${RESET}"
            ip6tables -A INPUT -p icmpv6 -m comment --comment "Allow ping" -j ACCEPT
            ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
        fi
        if ! iptables -L INPUT | grep "Allow loopback"; then
            echo -e "${B_GREEN}>> Allow ping to IPv6 ${RESET}"
            ip6tables -A INPUT -i lo -m comment --comment "Allow loopback" -j ACCEPT
            ip6tables -A INPUT ! -i lo -s ::1/128 -j REJECT
            ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
        fi

    else
        fn_install_xt_geoip_module
    fi
}

function fn_block_outgoing_iran() {
    modprobe xt_geoip
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        whitelist_necessary_ports

        echo -e "${B_GREEN}\n\nBlocking OUTGOING connections to Iran / China ${RESET}"
        sleep 2

        iptables -I FORWARD -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
        ip6tables -I FORWARD -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
        iptables -A OUTPUT -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
        ip6tables -A OUTPUT -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT

        # Save and cleanup
        iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
    else
        fn_install_xt_geoip_module
    fi
}

function fn_unblock_outgoing_iran() {
    echo -e "${B_GREEN}\n\nUnblocking OUTGOING connections to Iran / China ${RESET}"
    sleep 2

    iptables -D FORWARD -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
    ip6tables -D FORWARD -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
    iptables -D OUTPUT -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT
    ip6tables -D OUTPUT -m geoip --dst-cc IR,CN -m conntrack --ctstate NEW -m comment --comment "Reject outgoing to IR,CN" -j REJECT

    # Save and cleanup
    iptables-save | tee /etc/iptables/rules.v4 >/dev/null
    ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
}

function fn_toggle_iran_outbound_blocking() {
    if [ "$BLOCK_IRAN_OUT_STATUS" = "DEACTIVATED" ]; then
        # Install xtables if not found already
        local IS_INSTALLED=$(fn_check_for_pkg xtables-addons-common)
        if [ "$IS_INSTALLED" = false ]; then
            fn_install_xt_geoip_module
        fi
        fn_block_outgoing_iran
    else
        fn_unblock_outgoing_iran
    fi
}

function fn_update_iran_outbound_blocking_status() {
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        if [ -f "/etc/iptables/rules.v4" ]; then
            local IS_IPTABLES_CONFIGURED=$(cat /etc/iptables/rules.v4 | grep -e 'Reject outgoing to IR,CN')
            if [ "${IS_IPTABLES_CONFIGURED}" ]; then
                BLOCK_IRAN_OUT_STATUS="ACTIVATED"
                BLOCK_IRAN_OUT_STATUS_COLOR=$B_GREEN
            else
                BLOCK_IRAN_OUT_STATUS="DEACTIVATED"
                BLOCK_IRAN_OUT_STATUS_COLOR=$B_RED
            fi
        else
            BLOCK_IRAN_OUT_STATUS="DEACTIVATED"
            BLOCK_IRAN_OUT_STATUS_COLOR=$B_RED
        fi
    else
        BLOCK_IRAN_OUT_STATUS="DEACTIVATED"
        BLOCK_IRAN_OUT_STATUS_COLOR=$B_RED
    fi
}

function fn_block_china_inbound() {
    modprobe xt_geoip
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        echo -e "${B_GREEN}\n\nBlocking connections from China ${RESET}"
        sleep 2

        # Drop connections to/from China
        iptables -A INPUT -m geoip --src-cc CN -m comment --comment "Block China" -j DROP
        ip6tables -A INPUT -m geoip --src-cc CN -m comment --comment "Block China" -j DROP
        # Log any connection attempts originating from China to '/var/log/kern.log' tagged with the prefix below
        iptables -I INPUT -m geoip --src-cc CN -m limit --limit 5/min -j LOG --log-prefix ' ** GFW ** '
        ip6tables -I INPUT -m geoip --src-cc CN -m limit --limit 5/min -j LOG --log-prefix ' ** GFW ** '

        # Save and cleanup
        iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
    else
        fn_install_xt_geoip_module
    fi
}

function fn_unblock_china_inbound() {
    echo -e "${B_GREEN}\n\nUnblocking connections from China ${RESET}"
    sleep 2

    # Disable logs from any connection attempts originating from China to '/var/log/kern.log' tagged with the prefix below
    iptables -D INPUT -m geoip --src-cc CN -m limit --limit 5/min -j LOG --log-prefix ' ** GFW ** '
    ip6tables -D INPUT -m geoip --src-cc CN -m limit --limit 5/min -j LOG --log-prefix ' ** GFW ** '
    # Allow connections to/from China
    iptables -D INPUT -m geoip --src-cc CN -m comment --comment "Block China" -j DROP
    ip6tables -D INPUT -m geoip --src-cc CN -m comment --comment "Block China" -j DROP

    # Save and cleanup
    iptables-save | tee /etc/iptables/rules.v4 >/dev/null
    ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
}

function fn_toggle_china_blocking() {
    if [ "$BLOCK_OUTSIDERS_STATUS" = "ACTIVATED" ]; then
        echo -e "${B_YELLOW}\nYou have enabled outsiders protection which also covers Chinese IP, if you'd like to revert this, disable the outsiders protection. ${RESET}"
        echo -e "Press any key to continue..."
        read -r
    else
        if [ "$BLOCK_CHINA_IN_STATUS" = "DEACTIVATED" ]; then
            # Install xtables if not found already
            local IS_INSTALLED=$(fn_check_for_pkg xtables-addons-common)
            if [ "$IS_INSTALLED" = false ]; then
                fn_install_xt_geoip_module
            fi
            fn_block_china_inbound
        else
            fn_unblock_china_inbound
        fi
    fi
}

function fn_update_china_inbound_blocking_status() {
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        if [ -f "/etc/iptables/rules.v4" ]; then
            local IS_IPTABLES_CONFIGURED=$(cat /etc/iptables/rules.v4 | grep -e 'Block China')
            if [ "${IS_IPTABLES_CONFIGURED}" ]; then
                BLOCK_CHINA_IN_STATUS="ACTIVATED"
                BLOCK_CHINA_IN_STATUS_COLOR=$B_GREEN
            elif [ "$(cat /etc/iptables/rules.v4 | grep -e 'Block outsiders')" ]; then
                BLOCK_CHINA_IN_STATUS="COVERED"
                BLOCK_CHINA_IN_STATUS_COLOR=$B_GREEN
            else
                BLOCK_CHINA_IN_STATUS="DEACTIVATED"
                BLOCK_CHINA_IN_STATUS_COLOR=$B_RED
            fi
        else
            BLOCK_CHINA_IN_STATUS="DEACTIVATED"
            BLOCK_CHINA_IN_STATUS_COLOR=$B_RED
        fi
    else
        BLOCK_CHINA_IN_STATUS="DEACTIVATED"
        BLOCK_CHINA_IN_STATUS_COLOR=$B_RED
    fi
}

function fn_block_outsiders() {
    modprobe xt_geoip
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        whitelist_necessary_ports

        echo -e "${B_GREEN}\n\nBlocking incoming connections not originating from Iran or Cloudflare ${RESET}"
        sleep 2
        INTERFACE=$(ip route get 8.8.8.8 | awk '{print $5}')

        # Log any connection attempts not from Iran/Cloudflare to '/var/log/kern.log' tagged with the prefix below
        iptables -A INPUT -m geoip ! --src-cc IR,CF -m limit --limit 5/min -j LOG --log-prefix '** SUSPECT ** '
        ip6tables -A INPUT -m geoip ! --src-cc IR,CF -m limit --limit 5/min -j LOG --log-prefix '** SUSPECT ** '
        # Drop connections not from Iran/Cloudflare
        iptables -A INPUT -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
        ip6tables -A INPUT -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
        iptables -I FORWARD -i $INTERFACE -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
        ip6tables -I FORWARD -i $INTERFACE -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP

        # Save and cleanup
        iptables-save | tee /etc/iptables/rules.v4 >/dev/null
        ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
    else
        fn_install_xt_geoip_module
    fi
}

function fn_unlock_outsiders() {
    echo -e "${B_GREEN}\n\nUnblocking connections not originating from Iran or Cloudflare ${RESET}"
    sleep 2

    iptables -D INPUT -m geoip ! --src-cc IR,CF -m limit --limit 5/min -j LOG --log-prefix '** SUSPECT ** '
    ip6tables -D INPUT -m geoip ! --src-cc IR,CF -m limit --limit 5/min -j LOG --log-prefix '** SUSPECT ** '
    iptables -D INPUT -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
    ip6tables -D INPUT -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
    iptables -D FORWARD -i $INTERFACE -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP
    ip6tables -D FORWARD -i $INTERFACE -m geoip ! --src-cc IR,CF -m conntrack --ctstate NEW -m comment --comment "Block outsiders" -j DROP

    # Save and cleanup
    iptables-save | tee /etc/iptables/rules.v4 >/dev/null
    ip6tables-save | tee /etc/iptables/rules.v6 >/dev/null
}

function fn_toggle_outsiders_blocking() {
    if [ "$BLOCK_OUTSIDERS_STATUS" = "DEACTIVATED" ]; then
        echo -e "\n\n${B_YELLOW}WARNING:${RESET} This will break TLS certificate creation/renewal and you'd have to manually disable this and renew your certs when necessary!\n"
        read -rp "Do you want to continue? (yes/NO): " response
        response=${response:-no}
        response_lc=$(echo "$response" | tr '[:upper:]' '[:lower:]')

        if [[ "$response_lc" == "y" || "$response_lc" == "yes" ]]; then
            if [ "$BLOCK_CHINA_IN_STATUS" = "ACTIVATED" ]; then
                fn_unblock_china_inbound
            fi
            # Install xtables if not found already
            local IS_INSTALLED=$(fn_check_for_pkg xtables-addons-common)
            if [ "$IS_INSTALLED" = false ]; then
                fn_install_xt_geoip_module
            fi
            fn_block_outsiders
        fi

    else
        fn_unlock_outsiders
    fi
}

function fn_update_outsiders_blocking_status() {
    local IS_MODULE_LOADED=$(lsmod | grep ^xt_geoip)
    if [ ! -z "$IS_MODULE_LOADED" ]; then
        if [ -f "/etc/iptables/rules.v4" ]; then
            local IS_IPTABLES_CONFIGURED=$(cat /etc/iptables/rules.v4 | grep -e 'Block outsiders')
            if [ "${IS_IPTABLES_CONFIGURED}" ]; then
                BLOCK_OUTSIDERS_STATUS="ACTIVATED"
                BLOCK_OUTSIDERS_STATUS_COLOR=$B_GREEN
            else
                BLOCK_OUTSIDERS_STATUS="DEACTIVATED"
                BLOCK_OUTSIDERS_STATUS_COLOR=$B_RED
            fi
        else
            BLOCK_OUTSIDERS_STATUS="DEACTIVATED"
            BLOCK_OUTSIDERS_STATUS_COLOR=$B_RED
        fi
    else
        BLOCK_OUTSIDERS_STATUS="DEACTIVATED"
        BLOCK_OUTSIDERS_STATUS_COLOR=$B_RED
    fi
}

function fn_exit() {
    echo "Quitting!"
    exit 0
}
function fn_fail() {
    echo "Wrong option!"
    sleep 2
}

function fn_print_header() {
    echo -ne "
    #######################################################################
    #                                                                     #
    #                    GFI Proxy Server Protection                      #
    #                           Red Pill Labs                             #
    #                                                                     #
    #          This is a subset of 'Rainb0w Proxy Installer'              #
    #            available at [github.com/redpilllabs/Rainb0w]            #
    #          and it utilizes the aggregated CIDR database               #
    #            available at [github.com/redpilllabs/GFIGeoIP]           #
    #                                                                     #
    #######################################################################
    "
}

function mainmenu() {
    fn_print_header
    # Check and update status variables
    fn_update_iran_outbound_blocking_status
    fn_update_china_inbound_blocking_status
    fn_update_outsiders_blocking_status
    # Display the menu
    echo -ne "

${GREEN}1)${RESET} Block OUTGOING connections to Iran / China:    ${BLOCK_IRAN_OUT_STATUS_COLOR}${BLOCK_IRAN_OUT_STATUS}${RESET}
${GREEN}2)${RESET} Block INCOMING connections from China:   ${BLOCK_CHINA_IN_STATUS_COLOR}${BLOCK_CHINA_IN_STATUS}${RESET}
${GREEN}3)${RESET} Block ALL INCOMING except from Iran / Cloudflare:   ${BLOCK_OUTSIDERS_STATUS_COLOR}${BLOCK_OUTSIDERS_STATUS}${RESET}
${GREEN}4)${RESET} Update IP database
${GREEN}5)${RESET} Reset Firewall Settings
${RED}0)${RESET} Exit

Choose any option: "
    read -r ans
    case $ans in
    5)
        clear
        reset_firewall
        # clear
        mainmenu
        ;;
    4)
        clear
        get_latest_db
        # clear
        mainmenu
        ;;
    3)
        clear
        fn_toggle_outsiders_blocking
        # clear
        mainmenu
        ;;
    2)
        clear
        fn_toggle_china_blocking
        # clear
        mainmenu
        ;;
    1)
        clear
        fn_toggle_iran_outbound_blocking
        # clear
        mainmenu
        ;;
    0)
        fn_exit
        ;;
    *)
        fn_fail
        clear
        mainmenu
        ;;
    esac
}

fn_update_os
fn_check_for_newer_kernel
fn_install_required_packages
fn_install_xt_geoip_module
fn_rebuild_xt_geoip_database
fn_increase_connctrack_limit
mainmenu
