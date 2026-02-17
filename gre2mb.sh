#!/bin/bash
# GRE2MB v1.0
# Created by Bagherijaan

CONFIG_FILE="/etc/gre2mb.conf"
SERVICE_FILE="/etc/systemd/system/gre2mb.service"
SCRIPT_PATH="/usr/local/bin/gre2mb"
LOG_FILE="/var/log/gre2mb.log"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# ------------------ Utility Functions ------------------
is_valid_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        local ip_array=($ip)
        IFS=$OIFS
        [[ ${ip_array[0]} -le 255 && ${ip_array[1]} -le 255 && ${ip_array[2]} -le 255 && ${ip_array[3]} -le 255 ]]
        return $?
    else
        return 1
    fi
}

init_config() {
    if [ ! -f "$CONFIG_FILE" ]; then
        echo -e "SERVER_TYPE=\nKHAREJ_MAIN_IP=\nREMOTE_MAIN_IP=\nFORWARD_PORTS=\nMTU=1436\nSECRET_KEY=gretun2mb" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
}

load_config() {
    [ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE";
}

save_config() {
    cat > "$CONFIG_FILE" <<EOL
SERVER_TYPE=$SERVER_TYPE
KHAREJ_MAIN_IP=$KHAREJ_MAIN_IP
REMOTE_MAIN_IP=$REMOTE_MAIN_IP
FORWARD_PORTS=$FORWARD_PORTS
MTU=$MTU
SECRET_KEY=$SECRET_KEY
EOL
}

generate_ips() {
    local KEY=$1
    local KHAREJ_IP=$2
    local HASH=$(echo -n "${KEY}${KHAREJ_IP}" | md5sum | cut -d' ' -f1)
    
    local OCT2=$(( (0x${HASH:0:2} % 15) + 16 ))
    local OCT3=$(( (0x${HASH:2:2} % 250) + 1 ))

    INT_IPV4_IR="172.${OCT2}.${OCT3}.1"
    INT_IPV4_KH="172.${OCT2}.${OCT3}.2"
    FAKE_IPV6_IR="fd00:${HASH:4:4}:${HASH:8:4}:${HASH:12:4}::fe01"
    FAKE_IPV6_KH="fd00:${HASH:4:4}:${HASH:8:4}:${HASH:12:4}::fe02"
}

check_tunnel() {
    [ -z "$SERVER_TYPE" ] && return 1
    if [ "$SERVER_TYPE" == "IRAN" ]; then
        ip addr show GRE6Tun_To_KH 2>/dev/null | grep -q "UP"
    else
        ip addr show GRE6Tun_To_IR 2>/dev/null | grep -q "UP"
    fi
    return $?
}

check_ping() {
    generate_ips "$SECRET_KEY" "$KHAREJ_MAIN_IP"
    local T=$([ "$SERVER_TYPE" == "IRAN" ] && echo $INT_IPV4_KH || echo $INT_IPV4_IR)
    ping -c 1 -W 1 $T >/dev/null 2>&1
    return $?
}

# ------------------ Tunnel Operations ------------------
stop_tunnel() {
    ip link del 6to4_To_KH 2>/dev/null; ip link del 6to4_To_IR 2>/dev/null
    ip -6 tunnel del GRE6Tun_To_KH 2>/dev/null; ip -6 tunnel del GRE6Tun_To_IR 2>/dev/null
    
    # Clean NAT
    iptables -t nat -D PREROUTING -j GRE2MB_PRE 2>/dev/null
    iptables -t nat -F GRE2MB_PRE 2>/dev/null
    iptables -t nat -X GRE2MB_PRE 2>/dev/null
    
    iptables -t nat -D POSTROUTING -j GRE2MB_POST 2>/dev/null
    iptables -t nat -F GRE2MB_POST 2>/dev/null
    iptables -t nat -X GRE2MB_POST 2>/dev/null

    # Clean Mangle
    iptables -t mangle -D FORWARD -j GRE2MB_MANGLE 2>/dev/null
    iptables -t mangle -F GRE2MB_MANGLE 2>/dev/null
    iptables -t mangle -X GRE2MB_MANGLE 2>/dev/null

    # Clean Input
    iptables -D INPUT -j GRE2MB_INPUT 2>/dev/null
    iptables -F GRE2MB_INPUT 2>/dev/null
    iptables -X GRE2MB_INPUT 2>/dev/null
}

enable_forwarding() {
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_keepalive_time=60" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_keepalive_intvl=10" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_keepalive_probes=6" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1
}

setup_tunnel() {
    stop_tunnel
    generate_ips "$SECRET_KEY" "$KHAREJ_MAIN_IP"
    local LOCAL_IP=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
    [ -z "$LOCAL_IP" ] && LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    [ ! -f /proc/net/if_inet6 ] && { sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null; sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null; }

    # Setup Input Chain
    iptables -N GRE2MB_INPUT 2>/dev/null
    iptables -I INPUT 1 -j GRE2MB_INPUT

    if [ "$SERVER_TYPE" == "IRAN" ]; then
        enable_forwarding
        ip tunnel add 6to4_To_KH mode sit remote $REMOTE_MAIN_IP local $LOCAL_IP
        ip -6 addr add $FAKE_IPV6_IR/64 dev 6to4_To_KH
        ip link set 6to4_To_KH mtu $MTU up
        
        ip -6 tunnel add GRE6Tun_To_KH mode ip6gre remote $FAKE_IPV6_KH local $FAKE_IPV6_IR
        ip addr add $INT_IPV4_IR/30 dev GRE6Tun_To_KH
        ip link set GRE6Tun_To_KH mtu $((MTU - 44)) up
        
        iptables -A GRE2MB_INPUT -i GRE6Tun_To_KH -j ACCEPT

        # NAT Pre (DNAT)
        iptables -t nat -N GRE2MB_PRE 2>/dev/null
        iptables -t nat -A PREROUTING -j GRE2MB_PRE
        
        # NAT Post (Masquerade)
        iptables -t nat -N GRE2MB_POST 2>/dev/null
        iptables -t nat -A POSTROUTING -j GRE2MB_POST
        
        # Mangle (MSS)
        iptables -t mangle -N GRE2MB_MANGLE 2>/dev/null
        iptables -t mangle -A FORWARD -j GRE2MB_MANGLE
        iptables -t mangle -A GRE2MB_MANGLE -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
        
        # Apply Rules
        iptables -t nat -A GRE2MB_POST -o GRE6Tun_To_KH -j MASQUERADE
        for P in ${FORWARD_PORTS//,/ }; do
            iptables -t nat -A GRE2MB_PRE -p tcp --dport $P -j DNAT --to-destination $INT_IPV4_KH:$P
        done
    else
        ip tunnel add 6to4_To_IR mode sit remote $REMOTE_MAIN_IP local $LOCAL_IP
        ip -6 addr add $FAKE_IPV6_KH/64 dev 6to4_To_IR
        ip link set 6to4_To_IR mtu $MTU up
        
        ip -6 tunnel add GRE6Tun_To_IR mode ip6gre remote $FAKE_IPV6_IR local $FAKE_IPV6_KH
        ip addr add $INT_IPV4_KH/30 dev GRE6Tun_To_IR
        ip link set GRE6Tun_To_IR mtu $((MTU - 44)) up
        iptables -A GRE2MB_INPUT -i GRE6Tun_To_IR -j ACCEPT
    fi
}

# ------------------ UI ------------------
print_header() {
    clear
    echo -e "${YELLOW}  ____ ____  _____ ____  __  __ ____  "
    echo " / ___|  _ \| ____|___ \|  \/  | __ ) "
    echo "| |  _| |_) |  _|   __) | |\/| |  _ \ "
    echo "| |_| |  _ <| |___ / __/| |  | | |_) |"
    echo -e " \____|_| \_\_____|_____|_|  |_|____/ ${RESET}"
    echo -e "${WHITE}        GRE6 TURBO TUNNEL v1.0${RESET}"
    echo -e "${CYAN}        Created by Bagherijaan${RESET}\n"
    echo -e "${YELLOW}---------------- Status ----------------${RESET}"
    
    if [ ! -f "$CONFIG_FILE" ] || [ -z "$SERVER_TYPE" ]; then
        echo -e "Server Type: ${RED}Not Configured${RESET}"
    else
        ST_COLOR=$([ "$SERVER_TYPE" == "IRAN" ] && echo "$GREEN" || echo "$BLUE")
        echo -e "Server Type: ${ST_COLOR}$SERVER_TYPE${RESET}"
        
        if check_tunnel; then
            if check_ping; then
                echo -e "Status:      ${GREEN}Active & Healthy ✅${RESET}"
            else
                echo -e "Status:      ${YELLOW}Active (No Traffic) ⚠️${RESET}"
            fi
        else
            echo -e "Status:      ${RED}Inactive ❌${RESET}"
        fi
        
        [ "$SERVER_TYPE" == "IRAN" ] && echo -e "Forwarded Ports: ${BLUE}$FORWARD_PORTS${RESET}"
    fi
    echo -e "${YELLOW}----------------------------------------${RESET}"
}

test_connection() {
    if [ ! -f "$CONFIG_FILE" ]; then echo -e "${RED}Error: Not configured.${RESET}"; sleep 2; return; fi
    generate_ips "$SECRET_KEY" "$KHAREJ_MAIN_IP"
    T4=$([ "$SERVER_TYPE" == "IRAN" ] && echo $INT_IPV4_KH || echo $INT_IPV4_IR)
    T6=$([ "$SERVER_TYPE" == "IRAN" ] && echo $FAKE_IPV6_KH || echo $FAKE_IPV6_IR)
    echo -e "\n${BLUE}Testing Connection...${RESET}"
    echo -e "+--------------+---------------------------------------+----------+"
    echo -e "| Target       | IP Address                            | Latency  |"
    echo -e "+--------------+---------------------------------------+----------+"
    P=$(ping -c 3 -W 5 $T4 | grep 'time=' | awk -F'time=' '{print $2}')
    [ -n "$P" ] && printf "| Tunnel GRE6  | %-37s | ${GREEN}%-8s${RESET} |\n" "$T4" "$P" || printf "| Tunnel GRE6  | %-37s | ${RED}%-8s${RESET} |\n" "$T4" "FAIL"
    P=$(ping6 -c 3 -W 5 $T6 | grep 'time=' | awk -F'time=' '{print $2}')
    [ -n "$P" ] && printf "| Tunnel 6to4  | %-37s | ${GREEN}%-8s${RESET} |\n" "$T6" "$P" || printf "| Tunnel 6to4  | %-37s | ${RED}%-8s${RESET} |\n" "$T6" "FAIL"
    echo -e "+--------------+---------------------------------------+----------+"
    read -p "Press Enter..."
}

# ------------------ Main Menu ------------------
main_menu() {
    while true; do
        print_header
        echo "1) Install & Reconfigure"
        echo "2) Manage Tunnel"
        echo "3) Full Uninstall"
        echo "0) Exit"
        read -p "Selection: " choice
        
        case $choice in
            1)
                while true; do
                    read -p "Server Type [1: IRAN / 2: KHAREJ]: " T
                    if [[ "$T" == "1" ]]; then SERVER_TYPE="IRAN"; break;
                    elif [[ "$T" == "2" ]]; then SERVER_TYPE="KHAREJ"; break;
                    else echo -e "${RED}Invalid selection!${RESET}"; fi
                done
                
                IP_DETECTED=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $7; exit}')
                [ -z "$IP_DETECTED" ] && IP_DETECTED=$(hostname -I | awk '{print $1}')

                while true; do
                    read -p "Enter Current Server IP [$IP_DETECTED]: " USER_IP
                    IP_D=${USER_IP:-$IP_DETECTED}
                    if is_valid_ip "$IP_D"; then break; else echo -e "${RED}Invalid IP format! Try again.${RESET}"; fi
                done
                
                LABEL=$([ "$SERVER_TYPE" == "IRAN" ] && echo "KHAREJ IP" || echo "IRAN IP")
                
                while true; do
                    read -p "Enter $LABEL: " REMOTE_MAIN_IP
                    if is_valid_ip "$REMOTE_MAIN_IP"; then break; else echo -e "${RED}Invalid IP format! Try again.${RESET}"; fi
                done
                
                [ "$SERVER_TYPE" == "KHAREJ" ] && KHAREJ_MAIN_IP=$IP_D || KHAREJ_MAIN_IP=$REMOTE_MAIN_IP
                
                read -p "Secret Key [Default: gretun2mb]: " S
                SECRET_KEY=${S:-"gretun2mb"}
                
                MTU=1436; 
                [ "$SERVER_TYPE" == "IRAN" ] && read -p "Forward Ports [e.g. 80,443]: " FORWARD_PORTS
                
                init_config; save_config; setup_tunnel
                
                cat > "$SERVICE_FILE" <<EOL
[Unit]
Description=GRE2MB Tunnel
After=network-online.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH start
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOL
                systemctl daemon-reload && systemctl enable gre2mb.service >/dev/null 2>&1
                (crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH"; echo "*/5 * * * * $SCRIPT_PATH cron") | crontab -
                read -p "Success! Auto-Healing & Persistence enabled. Press Enter..."
                ;;
                
            2)
                while true; do
                    print_header
                    echo -e "1) Test Connection"
                    echo -e "2) Regenerate IPs"
                    echo -e "3) Change MTU"
                    [ "$SERVER_TYPE" == "IRAN" ] && echo -e "4) Change Forward Ports"
                    echo -e "0) Back"
                    read -p "Selection: " sc
                    
                    case $sc in
                        1) test_connection ;;
                        2) read -p "New Key [$SECRET_KEY]: " nk; SECRET_KEY=${nk:-$SECRET_KEY}; save_config; setup_tunnel; sleep 1 ;;
                        3) read -p "New MTU [$MTU]: " nm; MTU=${nm:-$MTU}; save_config; setup_tunnel; sleep 1 ;;
                        4) 
                            if [ "$SERVER_TYPE" == "IRAN" ]; then
                                read -p "New Forward Ports [Current: $FORWARD_PORTS]: " np
                                FORWARD_PORTS=${np:-$FORWARD_PORTS}
                                save_config; setup_tunnel; sleep 2
                            fi
                            ;;
                        0) break ;;
                    esac
                done
                ;;
                
            3)
                if [ ! -f "$CONFIG_FILE" ]; then echo -e "${RED}Error: Not installed.${RESET}"; sleep 2; continue; fi
                read -p "Confirm full uninstall? [y/n]: " cf
                if [[ "$cf" == "y" || "$cf" == "Y" ]]; then
                    systemctl disable --now gre2mb.service 2>/dev/null
                    stop_tunnel
                    rm -f "$SERVICE_FILE" "$CONFIG_FILE" "$LOG_FILE"
                    crontab -l 2>/dev/null | grep -v "$SCRIPT_PATH" | crontab -
                    echo -e "\n${RED}Goodbye! 🥲${RESET}\n"
                    rm -f "$SCRIPT_PATH" "$0"
                    exit
                fi
                ;;
            0) exit ;;
        esac
    done
}

# ------------------ Logic ------------------
load_config
if [ "$1" == "start" ]; then
    [ -n "$SERVER_TYPE" ] && setup_tunnel
elif [ "$1" == "cron" ]; then
    if [ -n "$SERVER_TYPE" ]; then
        if ! check_tunnel || ! check_ping || ! systemctl is-active --quiet gre2mb.service; then
            systemctl start gre2mb.service 2>/dev/null
            setup_tunnel
            echo "[$(date)] Tunnel repaired" >> "$LOG_FILE"
        fi
    fi
else
    main_menu
fi

