#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nROUTINATOR VERSION:"
    routinator --version

    echo -e "\nROUTINATOR CONF:"
    cat /etc/routinator/routinator.conf

    echo -e "\nROUTINATOR DATA DIR:"
    ls -la /var/lib/routinator

    echo -e "\nROUTINATOR SERVICE STATUS BEFORE ENABLE:"
    systemctl status routinator || true

    echo -e "\nINIT ROUTINATOR:"
    sudo routinator-init --accept-arin-rpa

    echo -e "\nROUTINATOR DATA DIR AFTER INIT:"
    ls -la /var/lib/routinator

    echo -e "\nENABLE ROUTINATOR SERVICE:"
    systemctl enable routinator

    echo -e "\nROUTINATOR SERVICE STATUS AFTER ENABLE:"
    systemctl status routinator || true

    echo -e "\nSTART ROUTINATOR SERVICE:"
    systemctl start routinator
    
    sleep 15s

    echo -e "\nROUTINATOR LOGS AFTER START:"
    journalctl --unit=routinator

    echo -e "\nROUTINATOR SERVICE STATUS AFTER START:"
    systemctl status routinator
    
    echo -e "\nROUTINATOR MAN PAGE:"
    man -P cat routinator

    echo -e "\nROUTINATOR TALS DIR:"
    ls -la /var/lib/routinator/tals/

    echo -e "\nROUTINATOR RPKI CACHE DIR (first 20 lines of ls output only):"
    ls -ltR /var/lib/routinator/rpki-cache/ | head -n 20
    ;;

  post-upgrade)
    echo -e "\nROUTINATOR VERSION:"
    routinator --version
    
    echo -e "\nROUTINATOR CONF:"
    cat /etc/routinator/routinator.conf
    
    echo -e "\nROUTINATOR DATA DIR:"
    ls -la /var/lib/routinator
    
    echo -e "\nROUTINATOR SERVICE STATUS:"
    systemctl status routinator || true
    
    echo -e "\nROUTINATOR MAN PAGE:"
    man -P cat routinator
    
    echo -e "\nROUTINATOR TALS DIR:"
    ls -la /var/lib/routinator/tals/
    
    echo -e "\nROUTINATOR RPKI CACHE DIR (first 20 lines of ls output only):"
    ls -ltR /var/lib/routinator/rpki-cache/ | head -n 20
    ;;
esac
