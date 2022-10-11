#!/usr/bin/env bash

set -eo pipefail
set -x

case $1 in
  post-install)
    echo -e "\nROUTINATOR VERSION:"
    VER=$(routinator --version)
    echo $VER

    echo -e "\nROUTINATOR CONF:"
    cat /etc/routinator/routinator.conf

    echo -e "\nROUTINATOR DATA DIR:"
    ls -la /var/lib/routinator

    # For newer Routinator init is no longer required and the Routinator service should be automatically enabled and
    # started, for 0.11.3 and earlier init had to be done first and then the service manually enabled and started:
    if [[ "$VER" == "0.11.3" ]]; then
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

      echo -e "\nROUTINATOR TALS DIR:"
      ls -la /var/lib/routinator/tals/
    fi

    echo -e "\nROUTINATOR SERVICE SHOULD BE ENABLED:"
    systemctl is-enabled --quiet routinator

    echo -e "\nROUTINATOR SERVICE SHOULD BE ACTIVE:"
    systemctl is-active --quiet routinator

    sleep 15s

    echo -e "\nROUTINATOR LOGS AFTER START:"
    journalctl --unit=routinator
    
    echo -e "\nROUTINATOR MAN PAGE (first 20 lines only):"
    man -P cat routinator | head -n 20 || true

    echo -e "\nROUTINATOR RPKI CACHE DIR (first 20 lines of ls output only):"
    ls -ltR /var/lib/routinator/rpki-cache/ | head -n 20 || true
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
  
    echo -e "\nOLD ROUTINATOR-INIT SCRIPT SHOULD NOT EXIST:"
    if [ -f /usr/bin/routinator-init ]; then
      echo >&2 "ERROR: /usr/bin/routinator-init exists but should have been removed if it was present"
      exit 1
    fi

    echo -e "\nROUTINATOR RPKI CACHE DIR (first 20 lines of ls output only):"
    ls -ltR /var/lib/routinator/rpki-cache/ | head -n 20 || true
    ;;
esac
