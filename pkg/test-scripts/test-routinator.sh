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

    # Check that the Routinator service is enabled
    systemctl is-enabled --quiet routinator

    # Check that the Routinator service is running
    systemctl is-active --quiet routinator

    echo -e "\nROUTINATOR SERVICE STATUS:"
    systemctl status routinator || true

    # Give Routinator time to do something interesting...
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
