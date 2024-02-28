#!/bin/sh

FLAG_FILE="/var/run/aesdsocket.started"

case "$1" in
    start)
        if [ ! -e "$FLAG_FILE" ]; then
            echo "Aesdsocket called for the first time"
            sleep 15
            start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
            touch "$FLAG_FILE"
        else
            
            echo "Starting aesdsocket for the second time"
            start-stop-daemon -S -n aesdsocket -a /usr/bin/aesdsocket -- -d
            touch "$FLAG_FILE"
        fi
        ;;
    stop)
        if ps aux | grep -q '[a]esdsocket'; then
            echo "Stopping aesdsocket"
            start-stop-daemon -K -n aesdsocket
            rm -f "$FLAG_FILE"
        else
            echo "No aesdsocket is running"

        fi
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

exit 0
