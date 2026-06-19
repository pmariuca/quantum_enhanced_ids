#!/bin/bash

LOG_DIR="/var/log/qks"
SERVICE_NAME="qks-daemon"

case "$1" in
    start)
        echo "Starting QKS daemon..."
        sudo systemctl start "$SERVICE_NAME"
        sleep 1
        sudo systemctl status "$SERVICE_NAME" --no-pager
        ;;
    stop)
        echo "Stopping QKS daemon..."
        sudo systemctl stop "$SERVICE_NAME"
        echo "Stopped."
        ;;
    restart)
        echo "Restarting QKS daemon..."
        sudo systemctl restart "$SERVICE_NAME"
        sleep 1
        sudo systemctl status "$SERVICE_NAME" --no-pager
        ;;
    status)
        sudo systemctl status "$SERVICE_NAME" --no-pager
        ;;
    logs)
        echo "Tailing daemon logs (Ctrl+C to exit)..."
        sudo journalctl -u "$SERVICE_NAME" -f --no-pager
        ;;
    logs-json)
        echo "Tailing event JSON logs (Ctrl+C to exit)..."
        tail -f /opt/qks/policy/events.jsonl | jq . 2>/dev/null || tail -f /opt/qks/policy/events.jsonl
        ;;
    enable)
        echo "Enabling daemon to start on boot..."
        sudo systemctl enable "$SERVICE_NAME"
        echo "Enabled."
        ;;
    disable)
        echo "Disabling daemon auto-start..."
        sudo systemctl disable "$SERVICE_NAME"
        echo "Disabled."
        ;;
    reload-policy)
        echo "Reloading policy (sends SIGUSR1)..."
        PID=$(sudo systemctl show -p MainPID --value "$SERVICE_NAME")
        if [ "$PID" != "0" ] && [ -n "$PID" ]; then
            sudo kill -USR1 "$PID"
            echo "Policy reload signal sent to PID $PID"
        else
            echo "Daemon not running"
            exit 1
        fi
        ;;
    *)
        echo "QKS Daemon Management Helper"
        echo ""
        echo "Usage: $0 {start|stop|restart|status|logs|logs-json|enable|disable|reload-policy}"
        echo ""
        echo "Commands:"
        echo "  start          - Start the daemon"
        echo "  stop           - Stop the daemon"
        echo "  restart        - Restart the daemon"
        echo "  status         - Show daemon status"
        echo "  logs           - View daemon logs (systemd journal)"
        echo "  logs-json      - View event JSON logs"
        echo "  enable         - Enable auto-start on boot"
        echo "  disable        - Disable auto-start on boot"
        echo "  reload-policy  - Reload policy files (SIGUSR1)"
        echo ""
        exit 1
        ;;
esac
