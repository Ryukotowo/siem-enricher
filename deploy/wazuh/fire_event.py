"""Отправка события в очередь Wazuh для проверки активного реагирования."""

from __future__ import annotations

import json
import socket
import sys

SOCKET = "/var/ossec/queue/sockets/queue"


def main() -> int:
    payload = sys.argv[1] if len(sys.argv) > 1 else json.dumps(
        {"dlp": {"decision": "block", "file": "/tmp/secret.txt", "rule": "POL-013"}}
    )
    message = f"1:wazuh-manager:{payload}".encode("utf-8")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    client.sendto(message, SOCKET)
    client.close()
    print(f"отправлено: {payload}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
