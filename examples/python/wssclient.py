#!/usr/bin/env python3
import ssl
import websocket
import json
import sys

if __name__ == "__main__":
    # websocket.enableTrace(True)
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})

    try:
        ws.connect("wss://localhost:3000")
    except ConnectionRefusedError as e:
        print(f"error: {e}")
        sys.exit(1)
    except websocket.WebSocketAddressException as e:
        print(f"error: {e}")
        sys.exit(1)

    msg = {
        "jsonrpc": "2.0",
        "method": "test",
        "params": {"greeting": "Hello Echo"},
        "id": "42",
    }
    ws.send(json.dumps(msg))
    print(ws.recv())
    ws.close()
