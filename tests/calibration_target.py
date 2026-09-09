"""Loopback protocol target used by managed-process calibration tests."""
import socket
import sys


if __name__ == "__main__":
    with socket.socket() as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", int(sys.argv[1])))
        server.listen(1)
        connection, _ = server.accept()
        with connection:
            buffer = b""
            while True:
                block = connection.recv(4096)
                if not block:
                    break
                buffer += block
                while b"\r\n\r\n" in buffer:
                    request, buffer = buffer.split(b"\r\n\r\n", 1)
                    method = request.split(b" ", 1)[0]
                    if method == b"CLOSE":
                        sys.exit(0)
                    code = b"403 Forbidden" if method == b"BAD" else b"200 OK"
                    headers = b"Content-Length: 4\r\n"
                    if method == b"SETUP":
                        headers += b"Session: CALIB123\r\n"
                    connection.sendall(b"RTSP/1.0 " + code + b"\r\n" + headers + b"\r\nbody")
