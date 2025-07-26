"""
mitm_tamper_script.py - 中间人攻击测试脚本
================================================

该脚本实现了一个简单的 TCP 代理，用于模拟中间人攻击场景。在 TLS 加密保护下，中间人无法解密或修改传输内容。

运行方式：

```
python mitm_tamper_script.py --listen-port 6002 --target-host localhost --target-port 5001
```

客户端连接到本地 6002 端口，代理再连接真实的 TLS 服务端 5001。代理打印捕获到的十六进制数据，但由于数据被 TLS 加密，原文不可读，修改任何字节都会导致 TLS 握手失败。
"""

from __future__ import annotations

import argparse
import socket
import threading


def hexdump(data: bytes, length: int = 16) -> str:
    """将字节序列转换为十六进制字符串供调试。"""
    return ' '.join(f"{b:02x}" for b in data)


def proxy_connection(client_sock: socket.socket, target_host: str, target_port: int) -> None:
    try:
        with socket.create_connection((target_host, target_port)) as server_sock:
            # 双向转发线程
            def forward(src: socket.socket, dst: socket.socket, label: str) -> None:
                try:
                    while True:
                        data = src.recv(65536)
                        if not data:
                            break
                        print(f"[{label}] {len(data)} bytes: {hexdump(data[:32])}{'...' if len(data) > 32 else ''}")
                        # 不修改数据，直接转发
                        dst.sendall(data)
                except Exception:
                    pass
                finally:
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
            t1 = threading.Thread(target=forward, args=(client_sock, server_sock, 'client->server'))
            t2 = threading.Thread(target=forward, args=(server_sock, client_sock, 'server->client'))
            t1.start(); t2.start()
            t1.join(); t2.join()
    finally:
        client_sock.close()


def main():
    parser = argparse.ArgumentParser(description="简单的 TLS 中间人代理 (仅用于教育目的)")
    parser.add_argument("--listen-port", type=int, required=True, help="代理监听端口")
    parser.add_argument("--target-host", required=True, help="目标服务器地址")
    parser.add_argument("--target-port", type=int, required=True, help="目标服务器端口")
    args = parser.parse_args()
    with socket.create_server(('0.0.0.0', args.listen_port), reuse_port=True) as listen_sock:
        print(f"[proxy] 监听端口 {args.listen_port}，转发到 {args.target_host}:{args.target_port}")
        while True:
            client_sock, addr = listen_sock.accept()
            print(f"[proxy] 来自 {addr} 的连接")
            threading.Thread(target=proxy_connection, args=(client_sock, args.target_host, args.target_port), daemon=True).start()


if __name__ == '__main__':
    main()