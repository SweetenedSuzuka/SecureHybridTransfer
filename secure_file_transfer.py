"""
secure_file_transfer.py - 核心加密传输实现
================================================

该模块提供文件发送和接收功能，通过 TLS 建立安全信道，并可选用数字签名验证文件完整性。协议格式清晰，便于在测试脚本和 GUI 中复用。

协议概要：

* 首先发送 1 个字节作为签名标志（0 表示无签名，1 表示有签名）。
* 发送 4 字节无符号整数（大端），表示主文件名长度；随后发送该名称的 UTF‑8 编码字节。
* 发送 8 字节无符号整数（大端），表示主文件大小；随后发送文件内容。
* 若签名标志为 1，则重复上述步骤发送签名文件：4 字节长度、文件名、8 字节大小、内容。

接收端解析完成后保存文件（及签名文件），若启用签名验证，则调用 ``base.verify_signature`` 对文件和签名进行校验。

注意：该模块不对文件内容应用额外的对称加密，而是依赖 TLS 提供的加密和完整性保证【244810917859368†L321-L337】。如需在应用层进一步加密，可在此基础上整合 AES 等算法。
"""

from __future__ import annotations

import os
import socket
import struct
from pathlib import Path
from typing import Optional

import ssl

from . import base


def _recv_all(conn: ssl.SSLSocket, length: int) -> bytes:
    """从连接中接收指定长度数据。"""
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("接收数据时连接中断")
        data.extend(chunk)
    return bytes(data)


def send_file(host: str, port: int, file_path: Path | str,
              insecure: bool = False, sign: bool = False) -> None:
    """发送文件到指定的 TLS 服务端。

    Args:
        host: 服务端主机名或 IP。
        port: 服务端端口。
        file_path: 要发送的文件路径。
        insecure: 如果为 True，则禁用证书验证（仅用于测试）。
        sign: 如果为 True，则使用私钥对文件生成签名并一同发送。
    """
    file_path = Path(file_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"文件不存在: {file_path}")
    # 创建签名（如需要）
    signature_file: Optional[Path] = None
    if sign:
        # 使用默认私钥文件生成签名
        signature_file = base.sign_file(file_path, base.KEY_FILE)
    # 准备文件名和大小
    filename_bytes = file_path.name.encode('utf-8')
    file_size = file_path.stat().st_size
    sign_flag = 1 if signature_file else 0
    context = base.create_client_context(cert_file=base.CERT_FILE, insecure=insecure)
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host if not insecure else None) as tls:
            # 发送签名标志
            tls.sendall(struct.pack('!B', sign_flag))
            # 主文件名长度 + 名称
            tls.sendall(struct.pack('!I', len(filename_bytes)))
            tls.sendall(filename_bytes)
            # 主文件大小 + 内容
            tls.sendall(struct.pack('!Q', file_size))
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    tls.sendall(chunk)
            # 如果有签名则发送签名文件
            if signature_file:
                sig_name_bytes = signature_file.name.encode('utf-8')
                sig_size = signature_file.stat().st_size
                tls.sendall(struct.pack('!I', len(sig_name_bytes)))
                tls.sendall(sig_name_bytes)
                tls.sendall(struct.pack('!Q', sig_size))
                with open(signature_file, 'rb') as f:
                    while True:
                        chunk = f.read(65536)
                        if not chunk:
                            break
                        tls.sendall(chunk)
    print(f"发送完成: {file_path.name}")


def receive_files(host: str, port: int, out_dir: Path | str,
                  verify_signature: bool = False) -> None:
    """作为服务端接收文件。

    支持连续处理多次连接，每个连接可选择携带签名文件。接收完毕后保存文件至 ``out_dir``，如启用 ``verify_signature`` 且接收到签名文件，则调用 ``base.verify_signature`` 验证。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    context = base.create_server_context(base.CERT_FILE, base.KEY_FILE)
    with socket.create_server((host, port), reuse_port=True) as server_sock:
        print(f"[receive] 监听 {host}:{port}")
        while True:
            client_sock, addr = server_sock.accept()
            print(f"[receive] 客户端连接自 {addr}")
            try:
                with context.wrap_socket(client_sock, server_side=True) as tls:
                    # 签名标志
                    sign_flag_raw = _recv_all(tls, 1)
                    (sign_flag,) = struct.unpack('!B', sign_flag_raw)
                    # 主文件名
                    name_len_raw = _recv_all(tls, 4)
                    (name_len,) = struct.unpack('!I', name_len_raw)
                    filename_bytes = _recv_all(tls, name_len)
                    filename = filename_bytes.decode('utf-8', errors='replace')
                    # 主文件大小
                    size_raw = _recv_all(tls, 8)
                    (size,) = struct.unpack('!Q', size_raw)
                    # 保存主文件
                    file_path = out_dir / filename
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    remaining = size
                    with open(file_path, 'wb') as f:
                        while remaining > 0:
                            chunk = tls.recv(min(65536, remaining))
                            if not chunk:
                                raise ConnectionError("文件传输中断")
                            f.write(chunk)
                            remaining -= len(chunk)
                    print(f"[receive] 已保存: {file_path}")
                    # 如果有签名文件，接收并验证
                    if sign_flag:
                        sig_name_len_raw = _recv_all(tls, 4)
                        (sig_name_len,) = struct.unpack('!I', sig_name_len_raw)
                        sig_name_bytes = _recv_all(tls, sig_name_len)
                        sig_filename = sig_name_bytes.decode('utf-8', errors='replace')
                        sig_size_raw = _recv_all(tls, 8)
                        (sig_size,) = struct.unpack('!Q', sig_size_raw)
                        sig_path = out_dir / sig_filename
                        remaining = sig_size
                        with open(sig_path, 'wb') as sf:
                            while remaining > 0:
                                chunk = tls.recv(min(65536, remaining))
                                if not chunk:
                                    raise ConnectionError("签名传输中断")
                                sf.write(chunk)
                                remaining -= len(chunk)
                        print(f"[receive] 已保存签名: {sig_path}")
                        if verify_signature:
                            ok = base.verify_signature(file_path, base.CERT_FILE, sig_path)
                            if ok:
                                print(f"[verify] 签名验证通过: {file_path.name}")
                            else:
                                print(f"[verify] 签名验证失败: {file_path.name}")
            except Exception as e:
                print(f"[receive] 错误: {e}")
            finally:
                client_sock.close()