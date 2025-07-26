"""
base.py - 公共辅助函数
=======================

此模块包含本项目的公共函数，包括证书生成、TLS 上下文创建和数字签名辅助工具。通过将基础功能集中于此，可以方便发送端和接收端脚本共享逻辑。
"""

from __future__ import annotations

import os
import subprocess
import ssl
from pathlib import Path
from typing import Optional, Tuple


CERT_FILE = Path(__file__).with_name("server.crt")
KEY_FILE = Path(__file__).with_name("server.key")


def generate_self_signed_cert(cn: str = "localhost", cert_file: Path | str = CERT_FILE,
                              key_file: Path | str = KEY_FILE,
                              days: int = 365) -> None:
    """生成自签名证书和对应私钥。

    依赖系统中的 ``openssl`` 工具。当证书或私钥文件存在时会先删除，避免交互式覆盖提示。

    Args:
        cn: 证书的 Common Name。
        cert_file: 证书文件路径。
        key_file: 私钥文件路径。
        days: 证书有效期（天）。
    """
    cert_file = Path(cert_file)
    key_file = Path(key_file)
    for p in (cert_file, key_file):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    cmd = [
        "openssl", "req", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key_file), "-x509", "-days", str(days), "-out",
        str(cert_file), "-subj", f"/CN={cn}"
    ]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("系统未安装 openssl，无法生成证书")


def create_server_context(cert_file: Path | str = CERT_FILE,
                          key_file: Path | str = KEY_FILE) -> ssl.SSLContext:
    """创建服务端 TLS 上下文。"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    return context


def create_client_context(cert_file: Optional[Path | str] = CERT_FILE,
                          insecure: bool = False) -> ssl.SSLContext:
    """创建客户端 TLS 上下文。

    如果 ``insecure`` 为 True，则禁用证书验证（仅用于测试）。否则加载给定证书作为受信任根证书。
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        context.load_verify_locations(cafile=str(cert_file))
    return context


def sign_file(file_path: Path | str, private_key: Path | str,
              signature_path: Optional[Path | str] = None) -> Path:
    """使用私钥对文件计算 SHA‑256 散列并生成签名。

    Args:
        file_path: 待签名文件。
        private_key: RSA 私钥文件。
        signature_path: 输出签名文件路径，默认在同目录下加 `.sig` 后缀。

    Returns:
        生成的签名文件路径。
    """
    file_path = Path(file_path)
    private_key = Path(private_key)
    if signature_path is None:
        signature_path = file_path.with_suffix(file_path.suffix + ".sig")
    signature_path = Path(signature_path)
    cmd = [
        "openssl", "dgst", "-sha256", "-sign", str(private_key),
        "-out", str(signature_path), str(file_path)
    ]
    subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return signature_path


def verify_signature(file_path: Path | str, cert_file: Path | str,
                     signature_path: Path | str) -> bool:
    """验证文件的 SHA‑256 签名。

    使用公钥证书验证对应签名是否来自持有私钥的人。返回验证结果。

    Args:
        file_path: 原文件。
        cert_file: 包含公钥的证书文件。
        signature_path: 签名文件。

    Returns:
        True 表示验证成功；False 表示验证失败。
    """
    file_path = Path(file_path)
    cert_file = Path(cert_file)
    signature_path = Path(signature_path)
    # 使用证书提取公钥后再验证。
    # openssl dgst 的 -verify 选项需要公钥 PEM，而不能直接传入证书文件。
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as tmp_pub:
        tmp_pub_path = Path(tmp_pub.name)
    try:
        # 提取证书中的公钥
        extract_cmd = [
            "openssl", "x509", "-in", str(cert_file), "-pubkey", "-noout"
        ]
        with open(tmp_pub_path, 'w') as out_f:
            subprocess.check_call(extract_cmd, stdout=out_f, stderr=subprocess.DEVNULL)
        # 调用 verify 验证签名
        cmd = [
            "openssl", "dgst", "-sha256", "-verify", str(tmp_pub_path),
            "-signature", str(signature_path), str(file_path)
        ]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            return "Verified OK" in output
        except subprocess.CalledProcessError:
            return False
    finally:
        try:
            tmp_pub_path.unlink()
        except Exception:
            pass