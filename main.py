"""
main.py - 项目入口
===================

提供命令行接口启动 TLS 服务端或客户端，并生成证书等。通过解析参数调用 `secure_file_transfer` 中的实际实现。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import base
from . import secure_file_transfer as sft


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="混合型加密可靠信道传输工具")
    subparsers = parser.add_subparsers(dest="cmd", required=True)

    # 生成证书
    gen = subparsers.add_parser("generate-certs", help="生成自签名证书和私钥")
    gen.add_argument("--cn", default="localhost", help="证书的 Common Name")
    gen.add_argument("--days", type=int, default=365, help="证书有效期天数")

    # 启动服务端
    srv = subparsers.add_parser("server", help="启动接收端服务")
    srv.add_argument("--host", default="0.0.0.0", help="监听地址")
    srv.add_argument("--port", type=int, default=5001, help="监听端口")
    srv.add_argument("--out-dir", type=Path, default=Path("."), help="保存文件目录")
    srv.add_argument("--verify", action="store_true", help="对收到的签名进行验证")

    # 启动客户端
    cli = subparsers.add_parser("client", help="启动发送端")
    cli.add_argument("--host", required=True, help="服务器地址")
    cli.add_argument("--port", type=int, required=True, help="服务器端口")
    cli.add_argument("--insecure", action="store_true", help="禁用证书验证")
    cli.add_argument("--sign", action="store_true", help="发送文件时附加数字签名")
    cli.add_argument("file", type=Path, help="要发送的文件")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "generate-certs":
        base.generate_self_signed_cert(cn=args.cn, days=args.days)
        print(f"生成证书: {base.CERT_FILE}\n生成私钥: {base.KEY_FILE}")
    elif args.cmd == "server":
        # 自动生成证书（如果不存在）
        if not base.CERT_FILE.exists() or not base.KEY_FILE.exists():
            print("未检测到证书和私钥，自动生成自签名证书……")
            base.generate_self_signed_cert()
        sft.receive_files(args.host, args.port, args.out_dir, verify_signature=args.verify)
    elif args.cmd == "client":
        sft.send_file(args.host, args.port, args.file, insecure=args.insecure, sign=args.sign)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()