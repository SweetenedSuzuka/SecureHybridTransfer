"""
启动发送端测试脚本
===================

此脚本提供简单的命令行接口，用于发送单个文件到指定服务端。可指定是否跳过证书验证以及是否附加数字签名。
"""

import argparse
from pathlib import Path

from .. import main as main_module


def parse_args():
    parser = argparse.ArgumentParser(description="发送端测试脚本")
    parser.add_argument("--host", required=True, help="服务器地址")
    parser.add_argument("--port", type=int, required=True, help="服务器端口")
    parser.add_argument("--insecure", action="store_true", help="禁用证书验证")
    parser.add_argument("--sign", action="store_true", help="发送时附加数字签名")
    parser.add_argument("file", type=Path, help="要发送的文件")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    # 调用主程序的 client 命令
    main_module.main([
        "client",
        "--host", args.host,
        "--port", str(args.port),
    ] + (["--insecure"] if args.insecure else []) + (["--sign"] if args.sign else []) + [str(args.file)])