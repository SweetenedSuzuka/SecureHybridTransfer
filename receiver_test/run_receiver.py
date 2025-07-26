"""
启动接收端测试脚本
===================

此脚本用于在测试环境中启动接收端，监听指定端口并保存收到的文件。如果检测到服务器证书不存在，则自动生成一份自签名证书。
"""

import argparse
from pathlib import Path

from .. import main as main_module


def parse_args():
    parser = argparse.ArgumentParser(description="接收端测试脚本")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=5001, help="监听端口")
    parser.add_argument("--out-dir", type=Path, default=Path("received_files"), help="保存文件目录")
    parser.add_argument("--verify", action="store_true", help="验证签名")
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    # 调用主程序的 server 命令
    main_module.main([
        "server",
        "--host", args.host,
        "--port", str(args.port),
        "--out-dir", str(args.out_dir),
    ] + (["--verify"] if args.verify else []))