# 混合型加密可靠信道传输工具

本项目是基于Python的混合型加密可靠信道传输工具，采用 TLS 建立加密信道，通过自签名或受信任证书验证身份，并增加可选数字签名验证文件完整性的功能。

> 注意：本项目是一个练习项目，不具备实用价值，请不要在任何重要环境使用。该项目大幅参考了[AGstars](https://github.com/AGstars)的[SafetyTranslation](https://github.com/AGstars/SafetyTranslation)的项目结构和思路。

## 功能概览

* **TLS 加密传输**：利用标准库 `ssl` 自动完成密钥交换和加密，会话密钥随机生成，阻止窃听和篡改。
* **AES 对称加密（可选）**：在文件传输前对文件内容进行 AES 加密，密钥使用 RSA 公钥加密后传输，可增强应用层安全。
* **数字签名**：发送端可对文件的 SHA‑256 哈希进行 RSA 签名，接收端使用公钥验证，确保文件来源与完整性。
* **命令行和测试脚本**：通过 `main.py` 启动 TLS 服务端或客户端，也可以使用 `sender_test` 和 `receiver_test` 目录中的脚本进行测试。
* **中间人攻击测试**：`mitm_tamper_script.py` 实现了一个简单的透明代理，用于演示在 TLS 加密下无法窃听明文。

## 安装与使用

1. 克隆或下载本仓库后，确保安装 Python 3.8+，并在项目根目录执行：

   ```bash
   pip install -r requirements.txt
   ```

2. 生成自签名证书（第一次运行需要）：

   ```bash
   python main.py generate-certs --cn "localhost"
   ```

3. 启动服务端：

   ```bash
   python main.py server --host 0.0.0.0 --port 5001 --out-dir received_files
   ```

4. 发送文件：

   ```bash
   python main.py client --host localhost --port 5001 path/to/file.txt
   ```

5. 可选：使用 `--insecure` 在客户端禁用证书校验（测试自签名证书时使用），或在 `--sign` 开启数字签名。

> 详细的命令选项请运行 `python main.py -h` 查看。

## 目录结构

```
SecureHybridTransfer/
├── FileTransfer/              # 打包和分发相关文件
│   ├── build/                 # 构建输出目录
│   ├── dist/                  # 分发目录
│   └── main.spec              # PyInstaller 配置文件（示例）
├── receiver_test/
│   └── run_receiver.py        # 启动接收端脚本
├── sender_test/
│   └── run_sender.py          # 启动发送端脚本
├── base.py                    # 公用函数和工具
├── icon.ico                   # 应用图标
├── main.py                    # 程序入口，提供 CLI
├── mitm_tamper_script.py      # 简易中间人攻击测试脚本
├── secure_file_transfer.py    # 核心加密传输实现
├── requirements.txt           # 项目依赖列表
└── README.md                  # 说明文档（本文件）
```