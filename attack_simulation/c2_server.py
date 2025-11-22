"""
极简 HTTPS 服务器，监听 0.0.0.0:4443。
使用同目录下的 server.pem（包含私钥+证书）进行 TLS 包装。
"""

import ssl
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


def main() -> None:
    addr = ("0.0.0.0", 4443)
    pem_path = Path(__file__).parent / "server.pem"

    if not pem_path.exists():
        print("[!] 未找到证书 server.pem，请先运行 gen_cert.py 生成证书。")
        return

    # 创建基础 HTTP 服务器
    httpd = HTTPServer(addr, SimpleHTTPRequestHandler)

    # 创建 TLS 上下文并加载证书链
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(pem_path))

    # 将底层套接字包装为 HTTPS
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("[+] C2 Server 正在监听 4443 端口 (JA3S 指纹源)...")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

