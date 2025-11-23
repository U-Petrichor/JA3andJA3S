"""
伪装攻击者客户端：使用 Python requests 发起 HTTPS 请求，
设置浏览器风格的 User-Agent，但保持 Python TLS 指纹（JA3）。
"""

import requests
import urllib3


def main() -> None:
    # 禁用自签名证书产生的警告
    urllib3.disable_warnings()

    url = "https://10.122.216.44:4443"
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    headers = {"User-Agent": user_agent}

    print("[*] 正在连接 C2...")
    print(f"[*] 伪装 User-Agent: {user_agent}")

    try:
        # verify=False 不验证证书，以允许自签名证书
        resp = requests.get(url, headers=headers, verify=False, timeout=10)
        print("[+] 连接成功！(攻击流量已发送)")
        # 可选输出：状态码
        print(f"[*] 响应状态码: {resp.status_code}")
    except Exception as e:
        print(f"[!] 连接失败: {e}")


if __name__ == "__main__":
    main()

