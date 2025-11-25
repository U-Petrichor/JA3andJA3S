# 项目概览

## 关键文件
- `main.py`：项目入口。负责网络抓包、五元组会话关联、JA3/JA3S 指纹检测与告警，附带 SOAR 模拟响应（只在报警后显示）。
- `tls_parser.py`：TLS 握手解析与 JA3/JA3S 指纹计算。
- `utils.py`：通用数据结构与工具函数（如五元组提取、常量）。
- `logger.py`：异步日志写入，按日期与 IP 落盘到 `logs/YYYY-MM-DD/IP.log`。
- `attack_simulation/gen_cert.py`：生成自签名证书 `server.pem`（供 C2 服务器使用）。
- `attack_simulation/c2_server.py`：极简 HTTPS C2 服务器，监听 `4443` 端口。
- `attack_simulation/attacker.py`：普通攻击者，请求使用 Python 默认 TLS 指纹，预期会被检测并告警。
- `attack_simulation/evasive_attacker.py`：逃逸攻击者，使用 `curl_cffi` 的 `requests` 接口与 `impersonate` 参数伪装浏览器握手（需要将 `YOUR_C2_IP` 修改为实际 IP）。

## 使用方法
- 安装依赖：
  ```bash
  pip install scapy colorama cryptography curl_cffi
  ```
- 生成证书：
  ```bash
  python attack_simulation/gen_cert.py
  ```
- 启动 C2 服务器：
  ```bash
  python attack_simulation/c2_server.py
  ```
- 以管理员权限运行检测程序：
  ```bash
  python main.py
  ```
- 发起攻击：
  - 常规攻击（预期触发告警）：
    ```bash
    python attack_simulation/attacker.py
    ```
  - 逃逸攻击（修改脚本中的 `YOUR_C2_IP` 后运行，预期不报警）：
    ```bash
    python attack_simulation/evasive_attacker.py
    ```
- 查看日志：
  ```
  logs/YYYY-MM-DD/<C2_IP>.log
  ```
