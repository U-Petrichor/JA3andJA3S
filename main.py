import os
""" 
 主程序模块，负责整合所有功能，启动网络嗅探，并根据JA3/JA3S指纹进行会话跟踪和威胁检测。 
 """ 
os.environ["SCAPY_USE_PCAP"] = "True"
import time 
import sys # 引入sys用于强制刷新输出 
from typing import Dict, Tuple 

from logger import LogManager 
from tls_parser import extract_ja3, extract_ja3s 
from utils import TrafficState, SessionInfo, get_five_tuple, MAX_PACKET_TRACK 
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    COLORAMA_AVAILABLE = True
except Exception:
    COLORAMA_AVAILABLE = False


ANSI_ENABLED = False

def _enable_ansi() -> bool:
    try:
        if os.name == "nt":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            h = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                return bool(kernel32.SetConsoleMode(h, mode.value | 0x0004))
            return False
        return True
    except Exception:
        return False

def _red(s: str) -> str:
    if COLORAMA_AVAILABLE:
        return f"{Fore.RED}{s}{Style.RESET_ALL}"
    return f"\033[31m{s}\033[0m" if ANSI_ENABLED else s

def _yellow(s: str) -> str:
    if COLORAMA_AVAILABLE:
        return f"{Fore.YELLOW}{s}{Style.RESET_ALL}"
    return f"\033[33m{s}\033[0m" if ANSI_ENABLED else s

def _cyan(s: str) -> str:
    if COLORAMA_AVAILABLE:
        return f"{Fore.CYAN}{s}{Style.RESET_ALL}"
    return f"\033[36m{s}\033[0m" if ANSI_ENABLED else s

def soar_simulate_response(ip: str, port: int, ja3s_hash: str) -> None:
    title = "SOAR Response"
    lines = [
        f"Step 1: 上报威胁情报 | JA3S={ja3s_hash}",
        f"Step 2: 生成防火墙策略 | netsh advfirewall firewall add rule name=\"Block_C2_{ip}\" dir=in action=block remoteip={ip}",
        "Step 3: 执行状态 | ✅ 模拟成功 (Dry Run)",
    ]
    width = max(len(title), *(len(x) for x in lines))
    top = f"╔{'═' * (width + 2)}╗"
    bot = f"╚{'═' * (width + 2)}╝"
    def wrap_row(s: str) -> str:
        return f"║ {s.ljust(width)} ║"
    color_on = Fore.CYAN if COLORAMA_AVAILABLE else ("\033[36m" if ANSI_ENABLED else "")
    color_off = Style.RESET_ALL if COLORAMA_AVAILABLE else ("\033[0m" if ANSI_ENABLED else "")
    print(color_on + top + color_off, flush=True)
    print(color_on + wrap_row(title) + color_off, flush=True)
    for ln in lines:
        print(color_on + wrap_row(ln) + color_off, flush=True)
    print(color_on + bot + color_off, flush=True)
 
 
def main(): 
    print("[*] 正在初始化系统组件...") # 1. 证明程序启动了 
    global ANSI_ENABLED
    ANSI_ENABLED = _enable_ansi()
    log_mgr = LogManager() 
    log_mgr.start() 
 
    session_table: Dict[Tuple[str, int, str, int, str], SessionInfo] = {} 
    whitelist_ja3 = set() 
    blacklist_ja3s = {"703d2b53a3645d5414cb4e340942549e", "15af977ce25de452b96affa2addb1036"} 
 
    def packet_callback(packet): 
        # 2. 心跳包：收到任何 443 包就打印一个点，证明抓包在工作 
        # flush=True 极其重要，强制让控制台立刻吐出字符，不许憋着 
        print(".", end="", flush=True) 
 
        ft = get_five_tuple(packet) 
        if not ft: return # 没解析出五元组就跳过 
 
        # --- Client Hello 处理 --- 
        ja3_hash = extract_ja3(packet) 
        if ja3_hash: 
            src_ip, src_port, dst_ip, dst_port, proto = ft 
            print(f"\n[ClientHello] {src_ip}:{src_port} -> {dst_ip}:{dst_port} JA3={ja3_hash}", flush=True) 
            st = TrafficState.SAFE if ja3_hash in whitelist_ja3 else TrafficState.SUSPICIOUS 
            session_table[ft] = SessionInfo( 
                ja3_hash=ja3_hash, 
                ja3s_hash=None, 
                timestamp=time.time(), 
                state=st, 
            ) 
            return 
 
        # --- Server Hello 处理 --- 
        ja3s_hash = extract_ja3s(packet) 
        if ja3s_hash: 
            src_ip, src_port, dst_ip, dst_port, proto = ft 
            print(f"\n[ServerHello] {src_ip}:{src_port} -> {dst_ip}:{dst_port} JA3S={ja3s_hash}", flush=True)
            rev = (dst_ip, dst_port, src_ip, src_port, proto) 
            info = session_table.get(rev) 

            if info and info.state == TrafficState.SUSPICIOUS: 
                malicious = (ja3s_hash in blacklist_ja3s)
                if malicious:
                    info.ja3s_hash = ja3s_hash 
                    info.state = TrafficState.MALICIOUS 
                    log_mgr.log_event({ 
                        "timestamp": time.time(), 
                        "ip": src_ip, 
                        "ja3": info.ja3_hash, 
                        "ja3s": ja3s_hash, 
                        "state": info.state.value, 
                    }) 
                    print("\n" + _red(f"[ALERT] 检测到 C2 通信! IP: {src_ip}"), flush=True) 
                    soar_simulate_response(src_ip, src_port, ja3s_hash)
            
            

        if packet.haslayer(TCP):
            pl = bytes(packet[TCP].payload)
            payload_len = len(pl)
            if payload_len > 0:
                ft2 = get_five_tuple(packet)
                if ft2:
                    s_ip, s_port, d_ip, d_port, pr = ft2
                    rev2 = (d_ip, d_port, s_ip, s_port, pr)
                    sess = session_table.get(ft2) or session_table.get(rev2)
                    if sess:
                        if len(sess.payload_sizes) < MAX_PACKET_TRACK:
                            now = time.time()
                            sess.payload_sizes.append(payload_len)
                            sess.arrival_times.append(now)
                            if len(sess.arrival_times) >= 2:
                                dt = sess.arrival_times[-1] - sess.arrival_times[-2]
                                sess.iat_list.append(dt)
                            latest_iat = sess.iat_list[-1] if sess.iat_list else 0.0
                            seq = len(sess.payload_sizes)
                            print(_cyan(f"[Flow Analysis] IP: {s_ip} -> {d_ip} | 包序列: {seq}/{MAX_PACKET_TRACK} | 最新IAT: {latest_iat:.2f}s | 载荷: {payload_len} bytes"), flush=True)
                            if len(sess.iat_list) >= 5 and len(sess.payload_sizes) >= 5:
                                window_iat = sess.iat_list[-5:]
                                window_payload = sess.payload_sizes[-5:]
                                heartbeat = all(abs(x - 1.0) <= 0.1 for x in window_iat)
                                fixed = len(set(window_payload)) == 1
                                if heartbeat and fixed:
                                    print(_yellow("[BEHAVIOR WARNING] 检测到各种机器心跳特征！"), flush=True)
 
    # 3. 加载 Scapy 的时候告诉用户别慌 
    print("[*] 正在加载 Scapy 网络驱动 (Windows上可能需要10-20秒，请耐心等待)...") 
    from scapy.all import sniff, conf, AsyncSniffer 
    from scapy.layers.tls.all import TLSClientHello, TLSServerHello, TLS
    from scapy.layers.inet import TCP
    from scapy.packet import bind_layers
    
    # 4. 打印当前 Scapy 选中的网卡，防止它选了 Loopback 或者 虚拟机网卡 
    print(f"[*] Scapy 加载完成！当前监听网卡: [{conf.iface.name}]") 
    # 暂时关闭 443 端口，仅保留 4443，以避免干扰 
    FILTER_STR = "tcp and port 4443" 
    # FILTER_STR = "tcp and (port 443 or port 4443)"  # 恢复 443取消此行注释
    print(f"[*] 过滤器: {FILTER_STR}") 
    bind_layers(TCP, TLS, dport=4443)
    bind_layers(TCP, TLS, sport=4443)
    print("[*] 开始抓包 (屏幕应该开始出现 '.' ) ...") 
 
   # 5. 启动抓包 (自动锁定 IP 为 10.122.216.44 的网卡，同时兼顾环回)
    # TARGET_IP = "10.122.216.44"
    TARGET_IP = "10.21.166.204"
    target_iface = None
    loop_iface = None

    print(f"[*] 正在自动搜索 IP 为 {TARGET_IP} 的网卡...")

    # 遍历 Scapy 识别到的所有网卡
    for iface_name in conf.ifaces.data:
        iface = conf.ifaces.data[iface_name]
        txt = f"{getattr(iface,'name','')}{getattr(iface,'description','')}".lower()
        if iface.ip == TARGET_IP:
            target_iface = iface
        if ("loop" in txt) or ("npcap" in txt) or ("环回" in txt):
            loop_iface = iface
    
    sniffers = []
    if target_iface:
        print(f"[*] 成功锁定网卡: [{target_iface.name}]")
        sniffers.append(AsyncSniffer(filter=FILTER_STR, prn=packet_callback, store=False, iface=target_iface))
    else:
        print(f"\n\033[91m[ERROR] 致命错误: 没找到 IP 是 {TARGET_IP} 的网卡！\033[0m")
        print("[HINT] 请检查网络是否断开，或者 IP 地址是否变了。")

    if loop_iface:
        print(f"[*] 同时监听环回网卡: [{loop_iface.name}]")
        sniffers.append(AsyncSniffer(filter=FILTER_STR, prn=packet_callback, store=False, iface=loop_iface))

    if sniffers:
        print("[*] 开始抓包 (屏幕应该开始出现 '.' ) ...")
        try:
            for s in sniffers:
                s.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            for s in sniffers:
                try:
                    s.stop()
                except Exception:
                    pass

if __name__ == "__main__":
    main()
