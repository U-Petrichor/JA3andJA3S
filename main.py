"""
主程序模块，负责整合所有功能，启动网络嗅探，并根据JA3/JA3S指纹进行会话跟踪和威胁检测。
"""
import threading
import time
from typing import Dict, Tuple

# 导入其他模块的组件
from logger import LogManager
from tls_parser import extract_ja3, extract_ja3s
from utils import TrafficState, SessionInfo, get_five_tuple

def heartbeat():
    """
    心跳线程，每10秒打印一次运行状态和计数。
    """
    count = 0
    while True:
        time.sleep(10)
        count += 1
        print(f"[Heartbeat] Program is running... (Count: {count})")


def main():
    """
    主函数，程序的入口点。
    负责初始化日志管理器、会话表、白名单和黑名单，并启动网络嗅探。
    """
    # 启动心跳线程
    hb_thread = threading.Thread(target=heartbeat, daemon=True)
    hb_thread.start()

    # 初始化日志管理器并启动后台日志记录线程
    log_mgr = LogManager()
    log_mgr.start()

    # 会话表，用于存储和跟踪网络会话的状态。
    # 键是五元组，值是 SessionInfo 对象。
    session_table: Dict[Tuple[str, int, str, int, str], SessionInfo] = {}

    # JA3 白名单，用于存放已知的、可信任的客户端JA3指纹。
    whitelist_ja3 = set()
    # JA3S 黑名单，用于存放已知的、恶意的服务器JA3S指纹。
    blacklist_ja3s = set()

    def packet_callback(packet):
        """
        scapy sniff函数的回调函数，用于处理每一个捕获到的数据包。
        """
        # 提取数据包的五元组
        ft = get_five_tuple(packet)
        
        # 尝试提取JA3指纹（客户端 -> 服务器）
        ja3_hash = extract_ja3(packet)
        if ja3_hash:
            # 如果是Client Hello包，则创建或更新会话信息
            # 根据JA3指纹是否在白名单中，设置会话的初始状态
            st = TrafficState.SAFE if ja3_hash in whitelist_ja3 else TrafficState.SUSPICIOUS
            session_table[ft] = SessionInfo(
                ja3_hash=ja3_hash,
                ja3s_hash=None,
                timestamp=time.time(),
                state=st,
            )
            return # 处理完毕，等待Server Hello

        # 尝试提取JA3S指纹（服务器 -> 客户端）
        ja3s_hash = extract_ja3s(packet)
        if ja3s_hash:
            # 如果是Server Hello包，查找对应的Client Hello会话
            src_ip, src_port, dst_ip, dst_port, proto = ft
            # 五元组反转，以匹配从客户端发起的原始会话
            rev = (dst_ip, dst_port, src_ip, src_port, proto)
            info = session_table.get(rev)


            # 如果找到了对应的可疑会话，并且JA3S指纹在黑名单中，则判定为恶意通信
            if info and info.state == TrafficState.SUSPICIOUS:
                if ja3s_hash in blacklist_ja3s:
                    info.ja3s_hash = ja3s_hash
                    info.state = TrafficState.MALICIOUS
                    # 记录恶意事件
                    log_mgr.log_event(
                        {
                            "timestamp": time.time(),
                            "ip": rev[0], # 记录客户端IP
                            "ja3": info.ja3_hash,
                            "ja3s": ja3s_hash,
                            "state": info.state.value,
                        }
                    )
                    # 在控制台打印告警信息
                    print("\033[31m" + "ALERT: C2 communication detected" + "\033[0m")
                
                # 无论是否恶意，会话处理完毕后都从会话表中移除
                session_table.pop(rev, None)

    # 延迟导入scapy的sniff函数，避免启动时加载过慢
    from scapy.all import sniff
    sniff(filter="tcp and (port 443 or port 4443)", prn=packet_callback, store=0)


if __name__ == "__main__":
    # 当脚本作为主程序运行时，调用main函数
    main()
