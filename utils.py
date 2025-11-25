# -*- coding: utf-8 -*-
"""
@author: Gemini
@license: (C) Copyright 2024-2025, Gemini Corporation.
@contact: gemini@google.com
@software: PyCharm
@file: utils.py
@time: 2024-11-23 10:00
@desc: 该模块提供了JA3/JA3S指纹分析所需的通用工具、数据结构和常量。
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple, List


class TrafficState(Enum):
    """
    定义了网络流量的三种安全状态，用于会话管理和威胁评估。
    """
    SAFE = "SAFE"  # 安全：流量被识别为良性或已加入白名单。
    SUSPICIOUS = "SUSPICIOUS"  # 可疑：流量具有潜在威胁特征，但尚未确认为恶意。
    MALICIOUS = "MALICIOUS"  # 恶意：流量已被确认为恶意，例如匹配了已知的C2服务器指纹。


@dataclass
class SessionInfo:
    """
    存储一个TLS会话的关键信息。
    使用 dataclass 装饰器可以自动生成 __init__, __repr__ 等方法。
    """
    ja3_hash: Optional[str]
    ja3s_hash: Optional[str]
    timestamp: float
    state: TrafficState
    payload_sizes: List[int] = field(default_factory=list)
    arrival_times: List[float] = field(default_factory=list)
    iat_list: List[float] = field(default_factory=list)


# RFC 8701 中定义的GREASE (Generate Random Extensions And Sustain Extensibility) 值。
# 在计算JA3/JA3S指纹时，必须忽略这些值，以确保指纹的稳定性和准确性。
GREASE_VALUES = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
]

MAX_PACKET_TRACK = 20


def get_five_tuple(packet) -> Tuple[str, int, str, int, str]:
    """
    从数据包中提取网络五元组（源IP、源端口、目标IP、目标端口、协议）。
    这是唯一标识一个网络连接的标准方法。

    Args:
        packet (scapy.packet.Packet): Scapy捕获到的数据包对象。

    Returns:
        Tuple[str, int, str, int, str]: 包含五元组信息的元组。
                                         如果无法解析，则返回空字符串和0。
    """
    # 延迟导入scapy相关模块，避免在模块加载时造成性能瓶颈。
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
    except ImportError:
        # 如果scapy未安装或导入失败，返回空元组。
        return "", 0, "", 0, ""

    src_ip = ""
    dst_ip = ""
    # 检查数据包是IPv4还是IPv6，并提取源/目标IP地址。
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

    src_port = 0
    dst_port = 0
    # 检查数据包是否包含TCP层，并提取源/目标端口。
    if packet.haslayer(TCP):
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)

    # 返回五元组，协议硬编码为"TCP"，因为TLS运行在TCP之上。
    return src_ip, src_port, dst_ip, dst_port, "TCP"
