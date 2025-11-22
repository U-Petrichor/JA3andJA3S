# -*- coding: utf-8 -*-
"""
@author: Gemini
@license: (C) Copyright 2024-2025, Gemini Corporation.
@contact: gemini@google.com
@software: PyCharm
@file: tls_parser.py
@time: 2024-11-23 10:00
@desc: 该模块负责解析TLS握手数据包，并根据提取的字段计算JA3和JA3S指纹。
"""
import hashlib
from typing import List, Optional

from utils import GREASE_VALUES


def _to_int(x) -> Optional[int]:
    """
    一个安全的类型转换函数，尝试将不同类型的值转换为整数。
    支持整数、字节串和字符串的转换。

    Args:
        x: 待转换的输入值。

    Returns:
        Optional[int]: 转换成功则返回整数，否则返回None。
    """
    if x is None:
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, bytes) and len(x) == 2:
        return int.from_bytes(x, "big")  # 按大端序解析两字节的整数
    try:
        return int(x)
    except (ValueError, TypeError):
        return None


def _get_version(msg) -> int:
    """
    从TLS握手消息中提取TLS版本号。
    由于Scapy不同版本或不同消息类型中版本字段名称可能不同（如 version, vers, legacy_version），
    此函数会尝试多个可能的属性名。

    Args:
        msg: Scapy的TLS握手消息对象。

    Returns:
        int: 提取到的TLS版本号，失败则返回0。
    """
    v = None
    for name in ("version", "vers", "legacy_version"):
        if hasattr(msg, name):
            v = getattr(msg, name)
            break
    iv = _to_int(v)
    return iv if iv is not None else 0


def _extract_extensions(msg) -> List[int]:
    """
    从TLS握手消息中提取所有扩展的ID列表。
    同样地，此函数会兼容不同Scapy版本中可能存在的不同字段名（如 ext, extensions）。

    Args:
        msg: Scapy的TLS握手消息对象。

    Returns:
        List[int]: 包含所有扩展ID的整数列表。
    """
    raw = []
    for name in ("ext", "extensions"):
        if hasattr(msg, name):
            val = getattr(msg, name)
            if isinstance(val, list):
                raw = val
                break
    ids: List[int] = []
    for e in raw:
        t = None
        # 尝试从扩展对象中提取类型ID
        for attr in ("type", "ext_type"):
            if hasattr(e, attr):
                tv = getattr(e, attr)
                t = _to_int(tv)
                break
        # 如果上述方法失败，则尝试使用Scapy的TLSExtension类型进行解析
        try:
            from scapy.layers.tls.all import TLSExtension
        except ImportError:
            # 如果Scapy TLS层导入失败，创建一个临时的占位符类型
            TLSExtension = type("TLSExtension", (), {})
        if t is None and isinstance(e, TLSExtension):
            t = _to_int(e.type)

        if t is not None:
            ids.append(t)
    return ids


def _extract_ciphers(ch) -> List[int]:
    """
    从Client Hello消息中提取客户端支持的加密套件列表。

    Args:
        ch: Scapy的TLSClientHello消息对象。

    Returns:
        List[int]: 包含所有加密套件ID的整数列表。
    """
    src = None
    for name in ("cipher_suites", "ciphers"):
        if hasattr(ch, name):
            src = getattr(ch, name)
            break
    if src is None:
        return []
    if isinstance(src, list):
        return [_to_int(x) for x in src if _to_int(x) is not None]
    return []


def _extract_supported_groups(msg) -> List[int]:
    """
    从TLS消息中提取支持的椭圆曲线组（Supported Groups）列表。

    Args:
        msg: Scapy的TLS握手消息对象。

    Returns:
        List[int]: 包含所有支持组ID的整数列表。
    """
    groups: List[int] = []
    extensions = getattr(msg, "ext", []) or getattr(msg, "extensions", [])
    try:
        from scapy.layers.tls.all import TLS_Ext_SupportedGroups
    except ImportError:
        TLS_Ext_SupportedGroups = type("TLS_Ext_SupportedGroups", (), {})

    for e in extensions:
        if isinstance(e, TLS_Ext_SupportedGroups):
            vals = getattr(e, "groups", [])
            groups.extend([_to_int(x) for x in vals if _to_int(x) is not None])
            break
    return groups


def _extract_point_formats(msg) -> List[int]:
    """
    从TLS消息中提取椭圆曲线点格式（EC Point Formats）列表。

    Args:
        msg: Scapy的TLS握手消息对象。

    Returns:
        List[int]: 包含所有点格式ID的整数列表。
    """
    fmts: List[int] = []
    extensions = getattr(msg, "ext", []) or getattr(msg, "extensions", [])
    try:
        from scapy.layers.tls.all import TLS_Ext_SupportedPointFormats
    except ImportError:
        TLS_Ext_SupportedPointFormats = type("TLS_Ext_SupportedPointFormats", (), {})

    for e in extensions:
        if isinstance(e, TLS_Ext_SupportedPointFormats):
            vals = getattr(e, "formats", [])
            fmts.extend([_to_int(x) for x in vals if _to_int(x) is not None])
            break
    return fmts


def extract_ja3(packet) -> Optional[str]:
    """
    从数据包中提取JA3指纹。
    JA3指纹由以下部分拼接而成，并进行MD5哈希：
    TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

    Args:
        packet: Scapy捕获的数据包。

    Returns:
        Optional[str]: 计算出的JA3指纹（MD5哈希值），如果不是Client Hello包则返回None。
    """
    try:
        from scapy.layers.tls.all import TLSClientHello
    except ImportError:
        return None

    if not packet.haslayer(TLSClientHello):
        return None

    ch = packet.getlayer(TLSClientHello)
    ver = _get_version(ch)
    # 提取时过滤掉GREASE值
    ciphers = [x for x in _extract_ciphers(ch) if x not in GREASE_VALUES]
    exts = [x for x in _extract_extensions(ch) if x not in GREASE_VALUES]
    groups = [x for x in _extract_supported_groups(ch) if x not in GREASE_VALUES]
    fmts = _extract_point_formats(ch)

    # 按照JA3规范拼接字符串
    s = (
        f"{ver},"
        f'{"-".join(map(str, ciphers))},'
        f'{"-".join(map(str, exts))},'
        f'{"-".join(map(str, groups))},'
        f'{"-".join(map(str, fmts))}'
    )
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _extract_server_cipher(sh) -> int:
    """
    从Server Hello消息中提取服务器选择的加密套件。

    Args:
        sh: Scapy的TLSServerHello消息对象。

    Returns:
        int: 服务器选择的加密套件ID，失败则返回0。
    """
    for name in ("cipher_suite", "cipher"):
        if hasattr(sh, name):
            iv = _to_int(getattr(sh, name))
            if iv is not None:
                return iv
    return 0


def extract_ja3s(packet) -> Optional[str]:
    """
    从数据包中提取JA3S指纹。
    JA3S指纹由以下部分拼接而成，并进行MD5哈希：
    TLSVersion,Cipher,Extensions

    Args:
        packet: Scapy捕获的数据包。

    Returns:
        Optional[str]: 计算出的JA3S指纹（MD5哈希值），如果不是Server Hello包则返回None。
    """
    try:
        from scapy.layers.tls.all import TLSServerHello
    except ImportError:
        return None

    if not packet.haslayer(TLSServerHello):
        return None

    sh = packet.getlayer(TLSServerHello)
    ver = _get_version(sh)
    cipher = _extract_server_cipher(sh)
    exts = [x for x in _extract_extensions(sh) if x not in GREASE_VALUES]

    # 按照JA3S规范拼接字符串
    s = f"{ver},{cipher},{'-'.join(map(str, exts))}"
    return hashlib.md5(s.encode("utf-8")).hexdigest()
