"""
在 attack_simulation 目录下生成一个自签名的 SSL 证书和私钥，
并将两者合并写入同一个 PEM 文件 server.pem。

跨平台（Windows/Linux），使用 cryptography 库实现。
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except Exception as e:  # 友好提示依赖缺失
    raise SystemExit(
        "[!] 依赖缺失: 需要安装 cryptography 库 (pip install cryptography)\n"
        f"    错误: {e}"
    )


def main() -> None:
    """
    生成一个 RSA 私钥和自签名证书，有效期 365 天，CN=localhost。
    将私钥和证书连续写入 attack_simulation/server.pem。
    """
    out_dir = Path(__file__).parent
    pem_path = out_dir / "server.pem"

    # 生成 2048 位 RSA 私钥
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 证书主题与颁发者相同（自签名）
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]
    )

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
    )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())

    # 写入 PEM（先私钥后证书）
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ) + cert.public_bytes(serialization.Encoding.PEM)

    pem_path.write_bytes(pem_bytes)
    print(f"[+] 证书已生成: {pem_path}")


if __name__ == "__main__":
    main()

