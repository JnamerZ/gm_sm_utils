# -*- coding: utf-8 -*-
"""
gmssl 工具封装模块

提供以下能力：
1. SM2 密钥生成、签名、验签（支持裸签名 r||s 与 ASN.1 DER 两种格式）。
2. SM2 签名格式转换：raw <-> ASN.1 DER，并支持解析 r、s。
3. ASN.1 DER 数据（证书、签名等）通用 TLV 解析、定点修改、重新打包。
4. PEM / DER 证书互转。
5. 自定义数据打包/解析：带长度前缀、TLV 等。

依赖：
    pip install gmssl
（gmssl 内部已依赖 pycryptodome 的 Cryptodome.Util.asn1）
"""

from __future__ import annotations

import binascii
from typing import Any, Callable, List, Optional, Tuple, Union

from Cryptodome.Util.asn1 import DerInteger, DerSequence
from gmssl import sm2, sm3, func


HexOrBytes = Union[str, bytes]


# ---------------------------------------------------------------------------
# 基础编码/解码辅助
# ---------------------------------------------------------------------------

def to_bytes(data: HexOrBytes) -> bytes:
    """统一转换为 bytes：如果是 16 进制字符串则先解码。"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        data = data.strip()
        if data.startswith("0x") or data.startswith("0X"):
            data = data[2:]
        return bytes.fromhex(data)
    raise TypeError(f"data must be str or bytes, got {type(data)}")


def to_hex(data: HexOrBytes) -> str:
    """统一转换为 16 进制字符串（小写、不带 0x）。"""
    if isinstance(data, str):
        data = data.strip()
        if data.startswith("0x") or data.startswith("0X"):
            return data[2:].lower()
        return data.lower()
    return data.hex()


def sm3_hash(data: HexOrBytes) -> str:
    """对任意数据计算 SM3 摘要，返回 16 进制字符串。"""
    b = to_bytes(data)
    return sm3.sm3_hash(func.bytes_to_list(b))


def sm3_padding(data: HexOrBytes) -> bytes:
    """
    生成 SM3 在哈希之前的完整填充后输入（bytes）。

    SM3 填充规则（与 SHA-256/MD5 相同）：
        1. 在原始消息末尾追加 0x80；
        2. 追加若干 0x00，使得总长度（bit） ≡ 448 (mod 512)；
        3. 最后追加 64 bit 大端无符号整数，表示原始消息长度（bit）。

    Args:
        data: 原始消息，可以是 bytes 或 hex 字符串。

    Returns:
        填充后的完整字节序列，可直接送入 SM3 压缩函数。
    """
    b = to_bytes(data)
    original_bit_len = len(b) * 8

    # 1) 0x80
    padded = bytearray(b)
    padded.append(0x80)

    # 2) 0x00 填充到长度 ≡ 56 (mod 64)，即 bit 长度 ≡ 448 (mod 512)
    while len(padded) % 64 != 56:
        padded.append(0x00)

    # 3) 64 bit 大端长度
    padded.extend(original_bit_len.to_bytes(8, "big"))
    return bytes(padded)


def random_hex(length: int = 64) -> str:
    """生成指定长度的随机 16 进制字符串（length 为字符数）。"""
    return func.random_hex(length)


# ---------------------------------------------------------------------------
# SM2 密钥 / 签名 / 验签
# ---------------------------------------------------------------------------

class SM2Utils:
    """SM2 非对称算法工具类。"""

    PARA_LEN = 64  # 国密推荐曲线参数 256-bit，16 进制字符串长度为 64

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        生成 SM2 密钥对。

        Returns:
            (private_key, public_key) 均为 16 进制字符串。
            public_key 以 04 开头（未压缩），长度为 130 字符。
        """
        for _ in range(100):
            private_key = func.random_hex(SM2Utils.PARA_LEN)
            # 临时实例只用于调用 _kg 计算公钥
            tmp = sm2.CryptSM2(private_key, "")
            pub_point = tmp._kg(int(private_key, 16), sm2.default_ecc_table["g"])
            if pub_point is not None and len(pub_point) == 2 * SM2Utils.PARA_LEN:
                public_key = "04" + pub_point
                return private_key, public_key
        raise RuntimeError("failed to generate valid SM2 keypair after 100 attempts")

    @staticmethod
    def _normalize_public_key(public_key: str) -> str:
        """
        去掉 04 前缀，避免 gmssl 内部 lstrip('04') 误删公钥坐标前导 0/4。
        """
        public_key = public_key.strip().lower()
        if public_key.startswith("04"):
            return public_key[2:]
        return public_key

    @staticmethod
    def private_key_from_int(d: int) -> str:
        """将 10 进制私钥转换为 64 字符 16 进制字符串。"""
        if d < 0 or d >= int(sm2.default_ecc_table["n"], 16):
            raise ValueError("private key out of range")
        return f"{d:064x}"

    @staticmethod
    def public_key_from_private(d: Union[int, str]) -> str:
        """
        由私钥计算对应的未压缩公钥（04 开头，130 字符 hex）。

        Args:
            d: 10 进制整数或 16 进制字符串私钥。
        """
        if isinstance(d, int):
            d_hex = SM2Utils.private_key_from_int(d)
        else:
            d_hex = to_hex(d)
        tmp = sm2.CryptSM2(d_hex, "")
        pub_point = tmp._kg(int(d_hex, 16), sm2.default_ecc_table["g"])
        if pub_point is None or len(pub_point) != 2 * SM2Utils.PARA_LEN:
            raise ValueError("failed to derive public key from private key")
        return "04" + pub_point

    @staticmethod
    def sign(
        private_key: str,
        public_key: str,
        data: HexOrBytes,
        *,
        asn1: bool = False,
        with_sm3: bool = False,
        k: Optional[str] = None,
    ) -> str:
        """
        SM2 签名。

        Args:
            private_key: 32 字节 16 进制私钥。
            public_key: 65 字节未压缩公钥（04 开头）或 64 字节坐标。
            data: 待签名数据；with_sm3=True 时按 SM2withSM3 规范签名，
                  否则 data 应为 SM3 摘要（32 字节）。
            asn1: 是否输出 ASN.1 DER 格式签名；False 输出 r||s（128 字符 hex）。
            with_sm3: 是否使用 SM2withSM3 签名模式。
            k: 签名随机数，默认随机生成。

        Returns:
            16 进制字符串签名。
        """
        if k is None:
            k = func.random_hex(SM2Utils.PARA_LEN)
        public_key = SM2Utils._normalize_public_key(public_key)
        crypt = sm2.CryptSM2(private_key, public_key, asn1=asn1)
        if with_sm3:
            return crypt.sign_with_sm3(to_bytes(data), k)
        return crypt.sign(to_bytes(data), k)

    @staticmethod
    def verify(
        public_key: str,
        signature: str,
        data: HexOrBytes,
        *,
        asn1: bool = False,
        with_sm3: bool = False,
    ) -> bool:
        """
        SM2 验签。

        Args:
            public_key: 公钥 16 进制字符串。
            signature: 16 进制签名（r||s 或 ASN.1 DER）。
            data: 原始数据或摘要。
            asn1: signature 是否为 ASN.1 DER 格式。
            with_sm3: 是否按 SM2withSM3 规范验签。

        Returns:
            验签结果 True / False。
        """
        public_key = SM2Utils._normalize_public_key(public_key)
        crypt = sm2.CryptSM2("", public_key, asn1=asn1)
        if with_sm3:
            return crypt.verify_with_sm3(signature, to_bytes(data))
        return crypt.verify(signature, to_bytes(data))

    @staticmethod
    def sign_decimal(
        d: int,
        public_key: str,
        data: HexOrBytes,
        *,
        with_sm3: bool = True,
        k: Optional[Union[int, str]] = None,
    ) -> Tuple[int, int]:
        """
        使用 10 进制私钥对消息进行 SM2 签名，返回 10 进制 (r, s)。

        Args:
            d: 10 进制私钥。
            public_key: 公钥（04 开头 或 64 字节坐标）。
            data: 待签名消息 m（bytes）。
            with_sm3: 是否使用 SM2withSM3 模式（默认 True，data 为原始消息）。
            k: 签名随机数，可为 10 进制整数或 hex 字符串；默认随机生成。

        Returns:
            (r, s) 均为 10 进制大整数。
        """
        d_hex = SM2Utils.private_key_from_int(d)
        if isinstance(k, int):
            k = f"{k:064x}"
        raw_sig = SM2Utils.sign(d_hex, public_key, data, with_sm3=with_sm3, k=k)
        return SM2SignatureFormat.parse_raw(raw_sig)

    @staticmethod
    def verify_decimal(
        public_key: str,
        r: int,
        s: int,
        data: HexOrBytes,
        *,
        with_sm3: bool = True,
    ) -> bool:
        """
        使用 10 进制 (r, s) 对消息进行 SM2 验签。

        Args:
            public_key: 公钥（04 开头 或 64 字节坐标）。
            r: 10 进制签名 r 值。
            s: 10 进制签名 s 值。
            data: 原始消息或摘要。
            with_sm3: 是否按 SM2withSM3 规范验签。

        Returns:
            验签结果 True / False。
        """
        raw_sig = SM2SignatureFormat.decimal_to_raw(r, s)
        return SM2Utils.verify(public_key, raw_sig, data, with_sm3=with_sm3)


# ---------------------------------------------------------------------------
# SM2 签名格式转换
# ---------------------------------------------------------------------------

class SM2SignatureFormat:
    """SM2 签名在 raw (r||s) 与 ASN.1 DER 之间互转，并支持解析。"""

    SIG_LEN = 128  # r(64) + s(64)

    @staticmethod
    def raw_to_asn1(raw_sig_hex: str) -> str:
        """
        将 r||s 格式的 16 进制签名转换为 ASN.1 DER 格式。

        Returns:
            DER 编码的 16 进制字符串。
        """
        raw = to_hex(raw_sig_hex)
        if len(raw) != SM2SignatureFormat.SIG_LEN:
            raise ValueError(f"raw signature length must be {SM2SignatureFormat.SIG_LEN}, got {len(raw)}")
        r = int(raw[0:64], 16)
        s = int(raw[64:128], 16)
        der = DerSequence([DerInteger(r), DerInteger(s)]).encode()
        return der.hex()

    @staticmethod
    def asn1_to_raw(asn1_sig_hex: str) -> str:
        """
        将 ASN.1 DER 格式签名转换为 r||s 格式。

        Returns:
            128 字符 16 进制字符串。
        """
        data = to_bytes(asn1_sig_hex)
        seq = DerSequence()
        seq.decode(data)
        r, s = int(seq[0]), int(seq[1])
        return f"{r:064x}{s:064x}"

    @staticmethod
    def parse_asn1(asn1_sig_hex: str) -> Tuple[int, int]:
        """
        解析 ASN.1 DER 签名，返回 (r, s) 两个大整数。
        """
        data = to_bytes(asn1_sig_hex)
        seq = DerSequence()
        seq.decode(data)
        if len(seq) != 2:
            raise ValueError("SM2 ASN.1 signature must contain exactly two integers")
        return int(seq[0]), int(seq[1])

    @staticmethod
    def parse_raw(raw_sig_hex: str) -> Tuple[int, int]:
        """
        解析 r||s 签名，返回 (r, s) 两个大整数。
        """
        raw = to_hex(raw_sig_hex)
        if len(raw) != SM2SignatureFormat.SIG_LEN:
            raise ValueError(f"raw signature length must be {SM2SignatureFormat.SIG_LEN}, got {len(raw)}")
        return int(raw[0:64], 16), int(raw[64:128], 16)

    @staticmethod
    def decimal_to_raw(r: int, s: int) -> str:
        """将 10 进制 (r, s) 打包为 r||s 格式 16 进制字符串（128 字符）。"""
        return f"{r:064x}{s:064x}"

    @staticmethod
    def decimal_to_asn1(r: int, s: int) -> str:
        """将 10 进制 (r, s) 打包为 ASN.1 DER 格式 16 进制字符串。"""
        return DerSequence([DerInteger(r), DerInteger(s)]).encode().hex()

    @staticmethod
    def asn1_to_decimal(asn1_sig_hex: str) -> Tuple[int, int]:
        """解析 ASN.1 DER 签名，返回 10 进制 (r, s)。"""
        return SM2SignatureFormat.parse_asn1(asn1_sig_hex)


# ---------------------------------------------------------------------------
# ASN.1 DER / PEM 通用工具
# ---------------------------------------------------------------------------

class ASN1Utils:
    """ASN.1 DER 数据（证书、签名等）通用解析、修改、重打包。"""

    # Tag class / constructed flag 常量
    TAG_INTEGER = 0x02
    TAG_BIT_STRING = 0x03
    TAG_OCTET_STRING = 0x04
    TAG_NULL = 0x05
    TAG_OBJECT_ID = 0x06
    TAG_SEQUENCE = 0x30
    TAG_SET = 0x31
    TAG_PRINTABLE_STRING = 0x13
    TAG_UTF8_STRING = 0x0C
    TAG_IA5_STRING = 0x16
    TAG_UTC_TIME = 0x17
    TAG_GENERALIZED_TIME = 0x18

    CONSTRUCTED_MASK = 0x20

    @staticmethod
    def pem_to_der(pem_data: Union[str, bytes]) -> bytes:
        """将 PEM 格式文本转换为 DER 字节。"""
        if isinstance(pem_data, bytes):
            pem_data = pem_data.decode("ascii", errors="ignore")
        lines = [line.strip() for line in pem_data.strip().splitlines()]
        body = "".join(line for line in lines if not line.startswith("-----") and line)
        return binascii.a2b_base64(body)

    @staticmethod
    def der_to_pem(der_data: bytes, label: str = "CERTIFICATE") -> str:
        """将 DER 字节转换为 PEM 格式文本。"""
        b64 = binascii.b2a_base64(der_data, newline=False).decode("ascii")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"

    @classmethod
    def _read_length(cls, data: bytes, offset: int) -> Tuple[int, int]:
        """
        从 offset 开始读取 ASN.1 length。

        Returns:
            (length, new_offset)
        """
        if offset >= len(data):
            raise ValueError("unexpected end of data while reading length")
        first = data[offset]
        offset += 1
        if first & 0x80 == 0:
            return first, offset
        num_bytes = first & 0x7F
        if num_bytes == 0:
            raise ValueError("indefinite length not supported")
        if offset + num_bytes > len(data):
            raise ValueError("length bytes exceed data boundary")
        length = int.from_bytes(data[offset : offset + num_bytes], "big")
        return length, offset + num_bytes

    @classmethod
    def _read_tlv(cls, data: bytes, offset: int) -> Tuple[int, int, bytes, int]:
        """
        从 offset 开始读取一个完整 TLV。

        Returns:
            (tag, length, value_bytes, new_offset)
        """
        if offset >= len(data):
            raise ValueError("unexpected end of data while reading tag")
        tag = data[offset]
        offset += 1
        length, offset = cls._read_length(data, offset)
        if offset + length > len(data):
            raise ValueError("value exceeds data boundary")
        value = data[offset : offset + length]
        return tag, length, value, offset + length

    @classmethod
    def parse_der(cls, der_data: bytes) -> List[dict]:
        """
        递归解析 DER 数据，返回 TLV 树。

        每个节点为 dict：
            {
                "tag": int,              # ASN.1 tag
                "length": int,           # value 长度
                "raw": bytes,            # 原始 value 字节
                "children": [...] | None # 构造类型才有子节点
            }

        Args:
            der_data: DER 字节，可一次性传入多个连续 TLV。

        Returns:
            TLV 节点列表。
        """
        nodes: List[dict] = []
        offset = 0
        while offset < len(der_data):
            tag, length, value, offset = cls._read_tlv(der_data, offset)
            node = {"tag": tag, "length": length, "raw": value, "children": None}
            if tag & cls.CONSTRUCTED_MASK:
                node["children"] = cls.parse_der(value)
            nodes.append(node)
        return nodes

    @classmethod
    def repack_der(cls, nodes: Union[dict, List[dict]]) -> bytes:
        """
        将 parse_der 得到的 TLV 树重新打包为 DER 字节。

        Args:
            nodes: 单个节点或节点列表。
        """
        if isinstance(nodes, dict):
            nodes = [nodes]
        out = bytearray()
        for node in nodes:
            tag = node["tag"]
            if node["children"] is not None:
                value = cls.repack_der(node["children"])
            else:
                value = node["raw"]
            length = len(value)
            out.append(tag)
            if length < 0x80:
                out.append(length)
            else:
                length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
                out.append(0x80 | len(length_bytes))
                out.extend(length_bytes)
            out.extend(value)
        return bytes(out)

    @classmethod
    def get_node(cls, nodes: Union[dict, List[dict]], path: List[int]) -> dict:
        """
        按路径获取 TLV 节点。

        Args:
            nodes: parse_der 结果（单个节点或节点列表）。
            path: 每一层构造类型中的子节点索引，例如 [0, 1, 0]。
        """
        if isinstance(nodes, dict):
            current: Any = nodes
        else:
            current = nodes[path[0]]
            path = path[1:]

        for idx in path:
            if not isinstance(current, dict):
                raise IndexError(f"path traversal reached non-node object: {current}")
            children = current.get("children")
            if not isinstance(children, list):
                raise IndexError(f"path {path} reaches non-constructed node")
            current = children[idx]

        if not isinstance(current, dict):
            raise IndexError(f"path {path} does not point to a TLV node")
        return current

    @classmethod
    def set_node_value(
        cls,
        nodes: Union[dict, List[dict]],
        path: List[int],
        new_value: Union[bytes, int],
        *,
        value_encoder: Optional[Callable[[Any], bytes]] = None,
    ) -> bytes:
        """
        修改指定路径节点的 value，并重新打包为 DER。

        Args:
            nodes: parse_der 结果。
            path: 节点路径。
            new_value: 新值；可以是 bytes 或 int（当 value_encoder 未指定时，
                       int 会被编码为 DerInteger 的 value 部分，外层 tag 保持不变）。
            value_encoder: 可选自定义编码函数，接收 new_value 返回该 tag 对应的 value 字节（不含 tag/length）。

        Returns:
            重新打包后的 DER 字节。
        """
        if isinstance(nodes, dict):
            nodes = [nodes]

        node = cls.get_node(nodes, path)

        if value_encoder is not None:
            encoded = value_encoder(new_value)
        elif isinstance(new_value, int):
            # 编码为 INTEGER 的 value 部分（不含 tag/length），外层 tag 保持不变
            if new_value < 0:
                raise ValueError("negative integer not supported")
            if new_value == 0:
                encoded = b"\x00"
            else:
                encoded = new_value.to_bytes((new_value.bit_length() + 7) // 8, "big")
                if encoded[0] & 0x80:
                    encoded = b"\x00" + encoded
        elif isinstance(new_value, bytes):
            encoded = new_value
        else:
            raise TypeError("new_value must be bytes or int when value_encoder is None")

        # 替换节点：保持 tag 不变，替换 raw/children
        node["raw"] = encoded
        node["length"] = len(encoded)
        node["children"] = None

        return cls.repack_der(nodes)


# ---------------------------------------------------------------------------
# 自定义数据打包 / 解析
# ---------------------------------------------------------------------------

class PackageUtils:
    """自定义数据打包与解析工具（长度前缀、TLV 等）。"""

    # 默认长度字段占用字节数
    DEFAULT_LENGTH_SIZE = 4

    @staticmethod
    def pack_with_length(
        data: HexOrBytes,
        length_size: int = DEFAULT_LENGTH_SIZE,
        endian: str = "big",
    ) -> bytes:
        """
        将数据打包为：length(定长) || data。

        Args:
            data: 原始数据或 hex 字符串。
            length_size: 长度字段字节数（1/2/4/8）。
            endian: "big" 或 "little"。
        """
        b = to_bytes(data)
        if len(b) >= (1 << (length_size * 8)):
            raise ValueError("data length exceeds length field capacity")
        length_bytes = len(b).to_bytes(length_size, endian)
        return length_bytes + b

    @staticmethod
    def unpack_with_length(
        data: bytes,
        length_size: int = DEFAULT_LENGTH_SIZE,
        endian: str = "big",
    ) -> Tuple[bytes, bytes]:
        """
        从带长度前缀的数据中解包出第一段数据。

        Returns:
            (payload, remaining)
        """
        if len(data) < length_size:
            raise ValueError("data too short to contain length field")
        length = int.from_bytes(data[:length_size], endian)
        end = length_size + length
        if end > len(data):
            raise ValueError("data too short for declared length")
        return data[length_size:end], data[end:]

    @staticmethod
    def pack_multi(parts: List[HexOrBytes], length_size: int = DEFAULT_LENGTH_SIZE, endian: str = "big") -> bytes:
        """将多个数据段依次打包为 length||data。"""
        out = bytearray()
        for part in parts:
            out.extend(PackageUtils.pack_with_length(part, length_size, endian))
        return bytes(out)

    @staticmethod
    def unpack_multi(data: bytes, length_size: int = DEFAULT_LENGTH_SIZE, endian: str = "big") -> List[bytes]:
        """将 length||data 序列全部解包为列表。"""
        parts: List[bytes] = []
        remaining = data
        while remaining:
            payload, remaining = PackageUtils.unpack_with_length(remaining, length_size, endian)
            parts.append(payload)
        return parts

    @staticmethod
    def tlv_encode(tag: int, value: HexOrBytes) -> bytes:
        """
        简易 TLV 编码（Tag 1 字节，Length 1~5 字节）。

        Args:
            tag: 1 字节标签。
            value: 数据内容。
        """
        b = to_bytes(value)
        length = len(b)
        out = bytearray()
        out.append(tag & 0xFF)
        if length < 0x80:
            out.append(length)
        elif length <= 0xFF:
            out.extend([0x81, length])
        else:
            length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
            out.append(0x80 | len(length_bytes))
            out.extend(length_bytes)
        out.extend(b)
        return bytes(out)

    @staticmethod
    def tlv_decode(data: bytes) -> Tuple[int, bytes, bytes]:
        """
        简易 TLV 解码。

        Returns:
            (tag, value, remaining)
        """
        if len(data) < 2:
            raise ValueError("data too short for TLV")
        tag = data[0]
        offset = 1
        first = data[offset]
        offset += 1
        if first & 0x80 == 0:
            length = first
        else:
            num_bytes = first & 0x7F
            if num_bytes == 0:
                raise ValueError("indefinite length not supported")
            length = int.from_bytes(data[offset : offset + num_bytes], "big")
            offset += num_bytes
        end = offset + length
        if end > len(data):
            raise ValueError("TLV value exceeds data boundary")
        return tag, data[offset:end], data[end:]


# ---------------------------------------------------------------------------
# 便捷组合函数（适合脚本直接调用）
# ---------------------------------------------------------------------------

def sm2_sign_data(
    private_key: str,
    public_key: str,
    data: HexOrBytes,
    *,
    asn1: bool = False,
    with_sm3: bool = True,
) -> str:
    """对数据做 SM2 签名，默认使用 SM2withSM3。"""
    return SM2Utils.sign(private_key, public_key, data, asn1=asn1, with_sm3=with_sm3)


def sm2_verify_data(
    public_key: str,
    signature: str,
    data: HexOrBytes,
    *,
    asn1: bool = False,
    with_sm3: bool = True,
) -> bool:
    """对 SM2 签名做验签，默认使用 SM2withSM3。"""
    return SM2Utils.verify(public_key, signature, data, asn1=asn1, with_sm3=with_sm3)


def sm2_sign_decimal(
    d: int,
    m: bytes,
    *,
    with_sm3: bool = True,
    k: Optional[Union[int, str]] = None,
) -> Tuple[int, int, str]:
    """
    使用 10 进制私钥 d 对消息 m 签名，返回 (r, s, public_key)。

    public_key 为 04 开头的 130 字符 hex，可直接用于后续验签或打包。
    """
    pub = SM2Utils.public_key_from_private(d)
    r, s = SM2Utils.sign_decimal(d, pub, m, with_sm3=with_sm3, k=k)
    return r, s, pub


def sm2_verify_decimal(
    public_key: str,
    r: int,
    s: int,
    m: bytes,
    *,
    with_sm3: bool = True,
) -> bool:
    """使用 10 进制 (r, s) 对消息 m 验签。"""
    return SM2Utils.verify_decimal(public_key, r, s, m, with_sm3=with_sm3)


def parse_certificate_pem(pem_data: Union[str, bytes]) -> List[dict]:
    """解析 PEM 证书，返回 ASN.1 TLV 树。"""
    der = ASN1Utils.pem_to_der(pem_data)
    return ASN1Utils.parse_der(der)


def modify_certificate_der(der_data: bytes, path: List[int], new_value: Union[bytes, int]) -> bytes:
    """修改 DER 证书指定 ASN.1 节点后重新打包。"""
    nodes = ASN1Utils.parse_der(der_data)
    return ASN1Utils.set_node_value(nodes, path, new_value)


# ---------------------------------------------------------------------------
# 自测示例
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("GMSSL 工具自测")
    print("=" * 60)

    # 0. SM3 填充
    padded_abc = sm3_padding("616263")
    assert padded_abc.hex().startswith("61626380")
    assert len(padded_abc) % 64 == 0
    # 最后 8 字节是原始长度 24 bit = 0x18
    assert padded_abc[-8:] == b"\x00\x00\x00\x00\x00\x00\x00\x18"
    # 与标准 SM3 测试向量 "abc" 的填充结果一致
    assert padded_abc.hex() == (
        "61626380" + "00" * 52 + "0000000000000018"
    )
    assert sm3_hash("616263") == "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    print("[SM3] padding ok")

    # 1. SM2 密钥生成
    priv, pub = SM2Utils.generate_keypair()
    print(f"[SM2] private key length: {len(priv)}")
    print(f"[SM2] public  key length: {len(pub)}")

    # 2. SM2withSM3 签名（raw / asn1）
    msg = b"hello gmssl"
    raw_sig = SM2Utils.sign(priv, pub, msg, with_sm3=True)
    asn1_sig = SM2SignatureFormat.raw_to_asn1(raw_sig)
    print(f"[SM2] raw  signature: {raw_sig[:20]}...{raw_sig[-20:]}")
    print(f"[SM2] asn1 signature: {asn1_sig[:20]}...{asn1_sig[-20:]}")

    # 3. 验签
    assert SM2Utils.verify(pub, raw_sig, msg, with_sm3=True) is True
    assert SM2Utils.verify(pub, asn1_sig, msg, with_sm3=True, asn1=True) is True
    print("[SM2] verify ok")

    # 4. 签名格式互转
    raw_from_asn1 = SM2SignatureFormat.asn1_to_raw(asn1_sig)
    asn1_from_raw = SM2SignatureFormat.raw_to_asn1(raw_sig)
    assert raw_from_asn1 == raw_sig
    assert asn1_from_raw == asn1_sig
    r, s = SM2SignatureFormat.parse_asn1(asn1_sig)
    print(f"[SM2] parsed r: {hex(r)[:30]}...")
    print(f"[SM2] parsed s: {hex(s)[:30]}...")
    print("[SM2] format convert ok")

    # 5. 10 进制私钥 / (r, s) 工作流
    d_int = int(priv, 16)
    pub_from_d = SM2Utils.public_key_from_private(d_int)
    assert pub_from_d == pub
    r_dec, s_dec = SM2Utils.sign_decimal(d_int, pub, msg, with_sm3=True)
    assert SM2Utils.verify_decimal(pub, r_dec, s_dec, msg, with_sm3=True) is True
    raw_from_dec = SM2SignatureFormat.decimal_to_raw(r_dec, s_dec)
    asn1_from_dec = SM2SignatureFormat.decimal_to_asn1(r_dec, s_dec)
    assert SM2Utils.verify(pub, raw_from_dec, msg, with_sm3=True) is True
    assert SM2Utils.verify(pub, asn1_from_dec, msg, with_sm3=True, asn1=True) is True
    r_back, s_back = SM2SignatureFormat.asn1_to_decimal(asn1_from_dec)
    assert (r_back, s_back) == (r_dec, s_dec)
    print("[SM2] decimal workflow ok")

    # 6. 自定义打包 / 解析
    packed = PackageUtils.pack_multi([b"AAA", b"BBB", b"CCC"])
    parts = PackageUtils.unpack_multi(packed)
    assert parts == [b"AAA", b"BBB", b"CCC"]
    print("[Pack] length-prefix ok")

    tlv = PackageUtils.tlv_encode(0x01, "deadbeef") + PackageUtils.tlv_encode(0x02, b"world")
    tag1, val1, rest = PackageUtils.tlv_decode(tlv)
    tag2, val2, _ = PackageUtils.tlv_decode(rest)
    assert tag1 == 0x01 and val1 == bytes.fromhex("deadbeef")
    assert tag2 == 0x02 and val2 == b"world"
    print("[Pack] TLV ok")

    # 7. ASN.1 签名解析 / 修改 / 重打包
    der_sig = bytes.fromhex(asn1_sig)
    tree = ASN1Utils.parse_der(der_sig)
    # 修改 SEQUENCE 中第一个 INTEGER（r）为 r+1 后重新打包（仅演示，会使签名失效）
    original_r_node = tree[0]["children"][0]
    original_r_int = int(original_r_node["raw"].hex(), 16)
    modified_der = ASN1Utils.set_node_value(tree, [0, 0], original_r_int + 1)
    modified_tree = ASN1Utils.parse_der(modified_der)
    modified_r_node = modified_tree[0]["children"][0]
    assert modified_r_node["tag"] == 0x02
    assert int(modified_r_node["raw"].hex(), 16) == original_r_int + 1
    print("[ASN1] parse-modify-repack ok")

    print("=" * 60)
    print("所有自测通过")
    print("=" * 60)
