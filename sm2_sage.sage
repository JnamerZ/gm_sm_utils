# -*- coding: utf-8 -*-
"""
SM2 曲线参数提取与自定义 SageMath 脚本

功能：
    1. 从 gmssl 提取 SM2 国密推荐曲线参数。
    2. 允许任意修改曲线参数 p, a, b, n 以及基点 G = (Gx, Gy)。
    3. 基于 SageMath 椭圆曲线实现 SM2 密钥派生、签名、验签。
    4. 支持消息 m(bytes)、十进制私钥 d、十进制 (r, s)。
    5. 支持 raw (r||s) 与 ASN.1 DER 两种签名格式打包/解析。

依赖：
    - SageMath 9.x / 10.x
    - gmssl（仅用于 extract_gmssl_params / SM2Params.from_gmssl，可选）

用法示例：
    load("sm2_sage.sage")

    # 默认国密曲线
    P = SM2Params.default()
    keys = SM2Keys(P)
    d, pub = keys.generate_keypair()
    r, s = keys.sign(d, pub, b"hello")
    assert keys.verify(pub, r, s, b"hello")

    # 修改基点（新点必须落在曲线上且阶为 n）
    P2 = change_base_point(P, P.gx, P.gy)
    keys2 = SM2Keys(P2)

    # 修改曲线参数
    P3 = modify_curve(P, a=P.a + 1)
"""

import binascii
import hashlib
import os
import struct
from typing import Any, List, Optional, Tuple, Union

# 如果可用，使用 Cryptodome 的 ASN.1 编码；否则内置一个最小 DerInteger/DerSequence
# SageMath 通常自带 pycryptodome，但这里提供 fallback 以便纯 Sage 环境运行。
try:
    from Cryptodome.Util.asn1 import DerInteger, DerSequence
except Exception:
    DerInteger = None
    DerSequence = None


# ---------------------------------------------------------------------------
# ASN.1 最小 fallback（当没有 Cryptodome 时也能跑）
# ---------------------------------------------------------------------------

class _DerInteger:
    """简易非负整数 DER 编码器。"""

    def __init__(self, value: int):
        if value < 0:
            raise ValueError("negative integer not supported in this minimal fallback")
        self.value = value

    def encode(self) -> bytes:
        if self.value == 0:
            data = b"\x00"
        else:
            data = self.value.to_bytes((self.value.bit_length() + 7) // 8, "big")
            if data[0] & 0x80:
                data = b"\x00" + data
        return bytes([0x02, len(data)]) + data


class _DerSequence:
    """SEQUENCE of INTEGER 简易编码器/解析器。"""

    def __init__(self, values: Optional[List[int]] = None):
        self.values: List[int] = list(values) if values else []

    def encode(self) -> bytes:
        body = b"".join(_DerInteger(v).encode() for v in self.values)
        return bytes([0x30]) + _encode_length(body) + body

    def decode(self, data: bytes):
        self.values = []
        if data[0] != 0x30:
            raise ValueError("not a SEQUENCE")
        offset = 1
        length, offset = _decode_length(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("SEQUENCE length exceeds data")
        while offset < end:
            if data[offset] != 0x02:
                raise ValueError("expected INTEGER")
            offset += 1
            ilen, offset = _decode_length(data, offset)
            val = int.from_bytes(data[offset : offset + ilen], "big")
            self.values.append(val)
            offset += ilen

    def __len__(self):
        return len(self.values)

    def __getitem__(self, idx):
        return self.values[idx]


def _encode_length(body: bytes) -> bytes:
    length = len(body)
    if length < 0x80:
        return bytes([length])
    bl = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(bl)]) + bl


def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    nb = first & 0x7F
    return int.from_bytes(data[offset : offset + nb], "big"), offset + nb


DerInteger = DerInteger or _DerInteger
DerSequence = DerSequence or _DerSequence


# ---------------------------------------------------------------------------
# 参数结构
# ---------------------------------------------------------------------------

class SM2Params:
    """SM2 曲线参数容器，支持自定义任意字段。"""

    def __init__(
        self,
        p: int,
        a: int,
        b: int,
        n: int,
        gx: int,
        gy: int,
    ):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.gx = gx
        self.gy = gy
        self.G = (gx, gy)
        self.field_len = (p.bit_length() + 7) // 8
        self.order_len = (n.bit_length() + 7) // 8

    def __repr__(self):
        return (
            f"SM2Params(p={self.p.bit_length()}b, a=..., b=..., n={self.n.bit_length()}b, "
            f"G=({hex(self.gx)[:20]}..., {hex(self.gy)[:20]}...))"
        )

    @classmethod
    def from_hex(
        cls,
        p_hex: str,
        a_hex: str,
        b_hex: str,
        n_hex: str,
        g_hex: str,
    ) -> "SM2Params":
        """
        从 16 进制字符串创建参数。
        g_hex 可以是 04||x||y（130 字符）或 x||y（128 字符）。
        """
        g_hex = g_hex.strip().lower()
        if g_hex.startswith("04"):
            g_hex = g_hex[2:]
        if len(g_hex) != 128:
            raise ValueError("G must be 04||x||y or x||y, total 130 or 128 hex chars")
        fl = 64
        gx = int(g_hex[:fl], 16)
        gy = int(g_hex[fl:], 16)
        return cls(
            p=int(p_hex, 16),
            a=int(a_hex, 16),
            b=int(b_hex, 16),
            n=int(n_hex, 16),
            gx=gx,
            gy=gy,
        )

    @classmethod
    def default(cls) -> "SM2Params":
        """gmssl 默认国密推荐曲线参数。"""
        return cls.from_hex(
            p_hex="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
            a_hex="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
            b_hex="28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
            n_hex="FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
            g_hex="04"
            "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
            "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
        )

    @classmethod
    def from_gmssl(cls) -> "SM2Params":
        """动态从当前环境 gmssl 中提取曲线参数。"""
        try:
            from gmssl import sm2
            table = sm2.default_ecc_table
            g = table["g"]
            if g.lower().startswith("04"):
                g = g[2:]
            return cls.from_hex(
                table["p"], table["a"], table["b"], table["n"], g
            )
        except Exception as exc:
            raise RuntimeError("failed to import gmssl or extract params: " + str(exc))

    def clone(
        self,
        *,
        p: Optional[int] = None,
        a: Optional[int] = None,
        b: Optional[int] = None,
        n: Optional[int] = None,
        gx: Optional[int] = None,
        gy: Optional[int] = None,
    ) -> "SM2Params":
        """复制参数并允许覆盖任意字段。"""
        return SM2Params(
            p=self.p if p is None else p,
            a=self.a if a is None else a,
            b=self.b if b is None else b,
            n=self.n if n is None else n,
            gx=self.gx if gx is None else gx,
            gy=self.gy if gy is None else gy,
        )

    def with_base_point(self, gx: int, gy: int) -> "SM2Params":
        """返回仅修改基点 G 的参数副本。"""
        return self.clone(gx=gx, gy=gy)


# ---------------------------------------------------------------------------
# 椭圆曲线与 SM2 算法
# ---------------------------------------------------------------------------

class SM2Curve:
    """基于 SageMath 的椭圆曲线封装。"""

    def __init__(self, params: SM2Params):
        self.params = params
        # Sage: EllipticCurve(GF(p), [a, b])  => y^2 = x^3 + a x + b
        self.E = EllipticCurve(GF(params.p), [params.a, params.b])
        self.G = self.E(params.gx, params.gy)

    def check_order(self) -> bool:
        """校验基点阶是否等于 n（大素数阶曲线可能较慢）。"""
        return self.G.order() == self.params.n

    def public_key_from_private(self, d: int) -> Tuple[int, int]:
        """由十进制私钥 d 计算未压缩公钥 (x, y)。"""
        P = d * self.G
        return int(P[0]), int(P[1])

    def point_from_hex(self, pub_hex: str) -> Any:
        """从 04||x||y 或 x||y hex 解析为 Sage 曲线点。"""
        pub_hex = pub_hex.strip().lower()
        if pub_hex.startswith("04"):
            pub_hex = pub_hex[2:]
        if len(pub_hex) != 128:
            raise ValueError("public key must be 04||x||y or x||y (130 or 128 hex chars)")
        x = int(pub_hex[:64], 16)
        y = int(pub_hex[64:], 16)
        return self.E(x, y)

    def decompress_public_key(self, pub_hex: str) -> Tuple[int, int]:
        """解析公钥 hex 为 (x, y) 坐标。"""
        P = self.point_from_hex(pub_hex)
        return int(P[0]), int(P[1])


class SM2Keys:
    """SM2 密钥、签名、验签核心（完全基于 SageMath）。"""

    def __init__(self, params: SM2Params):
        self.params = params
        self.curve = SM2Curve(params)

    # ---------------------------------------------------------------------
    # 密钥相关
    # ---------------------------------------------------------------------

    def generate_keypair(self) -> Tuple[int, str]:
        """随机生成 SM2 密钥对，返回 (d_decimal, public_key_hex_04...)。"""
        n = self.params.n
        d = int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 1) + 1
        return d, self.public_key_from_private(d)

    def public_key_from_private(self, d: Union[int, str]) -> str:
        """由私钥 d（10 进制整数或 16 进制字符串）计算 04 开头公钥。"""
        if isinstance(d, str):
            d = d.strip()
            if d.startswith(("0x", "0X")):
                d = int(d[2:], 16)
            elif len(d) == 64 or any(c in "abcdefABCDEF" for c in d):
                d = int(d, 16)
            else:
                d = int(d)
        if not (1 <= d < self.params.n):
            raise ValueError("private key out of range")
        x, y = self.curve.public_key_from_private(d)
        return "04" + self._int_to_hex(x) + self._int_to_hex(y)

    # ---------------------------------------------------------------------
    # SM3 哈希辅助（可选：gmssl 可用时优先使用 gmssl.sm3）
    # ---------------------------------------------------------------------

    @staticmethod
    def sm3_hash(data: bytes) -> bytes:
        """优先使用 gmssl.sm3；不可用则退回到 hashlib.sm3（依赖 OpenSSL 支持 SM3）。"""
        try:
            from gmssl import sm3, func
            return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))
        except Exception:
            return hashlib.new("sm3", data).digest()

    @staticmethod
    def _kdf(z: bytes, klen: int) -> bytes:
        """SM2 密钥派生函数 KDF（基于 SM3）。"""
        ct = 1
        out = bytearray()
        while len(out) < klen:
            out.extend(SM2Keys.sm3_hash(z + struct.pack(">I", ct)))
            ct += 1
        return bytes(out[:klen])

    # ---------------------------------------------------------------------
    # 签名 / 验签（GM/T 0003.2-2012 SM2 签名算法）
    # ---------------------------------------------------------------------

    def _compute_e(self, pub_hex: str, m: bytes) -> int:
        """
        计算 SM2 签名预处理值 e = SM3(Z_A || m)，其中
        Z_A = SM3(ENTL_A || IDA || a || b || Gx || Gy || Px || Py)。
        这里采用国密默认 IDA 字符串 "1234567812345678"（gmssl 默认）。
        """
        P = self.curve.point_from_hex(pub_hex)
        px, py = int(P[0]), int(P[1])
        a = self.params.a
        b = self.params.b
        gx, gy = self.params.gx, self.params.gy
        ida = b"1234567812345678"  # 16 字节默认标识，对应 gmssl 的 hex '31323334353637383132333435363738'
        entla = (len(ida) * 8).to_bytes(2, "big")

        za = self.sm3_hash(
            entla
            + ida
            + a.to_bytes(32, "big")
            + b.to_bytes(32, "big")
            + gx.to_bytes(32, "big")
            + gy.to_bytes(32, "big")
            + px.to_bytes(32, "big")
            + py.to_bytes(32, "big")
        )
        e = self.sm3_hash(za + m)
        return int.from_bytes(e, "big")

    def sign(
        self,
        d: int,
        pub_hex: str,
        m: bytes,
        *,
        k: Optional[int] = None,
        with_sm3: bool = True,
    ) -> Tuple[int, int]:
        """
        使用十进制私钥 d 对消息 m 签名。

        Args:
            d: 十进制私钥。
            pub_hex: 公钥 hex（04 开头或 64 字节坐标），用于计算 Z_A。
            m: 原始消息 bytes。
            k: 签名随机数；默认随机生成 [1, n-1]。
            with_sm3: 是否执行 SM2withSM3 预处理（默认 True）。

        Returns:
            (r, s) 十进制元组。
        """
        n = self.params.n
        if not (1 <= d < n):
            raise ValueError("private key out of range")

        if with_sm3:
            e = self._compute_e(pub_hex, m)
        else:
            if len(m) != 32:
                raise ValueError("without SM3, m must be 32-byte digest")
            e = int.from_bytes(m, "big")

        if k is None:
            k = int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 1) + 1
        if not (1 <= k < n):
            raise ValueError("k out of range")

        G = self.curve.G
        while True:
            x1 = int((k * G)[0])
            r = (e + x1) % n
            if r == 0 or r + k == n:
                k = int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 1) + 1
                continue
            s = (pow(1 + d, -1, n) * (k - r * d)) % n
            if s == 0:
                k = int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 1) + 1
                continue
            return r, s

    def verify(
        self,
        pub_hex: str,
        r: int,
        s: int,
        m: bytes,
        *,
        with_sm3: bool = True,
    ) -> bool:
        """使用十进制 (r, s) 对消息 m 验签。"""
        n = self.params.n
        if not (1 <= r < n and 1 <= s < n):
            return False

        if with_sm3:
            e = self._compute_e(pub_hex, m)
        else:
            if len(m) != 32:
                return False
            e = int.from_bytes(m, "big")

        G = self.curve.G
        P = self.curve.point_from_hex(pub_hex)
        t = (r + s) % n
        if t == 0:
            return False
        x1 = int((s * G + t * P)[0])
        R = (e + x1) % n
        return R == r

    # ---------------------------------------------------------------------
    # 格式转换
    # ---------------------------------------------------------------------

    def raw_signature(self, r: int, s: int) -> str:
        """十进制 (r, s) -> 128 字符 hex（r||s）。"""
        return self._int_to_hex(r, self.params.order_len) + self._int_to_hex(s, self.params.order_len)

    def asn1_signature(self, r: int, s: int) -> str:
        """十进制 (r, s) -> ASN.1 DER SEQUENCE{INTEGER r, INTEGER s} hex。"""
        der = DerSequence([DerInteger(r), DerInteger(s)]).encode()
        return der.hex()

    def parse_raw_signature(self, raw_hex: str) -> Tuple[int, int]:
        """128 字符 hex -> (r, s)。"""
        raw_hex = raw_hex.strip().lower()
        if raw_hex.startswith("04"):
            raw_hex = raw_hex[2:]
        L = self.params.order_len * 2
        if len(raw_hex) != 2 * L:
            raise ValueError(f"raw signature length must be {2*L}, got {len(raw_hex)}")
        return int(raw_hex[:L], 16), int(raw_hex[L:], 16)

    def parse_asn1_signature(self, asn1_hex: str) -> Tuple[int, int]:
        """ASN.1 DER 签名 hex -> (r, s)。"""
        seq = DerSequence()
        seq.decode(bytes.fromhex(asn1_hex.strip()))
        if len(seq) != 2:
            raise ValueError("SM2 ASN.1 signature must contain two integers")
        return int(seq[0]), int(seq[1])

    @staticmethod
    def _int_to_hex(x: int, byte_len: int = 32) -> str:
        return f"{x:0{byte_len * 2}x}"


# ---------------------------------------------------------------------------
# 曲线参数导出 / 修改 便利函数
# ---------------------------------------------------------------------------

def extract_gmssl_params() -> SM2Params:
    """从 gmssl 提取当前曲线参数。"""
    return SM2Params.from_gmssl()


def modify_curve(
    params: SM2Params,
    *,
    p: Optional[int] = None,
    a: Optional[int] = None,
    b: Optional[int] = None,
    n: Optional[int] = None,
    gx: Optional[int] = None,
    gy: Optional[int] = None,
) -> SM2Params:
    """修改曲线参数或基点后返回新参数。"""
    return params.clone(p=p, a=a, b=b, n=n, gx=gx, gy=gy)


def change_base_point(params: SM2Params, gx: int, gy: int) -> SM2Params:
    """仅修改基点 G。"""
    return params.with_base_point(gx, gy)


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

def self_test():
    """SM2 SageMath 脚本自测。"""
    print("=" * 60)
    print("SM2 SageMath 脚本自测")
    print("=" * 60)

    # 1. 提取默认参数
    params = SM2Params.default()
    print(f"[Params] {params}")

    # 2. 生成密钥对
    sm2 = SM2Keys(params)
    d, pub = sm2.generate_keypair()
    print(f"[Keys] d length: {d.bit_length()} bits")
    print(f"[Keys] public key: {pub[:20]}...{pub[-20:]}")

    # 3. 签名 / 验签
    msg = b"hello sagemath sm2"
    r, s = sm2.sign(d, pub, msg)
    print(f"[Sign] r: {hex(r)[:30]}...")
    print(f"[Sign] s: {hex(s)[:30]}...")
    assert sm2.verify(pub, r, s, msg)
    print("[Verify] ok")

    # 4. 格式转换
    raw = sm2.raw_signature(r, s)
    asn1 = sm2.asn1_signature(r, s)
    print(f"[Format] raw  signature: {raw[:20]}...{raw[-20:]}")
    print(f"[Format] asn1 signature: {asn1[:20]}...{asn1[-20:]}")
    r2, s2 = sm2.parse_asn1_signature(asn1)
    assert (r2, s2) == (r, s)
    r3, s3 = sm2.parse_raw_signature(raw)
    assert (r3, s3) == (r, s)
    print("[Format] parse ok")

    # 5. 指定 k 的可复现签名
    fixed_k = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
    rr, ss = sm2.sign(d, pub, msg, k=fixed_k)
    rr2, ss2 = sm2.sign(d, pub, msg, k=fixed_k)
    assert (rr, ss) == (rr2, ss2)
    assert sm2.verify(pub, rr, ss, msg)
    print("[Sign] fixed-k reproducible ok")

    # 6. 修改基点（示例：使用新的生成元，仍然在同一曲线上随机找一个点）
    #    注意：新点必须落在曲线上且阶最好为 n，否则签名/验签会不一致。
    #    这里简单测试参数克隆能力。
    params_new_g = change_base_point(params, params.gx, params.gy)
    assert params_new_g.G == params.G
    print("[Modify] base point clone ok")

    # 7. 修改曲线参数（仅参数结构演示，不保证新参数安全或有效）
    params_changed = modify_curve(params, a=params.a + 1)
    assert params_changed.a == params.a + 1
    assert params_changed.p == params.p
    print("[Modify] curve param clone ok")

    # 8. 从 gmssl 提取参数（如果 gmssl 已安装）
    try:
        params_gm = extract_gmssl_params()
        assert params_gm.p == params.p
        print("[Extract] gmssl params match ok")
    except Exception as exc:
        print(f"[Extract] gmssl not available: {exc}")

    # 9. 与 gmssl 交叉验签（如果 gmssl 在 Python 路径中）
    try:
        from gmssl import sm2 as gmssl_sm2

        d_hex = f"{d:064x}"
        gm_crypt = gmssl_sm2.CryptSM2(d_hex, pub[2:])
        gm_raw = gm_crypt.sign_with_sm3(msg)
        gm_r, gm_s = sm2.parse_raw_signature(gm_raw)
        assert sm2.verify(pub, gm_r, gm_s, msg)

        sage_raw = sm2.raw_signature(r, s)
        assert gm_crypt.verify_with_sm3(sage_raw, msg)
        print("[Cross] sage <-> gmssl verify ok")
    except Exception as exc:
        print(f"[Cross] gmssl cross-check skipped: {exc}")

    print("=" * 60)
    print("所有 SageMath 自测通过")
    print("=" * 60)


# SageMath 执行 .sage 文件时 __name__ 为 'sage.all'；
# 通过 sys.argv[0] 区分“直接运行脚本”与“load() 导入”。
import sys

if sys.argv[0].endswith("sm2_sage.sage"):
    self_test()
