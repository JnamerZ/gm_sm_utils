# -*- coding: utf-8 -*-
"""
SM4-GCM 认证标签的 SageMath 实现

调用 sm4_modes.py 中的 SM4 单分组加密接口作为黑盒，
GHASH 与 GCM 计数器逻辑在 SageMath 中用 GF(2^128) 实现，
方便在 CTF 中验证、调试或魔改标签计算过程。

依赖：
    - SageMath
    - gmssl（sm4_modes.py 依赖）

用法：
    load("sm4_gcm_sage.sage")

    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv  = bytes.fromhex("000000000000000000000000")
    ct  = bytes.fromhex("...")
    aad = b"meta"

    tag = sm4_gcm_tag(key, iv, ct, aad=aad)
    print(tag.hex())
"""

import sys
from pathlib import Path

# 把仓库根目录加入 Python 路径，以便导入 sm4_modes
_here = Path(__file__).resolve().parent
if str(_here) not in sys.path:
    sys.path.insert(0, str(_here))

from sm4_modes import _SM4Block


# ---------------------------------------------------------------------------
# GF(2^128) 与 GHASH
# ---------------------------------------------------------------------------

# GHASH 的约化多项式：x^128 + x^7 + x^2 + x + 1
# SageMath 中 GF(2^128) 的本原多项式可自定义
_R.<x> = GF(2)[]
_GHASH_POLY = x^128 + x^7 + x^2 + x + 1
F = GF(2^128, modulus=_GHASH_POLY, name="a")


def _bit_reverse_128(n: int) -> int:
    """将 128 位整数按位反转，匹配 GHASH 与 SageMath GF(2^128) 的位序差异。"""
    b = "{:0128b}".format(n)
    return int(b[::-1], 2)


def _bytes_to_gf(b: bytes):
    """16 字节 GHASH 块 -> GF(2^128) 元素。"""
    assert len(b) == 16
    n = int.from_bytes(b, "big")
    return F._cache.fetch_int(_bit_reverse_128(n))


def _gf_to_bytes(elem):
    """GF(2^128) 元素 -> 16 字节 GHASH 块。"""
    n = elem.to_integer()
    return _bit_reverse_128(n).to_bytes(16, "big")


def _inc32(counter: bytes) -> bytes:
    """GCM 计数器后 32 位加 1，模 2^32。"""
    n = int.from_bytes(counter, "big")
    n = ((n >> 32) << 32) | (((n & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)
    return n.to_bytes(16, "big")


def _ghash(h_elem, aad: bytes, ciphertext: bytes):
    """
    GHASH_H(A, C)。
    输入均按 16 字节分组，不足补零；最后追加 64+64 bit 长度块。
    """
    def blocks(data: bytes):
        for i in range(0, len(data), 16):
            yield _bytes_to_gf(data[i : i + 16].ljust(16, b"\x00"))

    y = F(0)
    for blk in blocks(aad):
        y = (y + blk) * h_elem
    for blk in blocks(ciphertext):
        y = (y + blk) * h_elem

    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    y = (y + _bytes_to_gf(len_block.to_bytes(16, "big"))) * h_elem
    return y


# ---------------------------------------------------------------------------
# GCM 标签计算
# ---------------------------------------------------------------------------


def sm4_gcm_tag(key: bytes, iv: bytes, ciphertext: bytes, *, aad: bytes = b"", tag_len: int = 16) -> bytes:
    """
    使用 SageMath GF(2^128) 计算 SM4-GCM 认证标签。

    Args:
        key: 16 字节 SM4 密钥。
        iv: 初始化向量；推荐 12 字节。
        ciphertext: 已加密的密文。
        aad: 附加认证数据，默认空。
        tag_len: 标签长度，默认 16。

    Returns:
        tag 字节。
    """
    if len(key) != 16:
        raise ValueError("SM4 key must be 16 bytes")
    if tag_len < 1 or tag_len > 16:
        raise ValueError("tag_len must be 1~16")

    # H = E(K, 0^128)
    h_bytes = _SM4Block.encrypt(key, b"\x00" * 16)
    h_elem = _bytes_to_gf(h_bytes)

    # J0
    if len(iv) == 12:
        j0 = iv + b"\x00\x00\x00\x01"
    else:
        j0 = _gf_to_bytes(_ghash(h_elem, b"", iv))

    # S = GHASH_H(AAD, CT)
    s = _ghash(h_elem, aad, ciphertext)

    # tag = GCTR(K, J0, S) 的前 tag_len 字节
    tag_ks = _SM4Block.encrypt(key, j0)
    tag = bytes(int.__xor__(x, y) for x, y in zip(_gf_to_bytes(s), tag_ks))[:tag_len]
    return tag


def sm4_gcm_sage_encrypt(key: bytes, iv: bytes, plaintext: bytes, *, aad: bytes = b"", tag_len: int = 16):
    """
    使用 SageMath GF(2^128) 实现完整 SM4-GCM 加密。

    返回 (ciphertext, tag)。
    计数器部分复用 sm4_modes.py 的 _gcm_ctr 以避免重复实现。
    """
    from sm4_modes import _gcm_ctr
    ciphertext = _xor(_gcm_ctr(key, iv, len(plaintext)), plaintext)
    tag = sm4_gcm_tag(key, iv, ciphertext, aad=aad, tag_len=tag_len)
    return ciphertext, tag


def _xor(a: bytes, b: bytes) -> bytes:
    # SageMath 中 ^ 是幂运算，必须显式使用 int.__xor__
    return bytes(int.__xor__(x, y) for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

def _self_test():
    print("=" * 60)
    print("SM4-GCM SageMath 工具自测")
    print("=" * 60)

    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("000000000000000000000000")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210") * 2
    aad = b"meta"

    # 与 sm4_modes.py 的 GCM 标签交叉验证
    from sm4_modes import SM4Modes
    ct_ref, tag_ref = SM4Modes.gcm_encrypt(key, iv, pt, aad=aad)
    tag_sage = sm4_gcm_tag(key, iv, ct_ref, aad=aad)
    assert tag_sage == tag_ref, f"tag mismatch: {tag_sage.hex()} != {tag_ref.hex()}"
    print(f"[GCM] tag cross-check ok (tag={tag_sage.hex()})")

    # 完整加密交叉验证
    ct_sage, tag_sage2 = sm4_gcm_sage_encrypt(key, iv, pt, aad=aad)
    assert ct_sage == ct_ref
    assert tag_sage2 == tag_ref
    print("[GCM] full encrypt cross-check ok")

    # 非 12 字节 IV 的标签交叉验证
    for iv_len in [13, 16, 17]:
        iv2 = bytes(range(iv_len))
        ct_ref2, tag_ref2 = SM4Modes.gcm_encrypt(key, iv2, pt, aad=aad)
        tag_sage3 = sm4_gcm_tag(key, iv2, ct_ref2, aad=aad)
        assert tag_sage3 == tag_ref2, f"iv_len={iv_len} tag mismatch"
        print(f"[GCM] iv_len={iv_len} tag cross-check ok")

    print("=" * 60)
    print("SageMath GCM 自测通过")
    print("=" * 60)


import sys
if sys.argv[0].endswith("sm4_gcm_sage.sage"):
    _self_test()
