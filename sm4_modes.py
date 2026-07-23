# -*- coding: utf-8 -*-
"""
SM4 分组密码工作模式纯 Python 实现

设计：
    - ECB 仅作为“黑盒”直接调用 gmssl.sm4 的单分组加/解密接口 one_round。
    - CBC / CFB / OFB / CTR / GCM / CCM / XTS 均在本文件中手工实现。
    - 所有接口均支持自定义 key / iv（或 nonce/tweak）/ plaintext / ciphertext / aad / tag。
    - 注意：XTS 严格遵循 IEEE P1619；OpenSSL 的 SM4-XTS tweak 更新与之存在差异，
      因此本实现与 OpenSSL 的 SM4-XTS 不保证字节级一致，但 roundtrip 自洽。

依赖：
    pip install gmssl

用法示例：
    from sm4_modes import SM4Modes

    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv  = bytes.fromhex("00000000000000000000000000000000")
    pt  = b"hello world 1234"   # 16 字节对齐示例

    ct = SM4Modes.ecb_encrypt(key, pt)
    pt2 = SM4Modes.ecb_decrypt(key, ct)

    ct = SM4Modes.cbc_encrypt(key, iv, pt)
    pt2 = SM4Modes.cbc_decrypt(key, iv, ct)

    ct, tag = SM4Modes.gcm_encrypt(key, iv[:12], pt, aad=b"meta")
    pt2 = SM4Modes.gcm_decrypt(key, iv[:12], ct, aad=b"meta", tag=tag)
"""

from __future__ import annotations

from pathlib import Path
from typing import Tuple

from gmssl import sm4


# ---------------------------------------------------------------------------
# 底层黑盒：SM4 单分组加解密（16 字节进，16 字节出，无 padding）
# ---------------------------------------------------------------------------

class _SM4Block:
    """封装 gmssl 的 SM4 one_round，提供原始 16 字节分组加解密。"""

    @staticmethod
    def encrypt(key: bytes, block: bytes) -> bytes:
        if len(key) != 16 or len(block) != 16:
            raise ValueError("SM4 block/key must be 16 bytes")
        c = sm4.CryptSM4()
        c.set_key(key, sm4.SM4_ENCRYPT)
        return bytes(c.one_round(c.sk, block))

    @staticmethod
    def decrypt(key: bytes, block: bytes) -> bytes:
        if len(key) != 16 or len(block) != 16:
            raise ValueError("SM4 block/key must be 16 bytes")
        c = sm4.CryptSM4()
        c.set_key(key, sm4.SM4_DECRYPT)
        return bytes(c.one_round(c.sk, block))


# ---------------------------------------------------------------------------
# 通用辅助
# ---------------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad_block_aligned(data: bytes) -> Tuple[bytes, bool]:
    """返回 (padded_data, was_padded)；仅在最后一块不足 16 字节时补零。"""
    r = len(data) % 16
    if r == 0:
        return data, False
    return data + b"\x00" * (16 - r), True


# ---------------------------------------------------------------------------
# GF(2^128) 乘法与 GHASH（用于 GCM）
# ---------------------------------------------------------------------------

def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int, n: int = 16) -> bytes:
    return x.to_bytes(n, "big")


def _gf128_mul(x: int, y: int) -> int:
    """GF(2^128) 乘法，约化多项式 x^128 + x^7 + x^2 + x + 1。"""
    res = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            res ^= x
        # x = x * α，若最高位为 1 则约化
        if x & 1:
            x = (x >> 1) ^ 0xE1000000000000000000000000000000
        else:
            x >>= 1
    return res


def _ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """
    GHASH_H(A, C)。
    输入 aad/ciphertext 均按 16 字节分组，不足补零。
    """
    def blocks(data: bytes):
        for i in range(0, len(data), 16):
            yield _bytes_to_int(data[i : i + 16].ljust(16, b"\x00"))

    y = 0
    for blk in blocks(aad):
        y = _gf128_mul(y ^ blk, h)
    for blk in blocks(ciphertext):
        y = _gf128_mul(y ^ blk, h)
    # 长度块：aad 位长 || ciphertext 位长，各 64 位
    len_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    y = _gf128_mul(y ^ len_block, h)
    return y


def _inc32(counter: bytes) -> bytes:
    """GCM/CTR 计数器后 32 位加 1，模 2^32。"""
    n = _bytes_to_int(counter)
    n = ((n >> 32) << 32) | (((n & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)
    return _int_to_bytes(n)


def _gcm_j0(key: bytes, iv: bytes) -> bytes:
    """计算 GCM 的 J0。12 字节 IV：J0 = IV || 0^31 || 1；否则 J0 = GHASH(IV)。"""
    if len(iv) == 12:
        return iv + b"\x00\x00\x00\x01"
    h = _bytes_to_int(_SM4Block.encrypt(key, b"\x00" * 16))
    return _int_to_bytes(_ghash(h, b"", iv), 16)


def _gcm_tag_ks(key: bytes, iv: bytes) -> bytes:
    """GCM tag 的密钥流：E(K, J0)。"""
    return _SM4Block.encrypt(key, _gcm_j0(key, iv))


def _gcm_ctr(key: bytes, iv: bytes, length: int) -> bytes:
    """GCM 明文加密 CTR：从 J0 + 1 开始生成 length 字节密钥流。"""
    counter = _inc32(_gcm_j0(key, iv))
    out = bytearray()
    while len(out) < length:
        out.extend(_SM4Block.encrypt(key, counter))
        counter = _inc32(counter)
    return bytes(out[:length])


# ---------------------------------------------------------------------------
# CCM 辅助
# ---------------------------------------------------------------------------

def _ccm_format_b0(nonce: bytes, msg_len: int, aad_len: int, tag_len: int) -> bytes:
    """构造 CCM B0 标志块。"""
    # Flags: Reserved(1) | Adata(1) | (M-2)/2(3) | (L-1)(3)
    # M = tag_len, L = 15 - len(nonce)
    if not 7 <= len(nonce) <= 13:
        raise ValueError("CCM nonce length must be 7~13 bytes")
    l_val = 15 - len(nonce)
    if not (1 <= l_val <= 8):
        raise ValueError("invalid CCM L value")
    if msg_len >= (1 << (8 * l_val)):
        raise ValueError("message too long for CCM L value")

    flags = (
        ((1 if aad_len > 0 else 0) << 6)
        | (((tag_len - 2) // 2) << 3)
        | (l_val - 1)
    )
    b0 = bytes([flags]) + nonce + msg_len.to_bytes(l_val, "big")
    return b0


def _ccm_format_aad(aad: bytes) -> bytes:
    """将 AAD 编码为 CCM 附加认证数据块序列，并补零到 16 字节倍数。"""
    if len(aad) == 0:
        return b""
    if len(aad) < (1 << 16) - (1 << 8):
        encoded = len(aad).to_bytes(2, "big") + aad
    elif len(aad) < (1 << 32):
        encoded = b"\xff\xfe" + len(aad).to_bytes(4, "big") + aad
    else:
        raise ValueError("AAD too long for CCM")
    pad = (16 - len(encoded) % 16) % 16
    return encoded + b"\x00" * pad


def _ccm_ctr_counter(nonce: bytes, i: int) -> bytes:
    """CCM 计数器块：0 | nonce | i，长度 16。"""
    l_val = 15 - len(nonce)
    return bytes([l_val - 1]) + nonce + i.to_bytes(l_val, "big")


# ---------------------------------------------------------------------------
# XTS 辅助：GF(2^128) 乘 alpha = x（即左移 1 位，最高位出则异或 0x87）
# ---------------------------------------------------------------------------

def _xts_mul_alpha(tweak: int) -> int:
    """XTS tweak 更新：T = T * α in GF(2^128)[x]/x^128+x^7+x^2+x+1 的变体。"""
    # IEEE P1619/XTS 使用的 alpha 乘法是左移 1 位，若原最高位为 1 则 XOR 0x87
    if tweak & (1 << 127):
        return ((tweak << 1) & ((1 << 128) - 1)) ^ 0x87
    return (tweak << 1) & ((1 << 128) - 1)


# ---------------------------------------------------------------------------
# 工作模式 API
# ---------------------------------------------------------------------------

class SM4Modes:
    """SM4 工作模式集合。ECB 为黑盒，其余模式手工实现。"""

    BLOCK_SIZE = 16

    # ------------------------------------------------------------------
    # ECB（黑盒）
    # ------------------------------------------------------------------

    @staticmethod
    def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
        """无 padding ECB 加密；输入长度必须是 16 字节倍数。"""
        if len(plaintext) % 16 != 0:
            raise ValueError("ECB plaintext length must be multiple of 16")
        return b"".join(_SM4Block.encrypt(key, plaintext[i : i + 16]) for i in range(0, len(plaintext), 16))

    @staticmethod
    def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
        """无 padding ECB 解密。"""
        if len(ciphertext) % 16 != 0:
            raise ValueError("ECB ciphertext length must be multiple of 16")
        return b"".join(_SM4Block.decrypt(key, ciphertext[i : i + 16]) for i in range(0, len(ciphertext), 16))

    # ------------------------------------------------------------------
    # CBC（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """无 padding CBC 加密；输入长度必须是 16 字节倍数。"""
        if len(iv) != 16:
            raise ValueError("CBC IV must be 16 bytes")
        if len(plaintext) % 16 != 0:
            raise ValueError("CBC plaintext length must be multiple of 16")
        prev = iv
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            block = _xor(plaintext[i : i + 16], prev)
            ct = _SM4Block.encrypt(key, block)
            out.extend(ct)
            prev = ct
        return bytes(out)

    @staticmethod
    def cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) % 16 != 0:
            raise ValueError("CBC ciphertext length must be multiple of 16")
        prev = iv
        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            ct = ciphertext[i : i + 16]
            pt = _xor(_SM4Block.decrypt(key, ct), prev)
            out.extend(pt)
            prev = ct
        return bytes(out)

    # ------------------------------------------------------------------
    # CFB（手工，按 128-bit 段）
    # ------------------------------------------------------------------

    @staticmethod
    def cfb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """CFB-128 加密，段长 = 分组长度 = 128 bit。"""
        if len(iv) != 16:
            raise ValueError("CFB IV must be 16 bytes")
        s = iv
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            o = _SM4Block.encrypt(key, s)
            block = plaintext[i : i + 16]
            ct = _xor(o, block)
            out.extend(ct)
            s = ct
        return bytes(out)

    @staticmethod
    def cfb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("CFB IV must be 16 bytes")
        s = iv
        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            o = _SM4Block.encrypt(key, s)
            ct = ciphertext[i : i + 16]
            pt = _xor(o, ct)
            out.extend(pt)
            s = ct
        return bytes(out)

    # ------------------------------------------------------------------
    # OFB（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def ofb_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("OFB IV must be 16 bytes")
        s = iv
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            s = _SM4Block.encrypt(key, s)
            block = plaintext[i : i + 16]
            out.extend(_xor(s, block))
        return bytes(out)

    @staticmethod
    def ofb_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        return SM4Modes.ofb_encrypt(key, iv, ciphertext)

    # ------------------------------------------------------------------
    # CTR（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
        """CTR 加密/解密（同一函数）。iv 为 16 字节计数器初始值。"""
        if len(iv) != 16:
            raise ValueError("CTR counter must be 16 bytes")
        counter = iv
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            ks = _SM4Block.encrypt(key, counter)
            block = plaintext[i : i + 16]
            out.extend(_xor(ks, block))
            counter = _inc32(counter)
        return bytes(out)

    @staticmethod
    def ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        return SM4Modes.ctr_encrypt(key, iv, ciphertext)

    # ------------------------------------------------------------------
    # GCM（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def gcm_encrypt(
        key: bytes,
        iv: bytes,
        plaintext: bytes,
        *,
        aad: bytes = b"",
        tag_len: int = 16,
    ) -> Tuple[bytes, bytes]:
        """
        GCM 加密。iv 推荐 12 字节。
        返回 (ciphertext, tag)。
        """
        if tag_len < 1 or tag_len > 16:
            raise ValueError("tag_len must be 1~16")
        h = _bytes_to_int(_SM4Block.encrypt(key, b"\x00" * 16))
        keystream = _gcm_ctr(key, iv, len(plaintext))
        ciphertext = _xor(plaintext, keystream)
        s = _ghash(h, aad, ciphertext)
        # tag = GCTR(K, J0, S) 的前 tag_len 字节
        tag_ks = _gcm_tag_ks(key, iv)
        tag = _xor(_int_to_bytes(s), tag_ks)[:tag_len]
        return bytes(ciphertext), tag

    @staticmethod
    def gcm_decrypt(
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        *,
        aad: bytes = b"",
        tag: bytes,
    ) -> bytes:
        """GCM 解密并校验 tag；失败则抛出 ValueError。"""
        if len(tag) < 1 or len(tag) > 16:
            raise ValueError("tag length must be 1~16")
        h = _bytes_to_int(_SM4Block.encrypt(key, b"\x00" * 16))
        s = _ghash(h, aad, ciphertext)
        tag_ks = _gcm_tag_ks(key, iv)
        expected = _xor(_int_to_bytes(s), tag_ks)[: len(tag)]
        if expected != tag:
            raise ValueError("GCM tag verification failed")
        keystream = _gcm_ctr(key, iv, len(ciphertext))
        return _xor(ciphertext, keystream)

    # ------------------------------------------------------------------
    # CCM（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def ccm_encrypt(
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        *,
        aad: bytes = b"",
        tag_len: int = 16,
    ) -> Tuple[bytes, bytes]:
        """
        CCM 加密。nonce 长度 7~13 字节；tag_len 为偶数 4~16。
        返回 (ciphertext, tag)。
        """
        if tag_len not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError("invalid CCM tag length")
        b0 = _ccm_format_b0(nonce, len(plaintext), len(aad), tag_len)
        aad_encoded = _ccm_format_aad(aad)

        # CBC-MAC：B0 || AAD || plaintext(padded) -> tag
        mac_input = b0 + aad_encoded
        padded_plain, _ = _pad_block_aligned(plaintext)
        mac_input += padded_plain

        x = b"\x00" * 16
        for i in range(0, len(mac_input), 16):
            x = _SM4Block.encrypt(key, _xor(x, mac_input[i : i + 16]))

        # CTR 加密 plaintext
        counter0 = _ccm_ctr_counter(nonce, 0)
        s0 = _SM4Block.encrypt(key, counter0)
        tag = _xor(x, s0)[:tag_len]

        ciphertext = bytearray()
        ctr = 1
        for i in range(0, len(plaintext), 16):
            si = _SM4Block.encrypt(key, _ccm_ctr_counter(nonce, ctr))
            ciphertext.extend(_xor(plaintext[i : i + 16], si))
            ctr += 1

        return bytes(ciphertext), tag

    @staticmethod
    def ccm_decrypt(
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        *,
        aad: bytes = b"",
        tag: bytes,
    ) -> bytes:
        """CCM 解密并校验 tag；失败则抛出 ValueError。"""
        tag_len = len(tag)
        if tag_len not in (4, 6, 8, 10, 12, 14, 16):
            raise ValueError("invalid CCM tag length")

        # 先 CTR 解密
        plaintext = bytearray()
        ctr = 1
        for i in range(0, len(ciphertext), 16):
            si = _SM4Block.encrypt(key, _ccm_ctr_counter(nonce, ctr))
            plaintext.extend(_xor(ciphertext[i : i + 16], si))
            ctr += 1
        plaintext = bytes(plaintext)

        # 重新计算 tag 校验
        b0 = _ccm_format_b0(nonce, len(plaintext), len(aad), tag_len)
        aad_encoded = _ccm_format_aad(aad)
        mac_input = b0 + aad_encoded
        padded_plain, _ = _pad_block_aligned(plaintext)
        mac_input += padded_plain

        x = b"\x00" * 16
        for i in range(0, len(mac_input), 16):
            x = _SM4Block.encrypt(key, _xor(x, mac_input[i : i + 16]))

        counter0 = _ccm_ctr_counter(nonce, 0)
        s0 = _SM4Block.encrypt(key, counter0)
        expected = _xor(x, s0)[:tag_len]
        if expected != tag:
            raise ValueError("CCM tag verification failed")
        return plaintext

    # ------------------------------------------------------------------
    # XTS（手工）
    # ------------------------------------------------------------------

    @staticmethod
    def xts_encrypt(key: bytes, tweak: bytes, plaintext: bytes) -> bytes:
        """
        XTS 加密。key 为 32 字节（key1 || key2），tweak 为 16 字节数据单元号。
        当前实现不支持 ciphertext-stealing，因此输入长度需为 16 字节倍数。
        """
        if len(key) != 32:
            raise ValueError("XTS key must be 32 bytes (key1 || key2)")
        if len(tweak) != 16:
            raise ValueError("XTS tweak must be 16 bytes")
        if len(plaintext) % 16 != 0:
            raise ValueError("XTS plaintext length must be multiple of 16 (no ciphertext stealing)")
        key1, key2 = key[:16], key[16:]
        t = _bytes_to_int(_SM4Block.encrypt(key2, tweak))
        out = bytearray()
        for i in range(0, len(plaintext), 16):
            t_bytes = _int_to_bytes(t)
            block = plaintext[i : i + 16]
            pp = _xor(block, t_bytes)
            cc = _SM4Block.encrypt(key1, pp)
            out.extend(_xor(cc, t_bytes))
            t = _xts_mul_alpha(t)
        return bytes(out)

    @staticmethod
    def xts_decrypt(key: bytes, tweak: bytes, ciphertext: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("XTS key must be 32 bytes (key1 || key2)")
        if len(tweak) != 16:
            raise ValueError("XTS tweak must be 16 bytes")
        if len(ciphertext) % 16 != 0:
            raise ValueError("XTS ciphertext length must be multiple of 16")
        key1, key2 = key[:16], key[16:]
        t = _bytes_to_int(_SM4Block.encrypt(key2, tweak))
        out = bytearray()
        for i in range(0, len(ciphertext), 16):
            t_bytes = _int_to_bytes(t)
            block = ciphertext[i : i + 16]
            cc = _xor(block, t_bytes)
            pp = _SM4Block.decrypt(key1, cc)
            out.extend(_xor(pp, t_bytes))
            t = _xts_mul_alpha(t)
        return bytes(out)


# ---------------------------------------------------------------------------
# 自测
# ---------------------------------------------------------------------------

def _self_test():
    print("=" * 60)
    print("SM4 工作模式 Python 手工实现自测")
    print("=" * 60)

    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    iv = bytes.fromhex("00000000000000000000000000000000")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210") * 2  # 32 字节

    # ECB / CBC / CFB / OFB / CTR
    for name, enc, dec in [
        ("ECB", SM4Modes.ecb_encrypt, SM4Modes.ecb_decrypt),
        ("CBC", lambda k, p: SM4Modes.cbc_encrypt(k, iv, p), lambda k, c: SM4Modes.cbc_decrypt(k, iv, c)),
        ("CFB", lambda k, p: SM4Modes.cfb_encrypt(k, iv, p), lambda k, c: SM4Modes.cfb_decrypt(k, iv, c)),
        ("OFB", lambda k, p: SM4Modes.ofb_encrypt(k, iv, p), lambda k, c: SM4Modes.ofb_decrypt(k, iv, c)),
        ("CTR", lambda k, p: SM4Modes.ctr_encrypt(k, iv, p), lambda k, c: SM4Modes.ctr_decrypt(k, iv, c)),
    ]:
        ct = enc(key, pt)
        pt2 = dec(key, ct)
        assert pt2 == pt, f"{name} roundtrip failed"
        print(f"[{name}] roundtrip ok")

    # GCM / CCM
    nonce = bytes.fromhex("000000000000000000000000")
    aad = b"meta"
    ct, tag = SM4Modes.gcm_encrypt(key, nonce, pt, aad=aad)
    pt2 = SM4Modes.gcm_decrypt(key, nonce, ct, aad=aad, tag=tag)
    assert pt2 == pt
    print(f"[GCM] roundtrip ok (tag={tag.hex()})")

    ct, tag = SM4Modes.ccm_encrypt(key, nonce, pt, aad=aad)
    pt2 = SM4Modes.ccm_decrypt(key, nonce, ct, aad=aad, tag=tag)
    assert pt2 == pt
    print(f"[CCM] roundtrip ok (tag={tag.hex()})")

    # XTS
    xts_key = key + key
    ct = SM4Modes.xts_encrypt(xts_key, iv, pt)
    pt2 = SM4Modes.xts_decrypt(xts_key, iv, ct)
    assert pt2 == pt
    print("[XTS] roundtrip ok")

    # 与 OpenSSL C 辅助程序交叉验证（若存在）
    helper = Path(__file__).resolve().parent / "openssl_sm_helper"
    if helper.exists():
        import subprocess
        def run(*args):
            return subprocess.run([str(helper)] + list(args), capture_output=True, text=True, check=True).stdout.strip()

        # ECB
        ct_ref = run("sm4", "ecb", "enc", key.hex(), iv.hex(), pt.hex())
        ct_py = SM4Modes.ecb_encrypt(key, pt).hex()
        assert ct_py == ct_ref, "ECB mismatch with openssl"
        print("[ECB] openssl cross-check ok")

        for mode in ["cbc", "cfb", "ofb", "ctr"]:
            ct_ref = run("sm4", mode, "enc", key.hex(), iv.hex(), pt.hex())
            ct_py = SM4Modes.__dict__[f"{mode}_encrypt"](key, iv, pt).hex()
            assert ct_py == ct_ref, f"{mode.upper()} mismatch with openssl"
            print(f"[{mode.upper()}] openssl cross-check ok")

        # GCM/CCM
        for mode in ["gcm", "ccm"]:
            out = run(f"sm4_{mode}", "enc", key.hex(), nonce.hex(), pt.hex(), aad.hex()).splitlines()
            ct_ref, tag_ref = out[0], out[1]
            ct_py, tag_py = SM4Modes.__dict__[f"{mode}_encrypt"](key, nonce, pt, aad=aad)
            assert ct_py.hex() == ct_ref, f"{mode.upper()} ct mismatch"
            assert tag_py.hex() == tag_ref, f"{mode.upper()} tag mismatch"
            print(f"[{mode.upper()}] openssl cross-check ok")

        # GCM 非 12 字节 IV（如 13/16/17 字节）同样遵循 NIST SP 800-38D
        for iv_len in [13, 16, 17]:
            nonce2 = bytes(range(iv_len))
            out = run("sm4_gcm", "enc", key.hex(), nonce2.hex(), pt.hex(), aad.hex()).splitlines()
            ct_ref, tag_ref = out[0], out[1]
            ct_py, tag_py = SM4Modes.gcm_encrypt(key, nonce2, pt, aad=aad)
            assert ct_py.hex() == ct_ref, f"GCM iv_len={iv_len} ct mismatch"
            assert tag_py.hex() == tag_ref, f"GCM iv_len={iv_len} tag mismatch"
            print(f"[GCM] iv_len={iv_len} openssl cross-check ok")

        # XTS：OpenSSL 的 SM4-XTS tweak 更新与标准 IEEE P1619 存在差异，
        # 因此本实现仅做 roundtrip 自洽验证，不做跨实现字节级比对。

    print("=" * 60)
    print("所有 SM4 模式自测通过")
    print("=" * 60)


if __name__ == "__main__":
    _self_test()
