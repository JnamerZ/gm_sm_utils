# -*- coding: utf-8 -*-
"""
以 gmssl Python 库为基准，验证各套件输出一致性。

运行：
    python verify_against_gmssl.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from gmssl import sm2 as gmssl_sm2
from gmssl import sm3 as gmssl_sm3
from gmssl import sm4 as gmssl_sm4
from gmssl import func

from sm4_modes import SM4Modes
from utils import (
    ASN1Utils,
    SM2SignatureFormat,
    SM2Utils,
    sm3_hash,
    sm3_padding,
)

HELPER = str(Path(__file__).resolve().parent / "openssl_sm_helper")
SAGE = "sage"


class Checker:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, name: str, cond: bool, detail: str = ""):
        if cond:
            print(f"[PASS] {name}")
            self.passed += 1
        else:
            print(f"[FAIL] {name}")
            if detail:
                print(f"       {detail}")
            self.failed += 1

    def summary(self):
        print("=" * 60)
        print(f"结果：{self.passed} 通过，{self.failed} 失败")
        print("=" * 60)
        return self.failed == 0


def gmssl_sm3_digest(data: bytes) -> bytes:
    return bytes.fromhex(gmssl_sm3.sm3_hash(func.bytes_to_list(data)))


def gmssl_sm4_ecb_one_block(key: bytes, block: bytes) -> bytes:
    c = gmssl_sm4.CryptSM4()
    c.set_key(key, gmssl_sm4.SM4_ENCRYPT)
    return bytes(c.one_round(c.sk, block))


def main() -> int:
    checker = Checker()
    msg = b"hello gmssl benchmark"

    # ------------------------------------------------------------------
    # SM3
    # ------------------------------------------------------------------
    gm_digest = gmssl_sm3_digest(msg).hex()
    checker.check("SM3: utils.py == gmssl", sm3_hash(msg) == gm_digest)

    # sm2_sage.sage SM3Hash
    # sm2_sage.sage SM3Hash
    sage_sm3 = subprocess.run([SAGE, "-c",
                               f'load("{Path(__file__).resolve().parent / "sm2_sage.sage"}"); '
                               f'print(SM2Keys.sm3_hash({msg!r}).hex())'],
                              capture_output=True, text=True, check=True).stdout.strip()
    checker.check("SM3: sm2_sage.sage == gmssl", sage_sm3 == gm_digest)

    # sm3_padding 结构：对填充后数据再次 gmssl sm3 应等于对原数据 gmssl sm3
    padded = sm3_padding(msg)
    # 注意：gmssl sm3_hash 不接受已填充数据会再填充一次，所以这里只验证 padding 长度与内容
    checker.check("SM3 padding: length multiple of 64", len(padded) % 64 == 0)
    checker.check("SM3 padding: last 8 bytes == bit length", padded[-8:] == (len(msg) * 8).to_bytes(8, "big"))

    # ------------------------------------------------------------------
    # SM4 单分组黑盒
    # ------------------------------------------------------------------
    key = bytes.fromhex("0123456789abcdeffedcba9876543210")
    block = bytes.fromhex("0123456789abcdeffedcba9876543210")

    gm_block_ct = gmssl_sm4_ecb_one_block(key, block)
    py_block_ct = SM4Modes.ecb_encrypt(key, block)
    checker.check("SM4 one block: sm4_modes.py == gmssl", py_block_ct == gm_block_ct,
                  f"py={py_block_ct.hex()} gm={gm_block_ct.hex()}")

    # helper 单分组 ECB
    helper_ct = bytes.fromhex(
        subprocess.run([HELPER, "sm4", "ecb", "enc", key.hex(), "0" * 32, block.hex()],
                       capture_output=True, text=True, check=True).stdout.strip()
    )
    checker.check("SM4 one block: helper == gmssl", helper_ct == gm_block_ct,
                  f"helper={helper_ct.hex()} gm={gm_block_ct.hex()}")

    # ------------------------------------------------------------------
    # SM4 ECB/CBC/CFB/OFB/CTR（no padding）vs gmssl one_round 手算
    # ------------------------------------------------------------------
    iv = bytes.fromhex("00000000000000000000000000000000")
    pt = bytes.fromhex("0123456789abcdeffedcba9876543210") * 2

    # ECB no-padding：逐块与 gmssl one_round 对比
    ct_ecb = SM4Modes.ecb_encrypt(key, pt)
    gm_ecb = b"".join(gmssl_sm4_ecb_one_block(key, pt[i : i + 16]) for i in range(0, len(pt), 16))
    checker.check("SM4-ECB no-padding: sm4_modes.py == gmssl", ct_ecb == gm_ecb)

    # CBC no-padding：手算与 gmssl one_round 对比
    ct_cbc = SM4Modes.cbc_encrypt(key, iv, pt)
    prev = iv
    gm_cbc = bytearray()
    for i in range(0, len(pt), 16):
        blk = bytes(x ^ y for x, y in zip(pt[i : i + 16], prev))
        ct_blk = gmssl_sm4_ecb_one_block(key, blk)
        gm_cbc.extend(ct_blk)
        prev = ct_blk
    checker.check("SM4-CBC no-padding: sm4_modes.py == gmssl", ct_cbc == bytes(gm_cbc))

    # CFB-128
    ct_cfb = SM4Modes.cfb_encrypt(key, iv, pt)
    s = iv
    gm_cfb = bytearray()
    for i in range(0, len(pt), 16):
        o = gmssl_sm4_ecb_one_block(key, s)
        ct_blk = bytes(x ^ y for x, y in zip(pt[i : i + 16], o))
        gm_cfb.extend(ct_blk)
        s = ct_blk
    checker.check("SM4-CFB: sm4_modes.py == gmssl", ct_cfb == bytes(gm_cfb))

    # OFB
    ct_ofb = SM4Modes.ofb_encrypt(key, iv, pt)
    s = iv
    gm_ofb = bytearray()
    for i in range(0, len(pt), 16):
        s = gmssl_sm4_ecb_one_block(key, s)
        gm_ofb.extend(bytes(x ^ y for x, y in zip(pt[i : i + 16], s)))
    checker.check("SM4-OFB: sm4_modes.py == gmssl", ct_ofb == bytes(gm_ofb))

    # CTR（计数器后 32 位递增）
    ct_ctr = SM4Modes.ctr_encrypt(key, iv, pt)
    counter = iv
    gm_ctr = bytearray()
    for i in range(0, len(pt), 16):
        o = gmssl_sm4_ecb_one_block(key, counter)
        gm_ctr.extend(bytes(x ^ y for x, y in zip(pt[i : i + 16], o)))
        n = int.from_bytes(counter, "big")
        n = ((n >> 32) << 32) | (((n & 0xFFFFFFFF) + 1) & 0xFFFFFFFF)
        counter = n.to_bytes(16, "big")
    checker.check("SM4-CTR: sm4_modes.py == gmssl", ct_ctr == bytes(gm_ctr))

    # ------------------------------------------------------------------
    # SM4 GCM/CCM：无法直接跟 gmssl 对比（gmssl 无 GCM/CCM 接口），
    # 但 sm4_modes.py 已与 helper（OpenSSL EVP）对齐，这里只验证 helper 可用。
    # ------------------------------------------------------------------
    nonce = bytes.fromhex("000000000000000000000000")
    aad = b"meta"
    ct_gcm, tag_gcm = SM4Modes.gcm_encrypt(key, nonce, pt, aad=aad)
    out = subprocess.run([HELPER, "sm4_gcm", "enc", key.hex(), nonce.hex(), pt.hex(), aad.hex()],
                         capture_output=True, text=True, check=True).stdout.strip().splitlines()
    checker.check("SM4-GCM: sm4_modes.py == helper(OpenSSL)", ct_gcm.hex() == out[0] and tag_gcm.hex() == out[1])

    ct_ccm, tag_ccm = SM4Modes.ccm_encrypt(key, nonce, pt, aad=aad)
    out = subprocess.run([HELPER, "sm4_ccm", "enc", key.hex(), nonce.hex(), pt.hex(), aad.hex()],
                         capture_output=True, text=True, check=True).stdout.strip().splitlines()
    checker.check("SM4-CCM: sm4_modes.py == helper(OpenSSL)", ct_ccm.hex() == out[0] and tag_ccm.hex() == out[1])

    # ------------------------------------------------------------------
    # SM2 公钥
    # ------------------------------------------------------------------
    priv_hex = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
    d_int = int(priv_hex, 16)

    # 先用临时实例计算公钥
    tmp_crypt = gmssl_sm2.CryptSM2(priv_hex, "")
    gm_pub = "04" + tmp_crypt._kg(d_int, gmssl_sm2.default_ecc_table["g"])

    # 正式实例需要带公钥才能验签
    gm_crypt = gmssl_sm2.CryptSM2(priv_hex, gm_pub[2:])

    utils_pub = SM2Utils.public_key_from_private(priv_hex)

    checker.check("SM2 public key: utils.py == gmssl", utils_pub.lower() == gm_pub.lower())

    # sm2_sage.sage 公钥
    sage_pub = subprocess.run([SAGE, "-c",
                               f'load("{Path(__file__).resolve().parent / "sm2_sage.sage"}"); '
                               f'P=SM2Params.default(); k=SM2Keys(P); '
                               f'print(k.public_key_from_private({d_int}))'],
                              capture_output=True, text=True, check=True).stdout.strip()
    checker.check("SM2 public key: sm2_sage.sage == gmssl", sage_pub.lower() == gm_pub.lower())

    # ------------------------------------------------------------------
    # SM2 签名（国密默认 ID，与 gmssl 一致）
    # ------------------------------------------------------------------
    gm_raw = gm_crypt.sign_with_sm3(msg)
    gm_r, gm_s = SM2SignatureFormat.parse_raw(gm_raw)

    # utils.py 签名
    utils_raw = SM2Utils.sign(priv_hex, gm_pub, msg, with_sm3=True)
    utils_r, utils_s = SM2SignatureFormat.parse_raw(utils_raw)

    # 注意：签名涉及随机数 k，utils 与 gmssl 每次签名不同，因此互相验证即可
    checker.check("SM2 sign: utils.py verify gmssl signature",
                  SM2Utils.verify(gm_pub, gm_raw, msg, with_sm3=True))
    checker.check("SM2 sign: gmssl verify utils.py signature",
                  gm_crypt.verify_with_sm3(utils_raw, msg))

    # sm2_sage.sage 签名与互验
    sage_sig_script = f'''
load("{Path(__file__).resolve().parent / "sm2_sage.sage"}")
P = SM2Params.default()
k = SM2Keys(P)
d = {d_int}
pub = "{gm_pub}"
msg = {msg!r}
r, s = k.sign(d, pub, msg)
print(k.raw_signature(r, s))
print("1" if k.verify(pub, {gm_r}, {gm_s}, msg) else "0")
'''
    sage_out = subprocess.run([SAGE, "-c", sage_sig_script],
                              capture_output=True, text=True, check=True).stdout.strip().splitlines()
    sage_raw = sage_out[0]
    sage_verify_gm = sage_out[1] == "1"
    checker.check("SM2 sign: sm2_sage.sage verify gmssl signature", sage_verify_gm)
    checker.check("SM2 sign: gmssl verify sm2_sage.sage signature",
                  gm_crypt.verify_with_sm3(sage_raw, msg))

    # ------------------------------------------------------------------
    # SM2 签名格式
    # ------------------------------------------------------------------
    gm_asn1 = SM2SignatureFormat.raw_to_asn1(gm_raw)
    checker.check("SM2 raw <-> asn1 roundtrip with gmssl signature",
                  SM2SignatureFormat.asn1_to_raw(gm_asn1) == gm_raw)

    # ------------------------------------------------------------------
    # ASN.1 DER：解析 gmssl 生成的签名
    # ------------------------------------------------------------------
    tree = ASN1Utils.parse_der(bytes.fromhex(gm_asn1))
    repacked = ASN1Utils.repack_der(tree)
    checker.check("ASN.1 DER: parse-repack gmssl SM2 signature", repacked == bytes.fromhex(gm_asn1))

    return 0 if checker.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
