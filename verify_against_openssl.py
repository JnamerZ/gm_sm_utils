# -*- coding: utf-8 -*-
"""
以系统自带 openssl CLI 为基准，对 GM/SM 工具集合做输出格式一致性验证。

运行：
    python verify_against_openssl.py

输出：
    每个检查项的 PASS/FAIL 状态；FAIL 时打印详细差异。
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Tuple

from Cryptodome.Util.asn1 import DerSequence

from sm4_modes import SM4Modes
from utils import ASN1Utils, SM2SignatureFormat, SM2Utils, sm3_hash


OPENSSL = "openssl"
HELPER = str(Path(__file__).resolve().parent / "openssl_sm_helper")


def run_openssl(*args: str, input_data: bytes = b"") -> Tuple[int, bytes, bytes]:
    r = subprocess.run([OPENSSL] + list(args), input=input_data, capture_output=True)
    return r.returncode, r.stdout, r.stderr


def run_helper(*args: str) -> Tuple[int, str, str]:
    r = subprocess.run([HELPER] + list(args), capture_output=True, text=True)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


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


def generate_sm2_key(tmpdir: Path) -> Tuple[str, str]:
    key = tmpdir / "sm2.pem"
    subprocess.run([OPENSSL, "ecparam", "-genkey", "-name", "SM2", "-out", str(key)], check=True, capture_output=True)

    out = subprocess.run([OPENSSL, "ec", "-in", str(key), "-pubout", "-text", "-noout"],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    pub_hex = "".join(lines[lines.index("pub:") + 1: lines.index("ASN1 OID: SM2")]).replace(":", "").replace(" ", "")

    out2 = subprocess.run([OPENSSL, "ec", "-in", str(key), "-noout", "-text"],
                          capture_output=True, text=True, check=True).stdout
    lines2 = out2.splitlines()
    priv_hex = "".join(lines2[lines2.index("priv:") + 1: lines2.index("pub:")]).replace(":", "").replace(" ", "").lstrip("00")
    return priv_hex, pub_hex


def main() -> int:
    checker = Checker()

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        msg = b"hello openssl benchmark"
        msg_hex = msg.hex()
        (tmpdir / "msg.bin").write_bytes(msg)

        priv_hex, pub_hex = generate_sm2_key(tmpdir)

        # 同时生成 CSR，供后续证书测试使用
        subprocess.run([OPENSSL, "req", "-new", "-key", str(tmpdir / "sm2.pem"), "-out", str(tmpdir / "sm2.csr"),
                        "-nodes", "-subj", "/CN=test", "-sm3"], check=True, capture_output=True)

        # ------------------------------------------------------------------
        # SM3
        # ------------------------------------------------------------------
        data_hex = "616263"
        ref = run_openssl("dgst", "-sm3", "-binary", input_data=bytes.fromhex(data_hex))[1].hex()
        checker.check("SM3: helper == openssl", run_helper("sm3", data_hex)[1] == ref)
        checker.check("SM3: utils.py == openssl", sm3_hash(data_hex) == ref)

        # ------------------------------------------------------------------
        # SM4 非 AEAD 模式
        # ------------------------------------------------------------------
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        iv = bytes.fromhex("00000000000000000000000000000000")
        pt = bytes.fromhex("0123456789abcdeffedcba9876543210") * 2

        for mode in ["ecb", "cbc", "cfb", "ofb", "ctr"]:
            args = [OPENSSL, "enc", f"-sm4-{mode}", "-K", key.hex(), "-iv", iv.hex(), "-nosalt", "-nopad", "-e"]
            ct_openssl = subprocess.run(args, input=pt, capture_output=True, check=True).stdout

            if mode == "ecb":
                ct_py = SM4Modes.ecb_encrypt(key, pt)
            else:
                ct_py = getattr(SM4Modes, f"{mode}_encrypt")(key, iv, pt)

            ct_helper = run_helper("sm4", mode, "enc", key.hex(), iv.hex(), pt.hex())[1]
            ct_helper_bytes = bytes.fromhex(ct_helper)

            checker.check(f"SM4-{mode.upper()}: openssl == helper", ct_openssl == ct_helper_bytes,
                          f"openssl={ct_openssl.hex()[:32]}... helper={ct_helper[:32]}...")
            checker.check(f"SM4-{mode.upper()}: openssl == sm4_modes.py", ct_openssl == ct_py,
                          f"openssl={ct_openssl.hex()[:32]}... py={ct_py.hex()[:32]}...")

        # ------------------------------------------------------------------
        # SM4 GCM/CCM：openssl enc 不支持 AAD/tag，以 helper（OpenSSL API）为基准
        # ------------------------------------------------------------------
        nonce = bytes.fromhex("000000000000000000000000")
        aad = b"meta"
        ct_gcm, tag_gcm = SM4Modes.gcm_encrypt(key, nonce, pt, aad=aad)
        out = run_helper("sm4_gcm", "enc", key.hex(), nonce.hex(), pt.hex(), aad.hex())[1].splitlines()
        checker.check("SM4-GCM: sm4_modes.py == helper",
                      ct_gcm.hex() == out[0] and tag_gcm.hex() == out[1])

        ct_ccm, tag_ccm = SM4Modes.ccm_encrypt(key, nonce, pt, aad=aad)
        out = run_helper("sm4_ccm", "enc", key.hex(), nonce.hex(), pt.hex(), aad.hex())[1].splitlines()
        checker.check("SM4-CCM: sm4_modes.py == helper",
                      ct_ccm.hex() == out[0] and tag_ccm.hex() == out[1])

        # ------------------------------------------------------------------
        # SM4 XTS：openssl enc CLI 不支持；默认 IEEE P1619 与 OpenSSL 默认 GB 不同。
        # 这里用 standard="GB" 与 helper（OpenSSL 默认）做字节级对比。
        # ------------------------------------------------------------------
        xts_key = key + key
        ct_xts_gb = SM4Modes.xts_encrypt(xts_key, iv, pt, standard="GB")
        ct_xts_helper = bytes.fromhex(run_helper("sm4", "xts", "enc", xts_key.hex(), iv.hex(), pt.hex())[1])
        checker.check("SM4-XTS (GB): sm4_modes.py == helper(OpenSSL default)",
                      ct_xts_gb == ct_xts_helper,
                      f"py={ct_xts_gb.hex()[:32]}... helper={ct_xts_helper.hex()[:32]}...")

        # ------------------------------------------------------------------
        # SM2 公钥
        # ------------------------------------------------------------------
        helper_pub = run_helper("sm2_pubkey", priv_hex)[1]
        checker.check("SM2 public key: helper == openssl", helper_pub.lower() == pub_hex.lower())

        pub_from_utils = SM2Utils.public_key_from_private(int(priv_hex, 16))
        checker.check("SM2 public key: utils.py == openssl", pub_from_utils.lower() == pub_hex.lower())

        # ------------------------------------------------------------------
        # SM2 签名：默认空 ID（与 openssl CLI 默认一致）
        # ------------------------------------------------------------------
        # helper default (empty id) sign -> openssl default verify
        helper_sig_default = run_helper("sm2_sign", priv_hex, msg_hex)[1]
        (tmpdir / "sig_helper_default.bin").write_bytes(bytes.fromhex(helper_sig_default))
        rc, _, _ = run_openssl("pkeyutl", "-verify", "-in", str(tmpdir / "msg.bin"), "-inkey", str(tmpdir / "sm2.pem"),
                               "-sigfile", str(tmpdir / "sig_helper_default.bin"), "-rawin", "-digest", "sm3")
        checker.check("SM2 sign/verify: helper(default empty id) <-> openssl CLI default", rc == 0)

        # openssl default sign -> helper default verify
        run_openssl("dgst", "-sm3", "-sign", str(tmpdir / "sm2.pem"), "-out", str(tmpdir / "sig_openssl_default.bin"),
                    str(tmpdir / "msg.bin"))
        sig_openssl_default = (tmpdir / "sig_openssl_default.bin").read_bytes().hex()
        rc, out, _ = run_helper("sm2_verify", pub_hex, sig_openssl_default, msg_hex)
        checker.check("SM2 sign/verify: openssl CLI default <-> helper(default empty id)", rc == 0 and out == "1")

        # ------------------------------------------------------------------
        # SM2 签名：国密默认 ID 1234567812345678
        # ------------------------------------------------------------------
        gm_id_hex = "1234567812345678"

        # helper gm id sign -> openssl distid verify
        helper_sig_gm = run_helper("sm2_sign", priv_hex, msg_hex, gm_id_hex)[1]
        (tmpdir / "sig_helper_gm.bin").write_bytes(bytes.fromhex(helper_sig_gm))
        rc, _, _ = run_openssl("pkeyutl", "-verify", "-in", str(tmpdir / "msg.bin"), "-inkey", str(tmpdir / "sm2.pem"),
                               "-sigfile", str(tmpdir / "sig_helper_gm.bin"), "-rawin", "-digest", "sm3",
                               "-pkeyopt", f"distid:{gm_id_hex}")
        checker.check("SM2 sign/verify: helper(gm id) <-> openssl CLI distid", rc == 0)

        # openssl distid sign -> helper gm id verify
        run_openssl("pkeyutl", "-sign", "-in", str(tmpdir / "msg.bin"), "-inkey", str(tmpdir / "sm2.pem"),
                    "-out", str(tmpdir / "sig_openssl_gm.bin"), "-rawin", "-digest", "sm3",
                    "-pkeyopt", f"distid:{gm_id_hex}")
        sig_openssl_gm = (tmpdir / "sig_openssl_gm.bin").read_bytes().hex()
        rc, out, _ = run_helper("sm2_verify", pub_hex, sig_openssl_gm, msg_hex, gm_id_hex)
        checker.check("SM2 sign/verify: openssl CLI distid <-> helper(gm id)", rc == 0 and out == "1")

        # utils.py 使用 gm id；与 openssl distid 互验
        raw_sig_utils = SM2Utils.sign(priv_hex, pub_hex, msg, with_sm3=True)
        asn1_sig_utils = SM2SignatureFormat.raw_to_asn1(raw_sig_utils)
        (tmpdir / "sig_utils.bin").write_bytes(bytes.fromhex(asn1_sig_utils))
        rc, _, _ = run_openssl("pkeyutl", "-verify", "-in", str(tmpdir / "msg.bin"), "-inkey", str(tmpdir / "sm2.pem"),
                               "-sigfile", str(tmpdir / "sig_utils.bin"), "-rawin", "-digest", "sm3",
                               "-pkeyopt", f"distid:{gm_id_hex}")
        checker.check("SM2 sign/verify: utils.py(gm id) <-> openssl CLI distid", rc == 0)

        raw_from_openssl_gm = SM2SignatureFormat.asn1_to_raw(sig_openssl_gm)
        checker.check("SM2 sign/verify: openssl CLI distid <-> utils.py(gm id)",
                      SM2Utils.verify(pub_hex, raw_from_openssl_gm, msg, with_sm3=True))

        # sm2_sage.sage 使用 gm id；与 helper 互验
        sage_script = tmpdir / "_sage_verify.sage"
        sage_script.write_text(
            f'''load("{Path(__file__).resolve().parent / "sm2_sage.sage"}")
P = SM2Params.default()
keys = SM2Keys(P)
d = {int(priv_hex, 16)}
pub = "{pub_hex}"
msg = bytes.fromhex("{msg_hex}")
r, s = keys.sign(d, pub, msg)
print("raw_sig:" + keys.raw_signature(r, s))
print("asn1_sig:" + keys.asn1_signature(r, s))
'''
        )
        r = subprocess.run(["sage", str(sage_script)], capture_output=True, text=True)
        sage_lines = r.stdout.strip().splitlines()
        sage_raw = sage_lines[0].split(":", 1)[1]
        sage_asn1 = sage_lines[1].split(":", 1)[1]
        # helper 验证 sage 签名
        rc, out, _ = run_helper("sm2_verify", pub_hex, sage_asn1, msg_hex, gm_id_hex)
        checker.check("SM2 sign/verify: sm2_sage.sage(gm id) <-> helper(gm id)", rc == 0 and out == "1")
        # utils.py 验证 sage 签名
        checker.check("SM2 sign/verify: sm2_sage.sage(gm id) <-> utils.py(gm id)",
                      SM2Utils.verify(pub_hex, sage_raw, msg, with_sm3=True))

        # ------------------------------------------------------------------
        # SM2 签名格式
        # ------------------------------------------------------------------
        r, s = SM2SignatureFormat.parse_asn1(asn1_sig_utils)
        raw_back = SM2SignatureFormat.decimal_to_raw(r, s)
        asn1_back = SM2SignatureFormat.decimal_to_asn1(r, s)
        checker.check("SM2 signature format: raw <-> asn1 roundtrip",
                      raw_back == raw_sig_utils and asn1_back == asn1_sig_utils)

        # ------------------------------------------------------------------
        # ASN.1 DER 解析/重打包：openssl 生成的 SM2 签名
        # ------------------------------------------------------------------
        tree = ASN1Utils.parse_der(bytes.fromhex(sig_openssl_default))
        repacked = ASN1Utils.repack_der(tree)
        checker.check("ASN.1 DER: parse-repack openssl SM2 signature", repacked == bytes.fromhex(sig_openssl_default))

        # ------------------------------------------------------------------
        # PEM/DER 证书转换
        # ------------------------------------------------------------------
        subprocess.run([OPENSSL, "req", "-x509", "-key", str(tmpdir / "sm2.pem"), "-in", str(tmpdir / "sm2.csr"),
                        "-out", str(tmpdir / "sm2_cert.pem"), "-days", "365", "-sm3"],
                       check=True, capture_output=True)
        cert_pem = (tmpdir / "sm2_cert.pem").read_text()
        cert_der = ASN1Utils.pem_to_der(cert_pem)
        cert_pem2 = ASN1Utils.der_to_pem(cert_der)
        checker.check("PEM/DER certificate roundtrip", cert_pem.strip() == cert_pem2.strip())

    return 0 if checker.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
