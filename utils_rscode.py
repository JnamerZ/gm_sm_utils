# -*- coding: utf-8 -*-
"""
Reed-Solomon 编解码工具封装模块

基于 reedsolo.RSCodec，提供以下能力：
1. RS 编码：为任意字节消息生成纠错码。
2. RS 解码：自动纠错并还原原始消息。
3. 擦除解码：在已知错误位置时恢复更多错误。
4. 参数自定义：nsym、nsize、fcr、primitive polynomial、generator、c_exp。
5. 输入输出统一支持 bytes 与 hex 字符串。

依赖：
    pip install reedsolo

典型场景：
    - CTF 中通过 RS 纠错码恢复被篡改的 flag 或密钥。
    - 需要在前向纠错（FEC）场景下快速验证/还原数据。
"""

from __future__ import annotations

import warnings
from typing import List, Optional, Tuple, Union

from reedsolo import RSCodec, ReedSolomonError


HexOrBytes = Union[str, bytes, bytearray]


# ---------------------------------------------------------------------------
# 基础编码/解码辅助
# ---------------------------------------------------------------------------

def to_bytes(data: Union[HexOrBytes, bytearray]) -> bytes:
    """统一转换为 bytes：如果是 16 进制字符串则先解码；bytearray 直接转 bytes。"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, str):
        data = data.strip()
        if data.startswith("0x") or data.startswith("0X"):
            data = data[2:]
        return bytes.fromhex(data)
    raise TypeError(f"data must be str, bytes or bytearray, got {type(data)}")


def to_hex(data: HexOrBytes) -> str:
    """统一转换为 16 进制字符串（小写、不带 0x）。"""
    if isinstance(data, str):
        data = data.strip()
        if data.startswith("0x") or data.startswith("0X"):
            return data[2:].lower()
        return data.lower()
    return data.hex()


# ---------------------------------------------------------------------------
# Reed-Solomon 工具类
# ---------------------------------------------------------------------------

class RSCodeUtils:
    """Reed-Solomon 编解码工具类，封装 reedsolo.RSCodec。"""

    def __init__(
        self,
        nsym: int = 10,
        nsize: int = 255,
        fcr: int = 0,
        prim: int = 0x11D,
        generator: int = 2,
        c_exp: int = 8,
        single_gen: bool = True,
    ):
        """
        初始化 RS 编解码器。

        Args:
            nsym: 纠错符号数。可纠正最多 nsym//2 个错误，或最多 nsym 个擦除。
            nsize: 码字长度，即一个码字中包含的符号个数（含消息与纠错符号）。
                   每个符号占 c_exp 比特；当 nsize 超过 2**c_exp - 1 时，
                   reedsolo 会自动增大 c_exp，输出格式也会改变（例如不再是 1 字节/符号）。
                   常见 byte 场景建议保持 c_exp=8、nsize<=255。
            fcr: 第一个连续根（first consecutive root）。
            prim: 本原多项式（primitive polynomial），默认 0x11D。
            generator: 生成元，默认 2。
            c_exp: 每个符号所占的比特数（伽罗瓦域指数），默认 8 表示每个符号为 1 字节（GF(2^8)）。
            single_gen: 是否缓存生成多项式；多 nsize 混用时可设为 False。
        """
        if nsym < 2:
            raise ValueError("nsym must be at least 2")
        if nsym >= nsize:
            raise ValueError("nsym must be less than nsize")
        if nsize > (1 << c_exp) - 1:
            warnings.warn(
                f"nsize={nsize} exceeds 2**c_exp-1={(1 << c_exp) - 1}; "
                f"reedsolo will auto-increase c_exp, changing the output symbol size. "
                f"For byte-oriented usage, keep c_exp=8 and nsize<=255.",
                UserWarning,
                stacklevel=2,
            )
        self.nsym = nsym
        self.nsize = nsize
        self.fcr = fcr
        self.prim = prim
        self.generator = generator
        self._codec = RSCodec(
            nsym=nsym,
            nsize=nsize,
            fcr=fcr,
            prim=prim,
            generator=generator,
            c_exp=c_exp,
            single_gen=single_gen,
        )
        # reedsolo 可能在 nsize 过大时自动增大 c_exp，使用实际生效值
        self.c_exp = self._codec.c_exp

    def encode(self, data: HexOrBytes) -> bytes:
        """
        对数据进行 Reed-Solomon 编码。

        Args:
            data: 原始消息，bytes 或 hex 字符串。

        Returns:
            完整码字：原始消息 || 纠错符号。
        """
        return bytes(self._codec.encode(to_bytes(data)))

    def decode(
        self,
        data: HexOrBytes,
        *,
        erase_pos: Optional[List[int]] = None,
        only_erasures: bool = False,
    ) -> bytes:
        """
        对 RS 码字进行解码并自动纠错。

        Args:
            data: 接收到的码字（可能含错误），bytes 或 hex 字符串。
            erase_pos: 可选，已知错误位置列表。提供后可纠正更多错误。
            only_erasures: 是否仅使用擦除位置进行纠错（不未知位置错误）。

        Returns:
            纠错后的原始消息（不含 ECC 符号）。

        Raises:
            ReedSolomonError: 当错误数量超过可纠正能力时抛出。
        """
        kwargs: dict = {}
        if erase_pos is not None:
            kwargs["erase_pos"] = erase_pos
        if only_erasures:
            kwargs["only_erasures"] = True

        decoded = self._codec.decode(to_bytes(data), **kwargs)
        # reedsolo 返回 (message, full_code, err_pos)
        return bytes(decoded[0])

    def decode_with_meta(
        self,
        data: HexOrBytes,
        *,
        erase_pos: Optional[List[int]] = None,
        only_erasures: bool = False,
    ) -> Tuple[bytes, bytes, List[int]]:
        """
        解码并返回详细元信息。

        Returns:
            (message, full_codeword, error_positions)
            - message: 纠错后的原始消息。
            - full_codeword: 完整码字（消息 + 纠错符号）。
            - error_positions: 检测到并纠正的错误位置列表。
        """
        kwargs: dict = {}
        if erase_pos is not None:
            kwargs["erase_pos"] = erase_pos
        if only_erasures:
            kwargs["only_erasures"] = True

        decoded = self._codec.decode(to_bytes(data), **kwargs)
        message = bytes(decoded[0])
        full = bytes(decoded[1])
        err_pos = list(decoded[2]) if decoded[2] is not None else []
        return message, full, err_pos

    def check(self, data: HexOrBytes) -> bool:
        """
        检查码字是否可被当前 RS 参数正确解码（无需纠错即可通过，或错误在可纠范围内）。

        注意：即使返回 False，调用 decode 仍可能成功纠错；本方法等价于
        "解码不抛出异常"。
        """
        try:
            self.decode(data)
            return True
        except ReedSolomonError:
            return False

    def calc_ecc(self, data: HexOrBytes) -> bytes:
        """仅计算并返回 nsym 字节的纠错符号。"""
        encoded = self.encode(data)
        msg_len = len(to_bytes(data))
        return encoded[msg_len:]

    def max_errors(self) -> int:
        """不借助擦除位置时，最多可纠正的错误字节数。"""
        return self.nsym // 2

    def max_erasures(self) -> int:
        """全部错误位置已知时，最多可纠正的擦除字节数。"""
        return self.nsym

    def parameters(self) -> Tuple[int, int, int, int]:
        """
        返回标准 RS 码参数 [n, k, d]_q。

            n = 码字长度（nsize）
            k = 消息长度（nsize - nsym）
            d = 最小 Hamming 距离（nsym + 1）
            q = 符号字母表大小（2**c_exp）
        """
        n = self.nsize
        k = self.nsize - self.nsym
        d = self.nsym + 1
        q = 1 << self.c_exp
        return n, k, d, q

    def capacity(self) -> dict:
        """返回当前编解码器的容量信息。"""
        n, k, d, q = self.parameters()
        return {
            "nsym": self.nsym,
            "nsize": n,
            "message_len": k,
            "min_distance": d,
            "alphabet_size": q,
            "max_errors": self.max_errors(),
            "max_erasures": self.max_erasures(),
            "fcr": self.fcr,
            "prim": self.prim,
            "generator": self.generator,
            "c_exp": self.c_exp,
        }


# ---------------------------------------------------------------------------
# 便捷组合函数（适合脚本直接调用）
# ---------------------------------------------------------------------------

def rs_encode(
    data: HexOrBytes,
    nsym: int = 10,
    nsize: int = 255,
    **codec_kwargs,
) -> bytes:
    """Reed-Solomon 编码便捷函数。"""
    return RSCodeUtils(nsym=nsym, nsize=nsize, **codec_kwargs).encode(data)


def rs_decode(
    data: HexOrBytes,
    nsym: int = 10,
    nsize: int = 255,
    *,
    erase_pos: Optional[List[int]] = None,
    **codec_kwargs,
) -> bytes:
    """Reed-Solomon 解码便捷函数。"""
    return RSCodeUtils(nsym=nsym, nsize=nsize, **codec_kwargs).decode(
        data, erase_pos=erase_pos
    )


def rs_decode_with_meta(
    data: HexOrBytes,
    nsym: int = 10,
    nsize: int = 255,
    *,
    erase_pos: Optional[List[int]] = None,
    **codec_kwargs,
) -> Tuple[bytes, bytes, List[int]]:
    """Reed-Solomon 解码并返回元信息。"""
    return RSCodeUtils(nsym=nsym, nsize=nsize, **codec_kwargs).decode_with_meta(
        data, erase_pos=erase_pos
    )


def rs_fix_hex(
    corrupted_hex: str,
    nsym: int = 10,
    nsize: int = 255,
    *,
    erase_pos: Optional[List[int]] = None,
    **codec_kwargs,
) -> str:
    """
    尝试修复被篡改的 hex 字符串并返回修复后消息的 hex。

    如果超出纠错能力则抛出 ReedSolomonError。
    """
    fixed = rs_decode(corrupted_hex, nsym=nsym, nsize=nsize, erase_pos=erase_pos, **codec_kwargs)
    return fixed.hex()


# ---------------------------------------------------------------------------
# 自测示例
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Reed-Solomon 工具自测")
    print("=" * 60)

    # 0. 基础编解码
    msg = b"flag{rscode_demo}"
    rs = RSCodeUtils(nsym=10)
    encoded = rs.encode(msg)
    print(f"[RS] message len={len(msg)}, encoded len={len(encoded)}")
    assert rs.decode(encoded) == msg
    print("[RS] basic encode/decode ok")

    # 1. 自动纠错（nsym=10 可纠正 5 个随机错误）
    corrupted = bytearray(encoded)
    error_positions = [0, 3, 7, 12, len(encoded) - 1]
    for pos in error_positions:
        corrupted[pos] ^= 0xFF
    fixed = rs.decode(corrupted)
    assert fixed == msg
    print(f"[RS] corrected {len(error_positions)} errors at {error_positions}")

    # 2. 擦除解码（已知错误位置可纠正更多）
    corrupted2 = bytearray(encoded)
    erase_positions = [0, 1, 2, 3, 4, 5, 6, 7]
    for pos in erase_positions:
        corrupted2[pos] ^= 0xAA
    fixed2, full2, errs2 = rs.decode_with_meta(corrupted2, erase_pos=erase_positions)
    assert fixed2 == msg
    print(f"[RS] erasure decode corrected {len(erase_positions)} positions")

    # 3. hex 接口
    encoded_hex = rs.encode(msg).hex()
    assert RSCodeUtils(nsym=10).decode(encoded_hex) == msg
    print("[RS] hex interface ok")

    # 4. 仅计算 ECC 符号
    ecc = rs.calc_ecc(msg)
    assert len(ecc) == rs.nsym
    assert rs.encode(msg) == msg + ecc
    print("[RS] calc_ecc ok")

    # 5. 便捷函数
    enc = rs_encode(msg, nsym=10)
    dec = rs_decode(enc, nsym=10)
    assert dec == msg
    print("[RS] convenience functions ok")

    # 6. 容量信息与标准 RS 参数 [n, k, d]_q
    n, k, d, q = rs.parameters()
    assert (n, k, d, q) == (255, 245, 11, 256)
    cap = rs.capacity()
    assert cap["max_errors"] == 5
    assert cap["max_erasures"] == 10
    print(f"[RS] parameters: [{n}, {k}, {d}]_{q}")
    print(f"[RS] capacity: {cap}")

    # 7. 超出纠错能力应抛出异常
    too_many_errors = bytearray(encoded)
    for pos in range(6):  # 6 > nsym//2 = 5
        too_many_errors[pos] ^= 0xFF
    try:
        rs.decode(too_many_errors)
        assert False, "should raise ReedSolomonError"
    except ReedSolomonError:
        print("[RS] correctly raised ReedSolomonError for uncorrectable data")

    print("=" * 60)
    print("所有 RS 自测通过")
    print("=" * 60)
