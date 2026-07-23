# GM / SM 密码学工具集

一套面向 CTF 竞赛与国密算法研究的工具集合，覆盖 SM2 签名、SM3 摘要、SM4 分组加密、ASN.1 解析修改以及自定义曲线参数实验。

## 目录

- [环境准备](#环境准备)
- [快速开始](#快速开始)
- [工具说明](#工具说明)
  - [`utils.py` — gmssl 工具封装](#utilspy--gmssl-工具封装)
  - [`sm2_sage.sage` — SageMath 自定义 SM2 曲线](#sm2_sagesage--sagemath-自定义-sm2-曲线)
  - [`openssl_sm_helper.c` — OpenSSL C 实现 SM2/3/4](#openssl_sm_helperc--openssl-c-实现-sm234)
  - [`sm4_modes.py` — Python 手工实现 SM4 全模式](#sm4_modespy--python-手工实现-sm4-全模式)
  - [`sm4_gcm_sage.sage` — SageMath 计算 SM4-GCM 标签](#sm4_gcm_sagesage--sagemath-计算-sm4-gcm-标签)
- [一致性验证](#一致性验证)
- [CTF 场景速查](#ctf-场景速查)
- [Makefile 目标](#makefile-目标)
- [常见问题](#常见问题)

---

## 环境准备

```bash
# Python 依赖
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt        # gmssl

# SageMath（可选，用于自定义曲线）
# 系统包管理器安装 sage

# OpenSSL C 辅助程序编译依赖
# Debian/Ubuntu: apt install gcc libssl-dev
# RHEL/CentOS  : yum install gcc openssl-devel
```

本仓库已包含：

| 文件 | 说明 |
|------|------|
| `utils.py` | Python 封装 gmssl，SM2 签名/验签、SM3 padding、ASN.1 解析修改、自定义打包 |
| `sm2_sage.sage` | SageMath 脚本，支持提取/修改 SM2 曲线参数与基点 |
| `openssl_sm_helper.c` | OpenSSL EVP API 的 C 辅助程序，可作为 CLI 或复制到 Exploit 中 |
| `sm4_modes.py` | Python 手工实现 SM4 全部工作模式 |
| `sm4_gcm_sage.sage` | SageMath 实现 SM4-GCM GHASH 与标签计算，调用 sm4_modes.py 加密 |
| `verify_against_openssl.py` | 以系统 `openssl` CLI 为基准的一致性验证脚本 |
| `verify_against_gmssl.py` | 以 `gmssl` Python 库为基准的一致性验证脚本 |
| `Makefile` | 一键编译与测试 |

---

## 快速开始

```bash
# 编译并运行全部测试
make clean && make test

# 仅运行以系统 openssl 为基准的一致性验证
make test-verify-openssl
```

---

## 工具说明

### `utils.py` — gmssl 工具封装

适合需要快速完成 SM2 签名、ASN.1 证书/签名解析修改、自定义数据打包的 CTF 题目。

#### 0. 基础编码与 SM3

```python
from utils import to_bytes, to_hex, sm3_hash, sm3_padding

# 统一转 bytes / hex
b = to_bytes("0x616263")      # b'abc'
h = to_hex(b"abc")            # '616263'

# 直接计算 SM3 摘要
digest = sm3_hash(b"abc")
# '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0'

# 生成 SM3 哈希之前的完整填充后输入（bytes）
# 规则：原始消息 || 0x80 || 0x00... || 64-bit 大端长度
padded = sm3_padding(b"abc")
print(padded.hex())
```

#### 1. SM2 密钥与签名

```python
from utils import SM2Utils, SM2SignatureFormat

# 生成密钥对
priv, pub = SM2Utils.generate_keypair()

# 由私钥派生公钥（支持 hex 字符串或 10 进制整数）
pub2 = SM2Utils.public_key_from_private(priv)
pub3 = SM2Utils.public_key_from_private(int(priv, 16))

# 10 进制私钥 -> 64 字符 hex
priv_hex = SM2Utils.private_key_from_int(int(priv, 16))

msg = b"flag{sm2_demo}"

# SM2withSM3 签名，输出 raw r||s（128 hex）
raw_sig = SM2Utils.sign(priv, pub, msg, with_sm3=True)

# 转成 ASN.1 DER
asn1_sig = SM2SignatureFormat.raw_to_asn1(raw_sig)

# 验签
assert SM2Utils.verify(pub, raw_sig, msg, with_sm3=True)
assert SM2Utils.verify(pub, asn1_sig, msg, with_sm3=True, asn1=True)

# 指定随机数 k（可复现签名）
k = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
raw_sig2 = SM2Utils.sign(priv, pub, msg, with_sm3=True, k=k)
```

#### 2. 十进制私钥 / (r, s) 工作流

CTF 题目经常给出十进制私钥 `d` 或签名值 `r, s`：

```python
from utils import (
    SM2Utils, SM2SignatureFormat,
    sm2_sign_decimal, sm2_verify_decimal,
)

d = 0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0
msg = b"hello"

# 方法 A：直接返回 (r, s, pub)
r, s, pub = sm2_sign_decimal(d, msg)

# 方法 B：已知公钥时直接签名
r, s = SM2Utils.sign_decimal(d, pub, msg, with_sm3=True)

# 打包成 raw / asn1
raw = SM2SignatureFormat.decimal_to_raw(r, s)
asn1 = SM2SignatureFormat.decimal_to_asn1(r, s)

# 解析签名
r2, s2 = SM2SignatureFormat.parse_raw(raw)
r3, s3 = SM2SignatureFormat.parse_asn1(asn1)

# 用十进制 (r, s) 验签
assert sm2_verify_decimal(pub, r, s, msg)
assert SM2Utils.verify_decimal(pub, r, s, msg, with_sm3=True)
```

#### 3. ASN.1 DER / PEM 通用工具

```python
from utils import ASN1Utils, parse_certificate_pem, modify_certificate_der

cert_pem = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----"""

# PEM <-> DER
der = ASN1Utils.pem_to_der(cert_pem)
pem2 = ASN1Utils.der_to_pem(der)

# DER -> TLV 树
tree = ASN1Utils.parse_der(der)

# 按路径读取节点
tree[0]["children"][0]          # 第一层第一个子节点
node = ASN1Utils.get_node(tree, [0, 0, 1])   # 指定路径

# 修改节点值后重新打包（int 会被编码为 DerInteger 的 value 部分，外层 tag 不变）
# 注意：set_node_value 会就地修改传入的 tree，返回新的 DER
new_der = ASN1Utils.set_node_value(tree, [0, 0, 1], 0x12345678)

# 自定义编码器：把 bytes 编码为 BIT STRING 的 value 部分（首字节为未使用位数 0）
# 如需再次独立修改，请重新 parse_der(der) 得到新的 tree
tree2 = ASN1Utils.parse_der(der)
new_der2 = ASN1Utils.set_node_value(
    tree2, [0, 0, 1], b"new_value",
    value_encoder=lambda x: bytes([0x00]) + x
)

# 便捷函数：PEM 证书解析 / DER 证书修改
nodes = parse_certificate_pem(cert_pem)
new_der = modify_certificate_der(der, [0, 0, 1], 0x12345678)
```

#### 4. 自定义数据打包

```python
from utils import PackageUtils

# length||data 单次打包
packed = PackageUtils.pack_with_length(b"payload")
payload, rest = PackageUtils.unpack_with_length(packed)

# length||data 多次打包/解包
packed = PackageUtils.pack_multi([b"AAA", b"BBB", b"CCC"], length_size=2)
parts = PackageUtils.unpack_multi(packed, length_size=2)

# 指定大小端
packed = PackageUtils.pack_with_length(b"x", endian="little")

# 简易 TLV
tlv = PackageUtils.tlv_encode(0x01, "deadbeef") + PackageUtils.tlv_encode(0x02, b"world")
tag, value, rest = PackageUtils.tlv_decode(tlv)
```

---

### `sm2_sage.sage` — SageMath 自定义 SM2 曲线

用于研究非标准曲线参数、修改基点、在自定义曲线上执行 SM2 签名/验签。

```sage
load("sm2_sage.sage")

# 默认国密曲线
P = SM2Params.default()
keys = SM2Keys(P)

d, pub = keys.generate_keypair()
r, s = keys.sign(d, pub, b"hello")
assert keys.verify(pub, r, s, b"hello")

# 签名格式转换
raw = keys.raw_signature(r, s)
asn1 = keys.asn1_signature(r, s)
r2, s2 = keys.parse_raw_signature(raw)
r3, s3 = keys.parse_asn1_signature(asn1)

# 由私钥派生公钥
pub2 = keys.public_key_from_private(d)
```

#### 曲线参数操作

```sage
# 从 hex 构造参数
P2 = SM2Params.from_hex(
    p_hex="FFFFFFFE...",
    a_hex="FFFFFFFE...",
    b_hex="28E9FA9E...",
    n_hex="FFFFFFFE...",
    g_hex="0432C4AE2C..."
)

# 从当前环境 gmssl 提取参数
P_gm = extract_gmssl_params()

# 克隆并修改任意字段
P3 = P.clone(a=P.a + 1)
P4 = modify_curve(P, a=P.a + 1, b=P.b ^ 0x1)

# 仅修改基点（新点必须落在曲线上且阶最好为 n）
P5 = change_base_point(P, gx_new, gy_new)

# 检查基点阶
curve = SM2Curve(P5)
ok = curve.check_order()

# 公钥坐标解析
x, y = curve.decompress_public_key(pub)
```

---

### `openssl_sm_helper.c` — OpenSSL C 实现 SM2/3/4

编译后有两个用途：

1. **命令行工具**：`./openssl_sm_helper <subcommand> ...`
2. **复制到 Exploit 中**：下面给出核心 OpenSSL EVP API 调用片段，可直接嵌入 C 程序用于题目中枚举。

```bash
make                    # 编译生成 openssl_sm_helper
./openssl_sm_helper     # 不带参数会打印用法
```

#### CLI 用法

```bash
# SM3
./openssl_sm_helper sm3 68656c6c6f

# SM4 ECB/CBC/CFB/OFB/CTR/XTS（无 padding）
./openssl_sm_helper sm4 cbc enc <key_hex> <iv_hex> <pt_hex>
./openssl_sm_helper sm4 cbc dec <key_hex> <iv_hex> <ct_hex>

# SM4 GCM / CCM
./openssl_sm_helper sm4_gcm enc <key_hex> <iv_hex> <pt_hex> [aad_hex]
# 输出两行：ciphertext\ntag
./openssl_sm_helper sm4_gcm dec <key_hex> <iv_hex> <ct_hex> [aad_hex] <tag_hex>

> 解密时 `tag_hex` 必填；若无需 AAD，需显式传入空字符串作为占位：
> `./openssl_sm_helper sm4_gcm dec <key> <iv> <ct> "" <tag>`

# SM2 公钥派生
./openssl_sm_helper sm2_pubkey <d_hex>

# SM2 签名 / 验签（SM2withSM3，DER 格式）
# 省略 sm2_id 时默认空 ID，与 OpenSSL CLI 默认行为一致
./openssl_sm_helper sm2_sign   <d_hex> <msg_hex> [sm2_id]
./openssl_sm_helper sm2_verify <pub_hex> <sig_der_hex> <msg_hex> [sm2_id]

# 使用国密推荐默认 ID
./openssl_sm_helper sm2_sign   <d_hex> <msg_hex> 1234567812345678
./openssl_sm_helper sm2_verify <pub_hex> <sig_der_hex> <msg_hex> 1234567812345678
```

> `sm2_id` 是**普通字符串**，按字节直接作为 SM2 签名中的用户标识。
> 这与 `openssl pkeyutl -pkeyopt distid:...` 语义相同；
> `utils.py` 与 `sm2_sage.sage` 的默认 ID 也是字符串 `"1234567812345678"`。
> 注意：系统 OpenSSL CLI 默认使用**空 ID**，省略 ID 时与 helper 默认一致。

#### C 代码调用样例（用于 Exploit 枚举）

以下片段可直接复制到 C 程序中，配合 `-lcrypto` 编译。

##### SM3 摘要

```c
#include <openssl/evp.h>

unsigned char digest[EVP_MAX_MD_SIZE];
unsigned int digest_len = 0;
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_DigestInit_ex(ctx, EVP_sm3(), NULL);
EVP_DigestUpdate(ctx, msg, msg_len);
EVP_DigestFinal_ex(ctx, digest, &digest_len);
EVP_MD_CTX_free(ctx);
// digest[0..digest_len-1] 即为 SM3 摘要
```

##### SM4 无 padding 模式枚举

```c
#include <openssl/evp.h>

const char *modes[] = {"SM4-ECB", "SM4-CBC", "SM4-CFB", "SM4-OFB", "SM4-CTR"};
for (int i = 0; i < 5; i++) {
    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, modes[i], NULL);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex2(ctx, cipher, key, iv, 1 /*enc*/, NULL);
    if (strstr(modes[i], "ECB") || strstr(modes[i], "CBC"))
        EVP_CIPHER_CTX_set_padding(ctx, 0);

    int block_size = EVP_CIPHER_block_size(cipher);
    unsigned char *out = malloc(in_len + block_size);
    int out_len1 = 0, out_len2 = 0;
    EVP_CipherUpdate(ctx, out, &out_len1, in, in_len);
    EVP_CipherFinal_ex(ctx, out + out_len1, &out_len2);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    // out[0..out_len1+out_len2-1] 即为密文
    free(out);
}
```

##### SM4 GCM（带 AAD/Tag）

```c
#include <openssl/evp.h>

const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "SM4-GCM", NULL);
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, 1, NULL);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);
EVP_CipherInit_ex2(ctx, NULL, key, iv, 1, NULL);

int len = 0;
EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len);   // AAD

unsigned char ct[256], tag[16];
int out_len1 = 0, out_len2 = 0;
EVP_CipherUpdate(ctx, ct, &out_len1, pt, pt_len);
EVP_CipherFinal_ex(ctx, ct + out_len1, &out_len2);
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
EVP_CIPHER_CTX_free(ctx);
EVP_CIPHER_free((EVP_CIPHER *)cipher);
```

##### SM2 公钥派生

```c
#include <openssl/ec.h>
#include <openssl/bn.h>

EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
BIGNUM *d = BN_bin2bn(d_bytes, d_len, NULL);
EC_POINT *pub = EC_POINT_new(group);
EC_POINT_mul(group, pub, d, NULL, NULL, NULL);

unsigned char x[32], y[32];
BIGNUM *bx = BN_new(), *by = BN_new();
EC_POINT_get_affine_coordinates(group, pub, bx, by, NULL);
BN_bn2binpad(bx, x, 32);
BN_bn2binpad(by, y, 32);
// 公钥为 04 || x || y
// 实际使用时需释放 group/d/pub/bx/by 等资源
```

##### SM2 从私钥构造 EVP_PKEY（签名用）

```c
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

// d_bytes: 32 字节私钥；pub_bytes: 65 字节未压缩公钥 04||x||y
EVP_PKEY_CTX *kg = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
if (!kg) { return -1; }
if (EVP_PKEY_keygen_init(kg) <= 0 ||
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kg, NID_sm2) <= 0) {
    EVP_PKEY_CTX_free(kg); return -1;
}
EVP_PKEY *pkey = NULL;
if (EVP_PKEY_keygen(kg, &pkey) <= 0) {
    EVP_PKEY_CTX_free(kg); return -1;
}
EVP_PKEY_CTX_free(kg);

EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
if (!ec) { EVP_PKEY_free(pkey); return -1; }
BIGNUM *d = BN_bin2bn(d_bytes, 32, NULL);
if (!d || !EC_KEY_set_private_key(ec, d)) {
    BN_free(d); EC_KEY_free(ec); EVP_PKEY_free(pkey); return -1;
}
BN_free(d);

EC_POINT *pub = EC_POINT_new(EC_KEY_get0_group(ec));
if (!pub || !EC_POINT_mul(EC_KEY_get0_group(ec), pub,
                          EC_KEY_get0_private_key(ec), NULL, NULL, NULL) ||
    !EC_KEY_set_public_key(ec, pub)) {
    EC_POINT_free(pub); EC_KEY_free(ec); EVP_PKEY_free(pkey); return -1;
}
EC_POINT_free(pub);

if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) {
    EC_KEY_free(ec); EVP_PKEY_free(pkey); return -1;
}
EC_KEY_free(ec);
// 现在 pkey 可用于 SM2 签名/验签
```

##### SM2 签名（可指定 ID，适合题目枚举）

```c
#include <openssl/evp.h>

EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_PKEY_CTX *pctx = NULL;
EVP_DigestSignInit(ctx, &pctx, EVP_sm3(), NULL, pkey);

// 空 ID（openssl CLI 默认）；或传入 "1234567812345678" 使用国密默认 ID
const char *sm2_id = "";
EVP_PKEY_CTX_set1_id(pctx, sm2_id, strlen(sm2_id));

size_t sig_len = 0;
EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len);
unsigned char *sig = malloc(sig_len);
EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len);
EVP_MD_CTX_free(ctx);
// sig[0..sig_len-1] 为 DER 格式签名；用完后 free(sig)
free(sig);
```

##### SM2 验签

```c
EVP_MD_CTX *ctx = EVP_MD_CTX_new();
EVP_PKEY_CTX *pctx = NULL;
EVP_DigestVerifyInit(ctx, &pctx, EVP_sm3(), NULL, pkey);
EVP_PKEY_CTX_set1_id(pctx, sm2_id, strlen(sm2_id));
int ret = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
EVP_MD_CTX_free(ctx);
EVP_PKEY_free(pkey);
// ret == 1 表示验证成功
```

---

### `sm4_modes.py` — Python 手工实现 SM4 全模式

**设计**：ECB 直接调用 gmssl 单分组接口作为黑盒，其余模式全部用 Python 手写，方便在 CTF 中魔改或分析中间状态。
XTS 默认严格遵循 IEEE P1619，同时提供 `standard="GB"` 选项以匹配 OpenSSL 默认的 GB/T 17964-2021 实现；`openssl enc` CLI 不支持 XTS。

```python
from sm4_modes import SM4Modes

key = bytes.fromhex("0123456789abcdeffedcba9876543210")
iv  = bytes.fromhex("00000000000000000000000000000000")
pt  = b"flag{sm4_demo_12}" + b"x" * (32 - len(b"flag{sm4_demo_12}"))  # 补齐到 32 字节

# ECB（黑盒，无 padding）
ct = SM4Modes.ecb_encrypt(key, pt)
pt2 = SM4Modes.ecb_decrypt(key, ct)

# CBC
ct = SM4Modes.cbc_encrypt(key, iv, pt)
pt2 = SM4Modes.cbc_decrypt(key, iv, ct)

# CFB-128
ct = SM4Modes.cfb_encrypt(key, iv, pt)
pt2 = SM4Modes.cfb_decrypt(key, iv, ct)

# OFB
ct = SM4Modes.ofb_encrypt(key, iv, pt)
pt2 = SM4Modes.ofb_decrypt(key, iv, ct)

# CTR（iv 为 16 字节计数器初值）
ct = SM4Modes.ctr_encrypt(key, iv, pt)
pt2 = SM4Modes.ctr_decrypt(key, iv, ct)

# GCM（iv 推荐 12 字节 nonce）
ct, tag = SM4Modes.gcm_encrypt(key, iv[:12], pt, aad=b"meta")
pt2 = SM4Modes.gcm_decrypt(key, iv[:12], ct, aad=b"meta", tag=tag)

# CCM（nonce 长度 7~13 字节）
ct, tag = SM4Modes.ccm_encrypt(key, iv[:12], pt, aad=b"meta")
pt2 = SM4Modes.ccm_decrypt(key, iv[:12], ct, aad=b"meta", tag=tag)

# XTS（key 为 32 字节：key1 || key2；tweak 为 16 字节数据单元号）
# 默认遵循 IEEE P1619
xts_key = key + key
ct = SM4Modes.xts_encrypt(xts_key, iv, pt)
pt2 = SM4Modes.xts_decrypt(xts_key, iv, ct)

# 若题目数据来自 OpenSSL 默认的 SM4-XTS，使用 GB/T 17964-2021 标准
ct_gb = SM4Modes.xts_encrypt_gb(xts_key, iv, pt)
pt2_gb = SM4Modes.xts_decrypt_gb(xts_key, iv, ct_gb)
```

> 注意：`XTS` 默认遵循 IEEE P1619。OpenSSL 的 `SM4-XTS` 默认采用 GB/T 17964-2021，两者 tweak 更新方向不同；本模块通过 `standard="GB"` 或 `xts_encrypt_gb` / `xts_decrypt_gb` 提供 GB 标准实现，可与 OpenSSL EVP API 字节级对齐。`openssl enc` CLI 不支持 XTS，故不通过 CLI 直接验证。

---

### `sm4_gcm_sage.sage` — SageMath 计算 SM4-GCM 标签

用于在 SageMath 环境中验证/调试 GCM 的 GHASH 与认证标签计算。
SM4 分组加密调用 `sm4_modes.py` 的黑盒接口，GHASH 使用 SageMath 的 `GF(2^128)` 实现。

```sage
load("sm4_gcm_sage.sage")

key = bytes.fromhex("0123456789abcdeffedcba9876543210")
iv  = bytes.fromhex("000000000000000000000000")
ct  = bytes.fromhex("...")     # 已知的密文
aad = b"meta"

# 只计算 tag
tag = sm4_gcm_tag(key, iv, ct, aad=aad)
print(tag.hex())

# 完整 GCM 加密（SageMath 做 GHASH，Python 黑盒做 CTR）
pt = bytes.fromhex("0123456789abcdeffedcba9876543210") * 2
ct2, tag2 = sm4_gcm_sage_encrypt(key, iv, pt, aad=aad)
```

> 注意：GHASH 的 128 位块位序与 SageMath 默认整数位序相反，脚本内部已做 bit-reverse 转换。

---

## 一致性验证

仓库提供两个独立的验证脚本，分别与系统 `openssl` CLI 和 `gmssl` Python 库做输出对比。

```bash
# 与系统 openssl CLI 对比
make test-verify-openssl

# 与 gmssl Python 库对比
make test-verify-gmssl
```

### 与 `openssl` CLI 对比结果

`verify_against_openssl.py` 覆盖：

- SM3 摘要
- SM4 ECB/CBC/CFB/OFB/CTR（与 `openssl enc` 字节级一致）
- SM4 GCM/CCM（与 helper / OpenSSL EVP API 一致）
- SM2 公钥派生
- SM2 签名/验签（默认空 ID 与国密 ID 两种模式）
- ASN.1 DER 签名解析与重打包
- PEM/DER 证书转换

### 与 `gmssl` 库对比结果

`verify_against_gmssl.py` 覆盖：

- SM3 摘要（`utils.py`、`sm2_sage.sage`）
- SM3 padding 结构
- SM4 单分组加密（与 `gmssl.sm4.one_round` 一致）
- SM4 ECB/CBC/CFB/OFB/CTR no-padding（手算与 `gmssl.sm4.one_round` 一致）
- SM4 GCM/CCM（与 helper / OpenSSL EVP API 一致）
- SM2 公钥派生
- SM2 签名互验（国密默认 ID）
- ASN.1 DER 签名解析与重打包

> 注意：`sm4_modes.py` 的 XTS 默认遵循 IEEE P1619，同时提供 `standard="GB"` 以匹配 OpenSSL 默认的 GB/T 17964-2021 实现；GCM/CCM 因 `openssl enc` CLI 不支持 AAD/tag 而无法直接通过 CLI 验证，XTS 因 `openssl enc` CLI 不支持而无法直接通过 CLI 验证。

---

## CTF 场景速查

### 场景 1：题目给了十进制 SM2 私钥 `d` 和消息 `m`，要求生成签名

```python
from utils import sm2_sign_decimal, SM2SignatureFormat

r, s, pub = sm2_sign_decimal(d, m)
sig_hex = SM2SignatureFormat.decimal_to_raw(r, s)   # 或 decimal_to_asn1
print(pub, sig_hex)
```

### 场景 2：题目给了 ASN.1 DER 签名，需要提取 r、s 并修改

```python
from utils import SM2SignatureFormat

r, s = SM2SignatureFormat.parse_asn1(der_sig_hex)
# 修改 r 或 s
new_asn1 = SM2SignatureFormat.decimal_to_asn1(r + 1, s)
```

### 场景 3：证书里某个字段被改了，需要重新打包

```python
from utils import ASN1Utils

tree = ASN1Utils.parse_der(cert_der)
new_der = ASN1Utils.set_node_value(tree, [0, 2, 0], b"new_value")
```

### 场景 4：自定义曲线参数或基点的 SM2 题目

```sage
load("sm2_sage.sage")
P = SM2Params.default()
P_custom = modify_curve(P, a=P.a ^ 0x1)
keys = SM2Keys(P_custom)
```

### 场景 5：SM4 加密逻辑被魔改，需要复现

`sm4_modes.py` 中的每个模式都是纯 Python，可直接打断点、打印中间状态，或修改模式逻辑（如改变 IV 链、计数器更新方式）。

### 场景 6：只给了 SM4 密文和密钥，不确定模式

```bash
# 用 OpenSSL 快速枚举常见模式
for mode in ecb cbc cfb ofb ctr; do
  ./openssl_sm_helper sm4 $mode dec <key> <iv> <ct>
done
```

### 场景 7：C 程序中枚举 SM4 模式或 SM2 ID

直接把 [openssl_sm_helper.c 调用样例](#c-代码调用样例用于-exploit-枚举) 中的循环复制到 Exploit 里，例如：

```c
const char *sm2_ids[] = {"", "1234567812345678", "user@example.com"};
for (int i = 0; i < 3; i++) {
    EVP_DigestVerifyInit(ctx, &pctx, EVP_sm3(), NULL, pkey);
    EVP_PKEY_CTX_set1_id(pctx, sm2_ids[i], strlen(sm2_ids[i]));
    if (EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) == 1) {
        printf("matched id: %s\n", sm2_ids[i]);
        break;
    }
}
```

---

## Makefile 目标

```bash
make                      # 编译 openssl_sm_helper
make test                 # 运行全部自测
make test-utils           # utils.py 自测
make test-sage            # sm2_sage.sage 自测
make test-openssl         # OpenSSL C 辅助程序自测
make test-sm4-modes       # sm4_modes.py 自测
make test-sm4-gcm-sage    # sm4_gcm_sage.sage 自测
make test-verify-openssl  # 以系统 openssl CLI 为基准做一致性验证
make test-verify-gmssl    # 以 gmssl Python 库为基准做一致性验证
make clean                # 清理编译产物
make help                 # 查看目标说明
```

---

## 常见问题

**Q: 为什么 `openssl_sm_helper.c` 用到了 deprecated 的 EC API？**  
A: 为了代码简洁，直接用 `EC_KEY_*` 派生公钥与设置私钥。编译时通过 `-Wno-deprecated-declarations` 抑制警告，功能在 OpenSSL 3.x 下正常。

**Q: `sm4_modes.py` 的 XTS 与 OpenSSL 是否一致？**  
A: `sm4_modes.xts_encrypt` 默认遵循 IEEE P1619；同时提供 `standard="GB"`（或 `xts_encrypt_gb` / `xts_decrypt_gb`）以匹配 OpenSSL 默认采用的 GB/T 17964-2021。`openssl enc` CLI 不支持 XTS，因此不通过 CLI 直接验证。

**Q: `openssl_sm_helper` 的 SM2 签名为什么和 `openssl dgst -sm3 -sign` 默认结果不同？**  
A: SM2 签名依赖一个“用户标识 ID”。系统 OpenSSL CLI 默认使用**空 ID**；helper 默认也使用空 ID，因此二者可直接互验。而 `utils.py`、`sm2_sage.sage`、gmssl 默认使用国密推荐 ID 字符串 `"1234567812345678"`。helper 可通过第 4 个参数指定该 ID，与它们互验。

**Q: 为什么不能用 `openssl enc -sm4-gcm` 直接验证 `sm4_modes.py` 的 GCM/CCM/XTS？**  
A: `openssl enc` 命令不支持 AEAD 模式的 AAD/tag 选项，也不支持 XTS。GCM/CCM 可与 helper（OpenSSL EVP API）做字节级一致性验证；XTS 默认遵循 IEEE P1619，也可通过 `standard="GB"` 匹配 OpenSSL 默认的 GB/T 17964-2021。非 AEAD 模式（ECB/CBC/CFB/OFB/CTR）可直接与 `openssl enc` CLI 字节级对齐。

**Q: gmssl 的 `CryptSM4.crypt_ecb` 会 padding，怎么得到原始 16 字节分组？**  
A: `sm4_modes.py` 使用 `CryptSM4.one_round` 直接做单轮加解密，绕过 padding。

**Q: 这些工具能在 Windows 上跑吗？**  
A: Python 脚本可直接跑；`openssl_sm_helper.c` 需要 MSVC/MinGW 与 OpenSSL 开发库；SageMath 脚本需要 Windows 版 SageMath。
