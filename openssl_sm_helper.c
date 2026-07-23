/*
 * OpenSSL SM2/SM3/SM4 命令行辅助程序
 *
 * 用法：
 *   ./openssl_sm_helper sm3 <hex>
 *
 *   ./openssl_sm_helper sm4 <mode> <enc|dec> <key_hex> <iv_hex> <in_hex>
 *        mode: ecb/cbc/cfb/ofb/ctr/xts
 *
 *   ./openssl_sm_helper sm4_gcm enc <key_hex> <iv_hex> <pt_hex> [aad_hex]
 *   ./openssl_sm_helper sm4_gcm dec <key_hex> <iv_hex> <ct_hex> [aad_hex] <tag_hex>
 *   ./openssl_sm_helper sm4_ccm enc <key_hex> <iv_hex> <pt_hex> [aad_hex]
 *   ./openssl_sm_helper sm4_ccm dec <key_hex> <iv_hex> <ct_hex> [aad_hex] <tag_hex>
 *
 *   ./openssl_sm_helper sm2_pubkey <d_hex>
 *   ./openssl_sm_helper sm2_sign <d_hex> <msg_hex> [sm2_id]
 *   ./openssl_sm_helper sm2_verify <pub_hex> <sig_hex> <msg_hex> [sm2_id]
 *
 *   sm2_id: SM2 签名/验签使用的用户标识 ID（普通字符串，按字节使用）。
 *           省略时默认空 ID，与 OpenSSL CLI 默认行为一致；
 *           国密推荐默认 ID 为字符串 "1234567812345678"，
 *           与 gmssl、utils.py、sm2_sage.sage 默认一致。
 *
 * 输出：
 *   成功时打印 16 进制结果；失败时向 stderr 打印错误并返回非 0。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/core_names.h>

static void print_err(const char *msg)
{
    fprintf(stderr, "error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static int hex_to_bytes(const char *hex, unsigned char **out, size_t *out_len)
{
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        fprintf(stderr, "error: hex length must be even\n");
        return 0;
    }
    size_t blen = len / 2;
    if (blen == 0) {
        *out = NULL;
        *out_len = 0;
        return 1;
    }
    unsigned char *buf = malloc(blen);
    if (!buf) return 0;
    for (size_t i = 0; i < blen; i++) {
        unsigned int b;
        if (sscanf(hex + 2*i, "%2x", &b) != 1) {
            free(buf);
            return 0;
        }
        buf[i] = (unsigned char)b;
    }
    *out = buf;
    *out_len = blen;
    return 1;
}

static void print_hex(const unsigned char *data, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

/* -------------------- SM3 -------------------- */

static int do_sm3(const char *hex)
{
    unsigned char *in = NULL;
    size_t in_len = 0;
    if (!hex_to_bytes(hex, &in, &in_len)) return 1;

    EVP_MD *md = EVP_MD_fetch(NULL, "SM3", NULL);
    if (!md) { print_err("EVP_MD_fetch SM3"); free(in); return 1; }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx || !EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, in, in_len) ||
        !EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
        print_err("SM3 digest");
        EVP_MD_CTX_free(ctx); EVP_MD_free(md); free(in); return 1;
    }
    EVP_MD_CTX_free(ctx); EVP_MD_free(md); free(in);
    print_hex(digest, digest_len);
    return 0;
}

/* -------------------- SM4 -------------------- */

static const EVP_CIPHER *fetch_sm4_cipher(const char *mode)
{
    char name[32];
    if (strcmp(mode, "ecb") == 0) strcpy(name, "SM4-ECB");
    else if (strcmp(mode, "cbc") == 0) strcpy(name, "SM4-CBC");
    else if (strcmp(mode, "cfb") == 0) strcpy(name, "SM4-CFB");
    else if (strcmp(mode, "ofb") == 0) strcpy(name, "SM4-OFB");
    else if (strcmp(mode, "ctr") == 0) strcpy(name, "SM4-CTR");
    else if (strcmp(mode, "xts") == 0) strcpy(name, "SM4-XTS");
    else return NULL;
    return EVP_CIPHER_fetch(NULL, name, NULL);
}

static int do_sm4(const char *mode, const char *op,
                  const char *key_hex, const char *iv_hex, const char *in_hex)
{
    int encrypt = (strcmp(op, "enc") == 0);
    unsigned char *key = NULL, *iv = NULL, *in = NULL, *out = NULL;
    size_t key_len = 0, iv_len = 0, in_len = 0;
    if (!hex_to_bytes(key_hex, &key, &key_len)) return 1;
    if (!hex_to_bytes(iv_hex, &iv, &iv_len)) { free(key); return 1; }
    if (!hex_to_bytes(in_hex, &in, &in_len)) { free(key); free(iv); return 1; }

    const EVP_CIPHER *cipher = fetch_sm4_cipher(mode);
    if (!cipher) { fprintf(stderr, "error: unsupported mode %s\n", mode); goto err; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { print_err("EVP_CIPHER_CTX_new"); goto err; }

    /* XTS 必须分两步设置 key/iv，否则 OpenSSL 会错误处理 tweak */
    if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, encrypt, NULL)) {
        print_err("EVP_CipherInit_ex2"); EVP_CIPHER_CTX_free(ctx); goto err;
    }
    if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, encrypt, NULL)) {
        print_err("EVP_CipherInit_ex2 key/iv"); EVP_CIPHER_CTX_free(ctx); goto err;
    }
    if (strcmp(mode, "ecb") == 0 || strcmp(mode, "cbc") == 0) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    out = malloc(in_len + EVP_CIPHER_block_size(cipher));
    if (!out) { EVP_CIPHER_CTX_free(ctx); goto err; }

    int out_len1 = 0, out_len2 = 0;
    if (!EVP_CipherUpdate(ctx, out, &out_len1, in, in_len) ||
        !EVP_CipherFinal_ex(ctx, out + out_len1, &out_len2)) {
        print_err("EVP_CipherUpdate/Final"); EVP_CIPHER_CTX_free(ctx); goto err;
    }
    EVP_CIPHER_CTX_free(ctx);
    print_hex(out, out_len1 + out_len2);
    free(key); free(iv); free(in); free(out);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 0;
err:
    free(key); free(iv); free(in); free(out);
    if (cipher) EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 1;
}

static int do_sm4_aead(const char *mode, const char *op,
                       const char *key_hex, const char *iv_hex, const char *in_hex,
                       const char *aad_hex, const char *tag_hex)
{
    int encrypt = (strcmp(op, "enc") == 0);
    unsigned char *key = NULL, *iv = NULL, *in = NULL, *out = NULL, *aad = NULL;
    size_t key_len = 0, iv_len = 0, in_len = 0, aad_len = 0;
    if (!hex_to_bytes(key_hex, &key, &key_len)) return 1;
    if (!hex_to_bytes(iv_hex, &iv, &iv_len)) { free(key); return 1; }
    if (!hex_to_bytes(in_hex, &in, &in_len)) { free(key); free(iv); return 1; }
    if (aad_hex && !hex_to_bytes(aad_hex, &aad, &aad_len)) { free(key); free(iv); free(in); return 1; }

    const EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, mode, NULL);
    if (!cipher) { fprintf(stderr, "error: cannot fetch %s\n", mode); goto err; }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { print_err("EVP_CIPHER_CTX_new"); goto err; }

    if (!EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, encrypt, NULL)) {
        print_err("EVP_CipherInit_ex2"); EVP_CIPHER_CTX_free(ctx); goto err;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_len, NULL)) {
        print_err("EVP_CTRL_AEAD_SET_IVLEN"); EVP_CIPHER_CTX_free(ctx); goto err;
    }

    int tag_len = 16;
    if (strcmp(mode, "SM4-CCM") == 0) {
        /* CCM 需要在设置 key/iv 之前先指定 tag 长度 */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, NULL)) {
            print_err("EVP_CTRL_AEAD_SET_TAG len"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
    }

    if (!EVP_CipherInit_ex2(ctx, NULL, key, iv, encrypt, NULL)) {
        print_err("EVP_CipherInit_ex2 key/iv"); EVP_CIPHER_CTX_free(ctx); goto err;
    }

    /* CCM 解密需要在设置消息长度之前设置待校验的 tag */
    unsigned char *dec_tag = NULL;
    size_t dec_tag_len = 0;
    if (!encrypt && strcmp(mode, "SM4-CCM") == 0) {
        if (!tag_hex || strlen(tag_hex) != 32 || !hex_to_bytes(tag_hex, &dec_tag, &dec_tag_len)) {
            fprintf(stderr, "error: decryption requires 16-byte tag hex\n");
            EVP_CIPHER_CTX_free(ctx); goto err;
        }
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, dec_tag)) {
            print_err("EVP_CTRL_AEAD_SET_TAG ccm dec"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
    }

    /* CCM 需要预先设置消息长度 */
    if (strcmp(mode, "SM4-CCM") == 0) {
        int len = 0;
        if (!EVP_CipherUpdate(ctx, NULL, &len, NULL, (int)in_len)) {
            print_err("EVP_CipherUpdate ccm msglen"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
    }

    if (aad && aad_len > 0) {
        int len = 0;
        if (!EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len)) {
            print_err("EVP_CipherUpdate aad"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
    }

    out = malloc(in_len + EVP_CIPHER_block_size(cipher));
    if (!out) { EVP_CIPHER_CTX_free(ctx); goto err; }

    int out_len1 = 0, out_len2 = 0;
    if (!EVP_CipherUpdate(ctx, out, &out_len1, in, in_len)) {
        print_err("EVP_CipherUpdate"); EVP_CIPHER_CTX_free(ctx); goto err;
    }

    if (encrypt) {
        if (!EVP_CipherFinal_ex(ctx, out + out_len1, &out_len2)) {
            print_err("EVP_CipherFinal_ex"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
        unsigned char tag[16];
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag)) {
            print_err("EVP_CTRL_AEAD_GET_TAG"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
        print_hex(out, out_len1 + out_len2);
        print_hex(tag, tag_len);
    } else {
        /* GCM 解密在最后设置 tag；CCM 已提前设置 */
        if (strcmp(mode, "SM4-GCM") == 0) {
            unsigned char *tag = NULL;
            size_t tag_len2 = 0;
            if (!tag_hex || strlen(tag_hex) != 32 || !hex_to_bytes(tag_hex, &tag, &tag_len2)) {
                fprintf(stderr, "error: decryption requires 16-byte tag hex\n");
                EVP_CIPHER_CTX_free(ctx); goto err;
            }
            if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_len, tag)) {
                print_err("EVP_CTRL_AEAD_SET_TAG"); free(tag); EVP_CIPHER_CTX_free(ctx); goto err;
            }
            free(tag);
        }
        if (!EVP_CipherFinal_ex(ctx, out + out_len1, &out_len2)) {
            print_err("EVP_CipherFinal_ex decrypt"); EVP_CIPHER_CTX_free(ctx); goto err;
        }
        print_hex(out, out_len1 + out_len2);
    }

    EVP_CIPHER_CTX_free(ctx);
    free(key); free(iv); free(in); free(out); free(aad); free(dec_tag);
    EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 0;
err:
    free(key); free(iv); free(in); free(out); free(aad); free(dec_tag);
    if (cipher) EVP_CIPHER_free((EVP_CIPHER *)cipher);
    return 1;
}

/* -------------------- SM2 -------------------- */

static int do_sm2_pubkey(const char *d_hex)
{
    unsigned char *d_bytes = NULL;
    size_t d_len = 0;
    if (!hex_to_bytes(d_hex, &d_bytes, &d_len)) return 1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) { print_err("EVP_PKEY_CTX_new_id"); free(d_bytes); return 1; }

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_sm2) <= 0) {
        print_err("SM2 keygen init"); EVP_PKEY_CTX_free(ctx); free(d_bytes); return 1;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        print_err("EVP_PKEY_keygen"); EVP_PKEY_CTX_free(ctx); free(d_bytes); return 1;
    }
    EVP_PKEY_CTX_free(ctx);

    BIGNUM *d = BN_bin2bn(d_bytes, d_len, NULL);
    free(d_bytes);
    if (!d) { print_err("BN_bin2bn"); EVP_PKEY_free(pkey); return 1; }

    /* 通过 EC_KEY 替换私钥并重新计算公钥 */
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec) { print_err("EVP_PKEY_get1_EC_KEY"); BN_free(d); EVP_PKEY_free(pkey); return 1; }

    if (!EC_KEY_set_private_key(ec, d)) {
        print_err("EC_KEY_set_private_key"); BN_free(d); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1;
    }
    BN_free(d);

    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *pub = EC_POINT_new(group);
    if (!pub) { print_err("EC_POINT_new"); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1; }

    const BIGNUM *order = EC_GROUP_get0_order(group);
    if (!order) { print_err("EC_GROUP_get0_order"); EC_POINT_free(pub); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1; }

    const BIGNUM *d_bn = EC_KEY_get0_private_key(ec);
    if (!d_bn) {
        print_err("EC_KEY_get0_private_key"); EC_POINT_free(pub); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1;
    }

    if (!EC_POINT_mul(group, pub, d_bn, NULL, NULL, NULL)) {
        print_err("EC_POINT_mul"); EC_POINT_free(pub); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1;
    }

    if (!EC_KEY_set_public_key(ec, pub)) {
        print_err("EC_KEY_set_public_key"); EC_POINT_free(pub); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1;
    }
    EC_POINT_free(pub);

    /* 直接提取 x, y 坐标，输出未压缩 04||x||y */
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec);
    BIGNUM *x = BN_new(), *y = BN_new();
    if (!EC_POINT_get_affine_coordinates(group, pub_point, x, y, NULL)) {
        print_err("EC_POINT_get_affine_coordinates"); BN_free(x); BN_free(y); EC_KEY_free(ec); EVP_PKEY_free(pkey); return 1;
    }
    EC_KEY_free(ec); EVP_PKEY_free(pkey);

    unsigned char xbuf[32], ybuf[32];
    BN_bn2binpad(x, xbuf, 32); BN_free(x);
    BN_bn2binpad(y, ybuf, 32); BN_free(y);
    printf("04");
    for (int i = 0; i < 32; i++) printf("%02x", xbuf[i]);
    for (int i = 0; i < 32; i++) printf("%02x", ybuf[i]);
    printf("\n");
    return 0;
}

static int do_sm2_sign(const char *d_hex, const char *msg_hex, const char *sm2_id)
{
    /* 先生成 pkey（复用 sm2_pubkey 逻辑会简洁一些），这里直接构造 */
    /* 为简化，先创建临时 SM2 key，再替换私钥 */
    unsigned char *d_bytes = NULL, *msg = NULL, *sig = NULL;
    size_t d_len = 0, msg_len = 0;
    EVP_PKEY_CTX *kg = NULL;
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec = NULL;
    BIGNUM *d = NULL;
    EC_POINT *pub = NULL;
    EVP_MD_CTX *ctx = NULL;
    int success = 0;

    if (!hex_to_bytes(d_hex, &d_bytes, &d_len)) return 1;
    if (!hex_to_bytes(msg_hex, &msg, &msg_len)) goto cleanup;
    const char *id = sm2_id ? sm2_id : "";
    size_t id_len = strlen(id);

    /* 创建临时 SM2 key */
    kg = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kg) { print_err("EVP_PKEY_CTX_new_id"); goto cleanup; }
    if (EVP_PKEY_keygen_init(kg) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kg, NID_sm2) <= 0) {
        print_err("SM2 keygen init"); goto cleanup;
    }
    if (EVP_PKEY_keygen(kg, &pkey) <= 0) {
        print_err("EVP_PKEY_keygen"); goto cleanup;
    }
    EVP_PKEY_CTX_free(kg); kg = NULL;

    ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec) { print_err("EVP_PKEY_get1_EC_KEY"); goto cleanup; }
    d = BN_bin2bn(d_bytes, d_len, NULL);
    if (!d) { print_err("BN_bin2bn"); goto cleanup; }
    if (!EC_KEY_set_private_key(ec, d)) {
        print_err("EC_KEY_set_private_key"); goto cleanup;
    }
    BN_free(d); d = NULL;

    pub = EC_POINT_new(EC_KEY_get0_group(ec));
    if (!pub) { print_err("EC_POINT_new"); goto cleanup; }
    const BIGNUM *dtmp = EC_KEY_get0_private_key(ec);
    if (!EC_POINT_mul(EC_KEY_get0_group(ec), pub, dtmp, NULL, NULL, NULL)) {
        print_err("EC_POINT_mul"); goto cleanup;
    }
    if (!EC_KEY_set_public_key(ec, pub)) {
        print_err("EC_KEY_set_public_key"); goto cleanup;
    }
    EC_POINT_free(pub); pub = NULL;

    if (!EVP_PKEY_set1_EC_KEY(pkey, ec)) {
        print_err("EVP_PKEY_set1_EC_KEY"); goto cleanup;
    }
    EC_KEY_free(ec); ec = NULL;

    ctx = EVP_MD_CTX_new();
    if (!ctx) { print_err("EVP_MD_CTX_new"); goto cleanup; }
    EVP_PKEY_CTX *pctx = NULL;
    if (!EVP_DigestSignInit(ctx, &pctx, EVP_sm3(), NULL, pkey)) {
        print_err("EVP_DigestSignInit"); goto cleanup;
    }
    /* 默认空 ID，与 OpenSSL CLI 默认行为一致；可通过 sm2_id 指定 */
    if (EVP_PKEY_CTX_set1_id(pctx, id, (int)id_len) <= 0) {
        print_err("EVP_PKEY_CTX_set1_id"); goto cleanup;
    }

    size_t sig_len = 0;
    if (!EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len)) {
        print_err("EVP_DigestSign length"); goto cleanup;
    }
    sig = malloc(sig_len);
    if (!sig) { print_err("malloc"); goto cleanup; }
    if (!EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len)) {
        print_err("EVP_DigestSign"); goto cleanup;
    }

    print_hex(sig, sig_len);
    success = 1;

cleanup:
    free(sig);
    EVP_MD_CTX_free(ctx);
    EC_POINT_free(pub);
    BN_free(d);
    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(kg);
    free(d_bytes);
    free(msg);
    return success ? 0 : 1;
}

static int do_sm2_verify(const char *pub_hex, const char *sig_hex, const char *msg_hex, const char *sm2_id)
{
    unsigned char *pub = NULL, *sig = NULL, *msg = NULL;
    size_t pub_len = 0, sig_len = 0, msg_len = 0;
    if (!hex_to_bytes(pub_hex, &pub, &pub_len)) return 1;
    if (!hex_to_bytes(sig_hex, &sig, &sig_len)) { free(pub); return 1; }
    if (!hex_to_bytes(msg_hex, &msg, &msg_len)) { free(pub); free(sig); return 1; }
    const char *id = sm2_id ? sm2_id : "";
    size_t id_len = strlen(id);

    EVP_PKEY *pkey = NULL;

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len);
    params[2] = OSSL_PARAM_construct_end();

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "SM2", NULL);
    if (!ctx) { print_err("EVP_PKEY_CTX_new_from_name"); EVP_PKEY_free(pkey); goto err; }
    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        print_err("EVP_PKEY_fromdata_init"); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); goto err;
    }
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        print_err("EVP_PKEY_fromdata"); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(pkey); goto err;
    }
    EVP_PKEY_CTX_free(ctx);

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    if (!mctx || !EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), NULL, pkey)) {
        print_err("EVP_DigestVerifyInit"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); goto err;
    }
    if (EVP_PKEY_CTX_set1_id(pctx, id, (int)id_len) <= 0) {
        print_err("EVP_PKEY_CTX_set1_id verify"); EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey); goto err;
    }
    int ret = EVP_DigestVerify(mctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(mctx); EVP_PKEY_free(pkey);
    free(pub); free(sig); free(msg);
    printf("%d\n", ret);
    return 0;
err:
    EVP_PKEY_free(pkey);
    free(pub); free(sig); free(msg);
    return 1;
}

/* -------------------- main -------------------- */

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <subcommand> ...\n", argv[0]);
        return 1;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "sm3") == 0) {
        if (argc != 3) { fprintf(stderr, "usage: %s sm3 <hex>\n", argv[0]); return 1; }
        return do_sm3(argv[2]);
    }

    if (strcmp(cmd, "sm4") == 0) {
        if (argc != 7) {
            fprintf(stderr, "usage: %s sm4 <mode> <enc|dec> <key_hex> <iv_hex> <in_hex>\n", argv[0]);
            return 1;
        }
        return do_sm4(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }

    if (strcmp(cmd, "sm4_gcm") == 0 || strcmp(cmd, "sm4_ccm") == 0) {
        if (argc < 6 || argc > 8) {
            fprintf(stderr, "usage: %s %s <enc|dec> <key_hex> <iv_hex> <in_hex> [aad_hex] [tag_hex]\n", argv[0], cmd);
            return 1;
        }
        const char *mode = strcmp(cmd, "sm4_gcm") == 0 ? "SM4-GCM" : "SM4-CCM";
        return do_sm4_aead(mode, argv[2], argv[3], argv[4], argv[5],
                           argc > 6 ? argv[6] : NULL,
                           argc > 7 ? argv[7] : NULL);
    }

    if (strcmp(cmd, "sm2_pubkey") == 0) {
        if (argc != 3) { fprintf(stderr, "usage: %s sm2_pubkey <d_hex>\n", argv[0]); return 1; }
        return do_sm2_pubkey(argv[2]);
    }
    if (strcmp(cmd, "sm2_sign") == 0) {
        if (argc < 4 || argc > 5) { fprintf(stderr, "usage: %s sm2_sign <d_hex> <msg_hex> [sm2_id]\n", argv[0]); return 1; }
        return do_sm2_sign(argv[2], argv[3], argc > 4 ? argv[4] : NULL);
    }
    if (strcmp(cmd, "sm2_verify") == 0) {
        if (argc < 5 || argc > 6) { fprintf(stderr, "usage: %s sm2_verify <pub_hex> <sig_hex> <msg_hex> [sm2_id]\n", argv[0]); return 1; }
        return do_sm2_verify(argv[2], argv[3], argv[4], argc > 5 ? argv[5] : NULL);
    }

    fprintf(stderr, "unknown subcommand: %s\n", cmd);
    return 1;
}
