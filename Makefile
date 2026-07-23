# SM2/SM3/SM4 工具集合 Makefile
#
# 目标：
#   make              编译 OpenSSL C 辅助程序
#   make test         运行全部自测
#   make test-utils   运行 utils.py 自测
#   make test-sage    运行 sm2_sage.sage 自测
#   make test-openssl 运行 OpenSSL SM2/3/4 演示自测
#   make clean        清理编译产物

CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wno-deprecated-declarations
LDFLAGS  ?= -lcrypto

HELPER    = openssl_sm_helper
HELPER_SRC = openssl_sm_helper.c
H         = ./$(HELPER)

PYTHON   ?= python
SAGE     ?= sage

.PHONY: all clean help test test-utils test-sage test-openssl test-sm4-modes test-sm4-gcm-sage test-verify-openssl test-verify-gmssl test-sm2 test-sm3 test-sm4

.DEFAULT_GOAL := all

help:
	@echo "目标:"
	@echo "  make                  编译 OpenSSL C 辅助程序"
	@echo "  make test             运行全部自测"
	@echo "  make test-utils       运行 utils.py 自测"
	@echo "  make test-sage        运行 sm2_sage.sage 自测"
	@echo "  make test-openssl        运行 OpenSSL SM2/3/4 演示自测"
	@echo "  make test-sm4-modes      运行 sm4_modes.py 自测"
	@echo "  make test-sm4-gcm-sage   运行 sm4_gcm_sage.sage 自测"
	@echo "  make test-verify-openssl 以系统 openssl CLI 为基准做一致性验证"
	@echo "  make test-verify-gmssl   以 gmssl Python 库为基准做一致性验证"
	@echo "  make clean               清理编译产物"

all: $(HELPER)

$(HELPER): $(HELPER_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(HELPER)
	rm -rf __pycache__
	rm -f /tmp/_sm2*.pem /tmp/_sm2_pub_compressed.pem

test: all test-utils test-sage test-openssl test-sm4-modes test-sm4-gcm-sage test-verify-openssl test-verify-gmssl
	@echo "========================================"
	@echo "全部测试通过"
	@echo "========================================"

test-utils:
	@echo "========================================"
	@echo "utils.py 自测"
	@echo "========================================"
	$(PYTHON) utils.py

test-sage:
	@echo "========================================"
	@echo "sm2_sage.sage 自测"
	@echo "========================================"
	$(SAGE) sm2_sage.sage

test-openssl: all test-sm3 test-sm4 test-sm2
	@echo "========================================"
	@echo "OpenSSL 演示自测全部通过"
	@echo "========================================"

test-sm4-modes:
	@echo "========================================"
	@echo "sm4_modes.py 自测"
	@echo "========================================"
	$(PYTHON) sm4_modes.py

test-sm4-gcm-sage:
	@echo "========================================"
	@echo "sm4_gcm_sage.sage 自测"
	@echo "========================================"
	$(SAGE) sm4_gcm_sage.sage

test-verify-openssl:
	@echo "========================================"
	@echo "以系统 openssl CLI 为基准的一致性验证"
	@echo "========================================"
	$(PYTHON) verify_against_openssl.py

test-verify-gmssl:
	@echo "========================================"
	@echo "以 gmssl Python 库为基准的一致性验证"
	@echo "========================================"
	$(PYTHON) verify_against_gmssl.py

test-sm3: all
	@echo "[SM3] abc -> 66c7f0f4..."
	@test "$$($(H) sm3 616263)" = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

test-sm4: all
	@echo "[SM4] ECB/CBC/CFB/OFB/CTR/XTS roundtrip"
	@for mode in ecb cbc cfb ofb ctr xts; do \
		key=0123456789abcdeffedcba9876543210; \
		iv=00000000000000000000000000000000; \
		pt=0123456789abcdeffedcba9876543210; \
		if [ "$$mode" = "xts" ]; then key="$$key$$key"; fi; \
		ct=$$($(H) sm4 $$mode enc $$key $$iv $$pt); \
		pt2=$$($(H) sm4 $$mode dec $$key $$iv $$ct); \
		if [ "$$pt" != "$$pt2" ]; then echo "SM4-$$mode failed"; exit 1; fi; \
		echo "[SM4-$$mode] ok"; \
	done
	@echo "[SM4] GCM/CCM roundtrip"
	@key=0123456789abcdeffedcba9876543210; \
	iv=000000000000000000000000; \
	pt=0123456789abcdeffedcba9876543210; \
	aad=616263; \
	for mode in gcm ccm; do \
		out=$$($(H) sm4_$$mode enc $$key $$iv $$pt $$aad); \
		ct=$$(echo "$$out" | head -1); \
		tag=$$(echo "$$out" | tail -1); \
		pt2=$$($(H) sm4_$$mode dec $$key $$iv $$ct $$aad $$tag); \
		if [ "$$pt" != "$$pt2" ]; then echo "SM4-$$mode failed"; exit 1; fi; \
		echo "[SM4-$$mode] ok (tag=$$tag)"; \
	done

test-sm2: all
	@echo "[SM2] pubkey / sign / verify"
	@d=123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0; \
	msg=68656c6c6f; \
	pub=$$($(H) sm2_pubkey $$d); \
	if [ "$${pub:0:2}" != "04" ] || [ "$${#pub}" != "130" ]; then echo "pubkey format error"; exit 1; fi; \
	sig=$$($(H) sm2_sign $$d $$msg); \
	ret=$$($(H) sm2_verify $$pub $$sig $$msg); \
	if [ "$$ret" != "1" ]; then echo "SM2 verify failed"; exit 1; fi; \
	echo "[SM2] pubkey/sign/verify ok"
