#
#
#================================================================
#   
#   
#   文件名称：mbedtls.mk
#   创 建 者：肖飞
#   创建日期：2019年09月20日 星期五 12时53分39秒
#   修改日期：2020年01月30日 星期四 10时03分34秒
#   描    述：
#
#================================================================
include $(default_rules)

CFLAGS += -g
CC := gcc

common_c_files := mbedTLS/library/aes.c
common_c_files += mbedTLS/library/aesni.c
common_c_files += mbedTLS/library/arc4.c
common_c_files += mbedTLS/library/asn1parse.c
common_c_files += mbedTLS/library/asn1write.c
common_c_files += mbedTLS/library/base64.c
common_c_files += mbedTLS/library/bignum.c
common_c_files += mbedTLS/library/blowfish.c
common_c_files += mbedTLS/library/camellia.c
common_c_files += mbedTLS/library/ccm.c
common_c_files += mbedTLS/library/certs.c
common_c_files += mbedTLS/library/cipher.c
common_c_files += mbedTLS/library/cipher_wrap.c
common_c_files += mbedTLS/library/cmac.c
common_c_files += mbedTLS/library/ctr_drbg.c
common_c_files += mbedTLS/library/debug.c
common_c_files += mbedTLS/library/des.c
common_c_files += mbedTLS/library/dhm.c
common_c_files += mbedTLS/library/ecdh.c
common_c_files += mbedTLS/library/ecdsa.c
common_c_files += mbedTLS/library/ecjpake.c
common_c_files += mbedTLS/library/ecp.c
common_c_files += mbedTLS/library/ecp_curves.c
common_c_files += mbedTLS/library/entropy.c
common_c_files += mbedTLS/library/entropy_poll.c
common_c_files += mbedTLS/library/error.c
common_c_files += mbedTLS/library/gcm.c
common_c_files += mbedTLS/library/havege.c
common_c_files += mbedTLS/library/hmac_drbg.c
common_c_files += mbedTLS/library/md.c
common_c_files += mbedTLS/library/md2.c
common_c_files += mbedTLS/library/md4.c
common_c_files += mbedTLS/library/md5.c
common_c_files += mbedTLS/library/md_wrap.c
common_c_files += mbedTLS/library/memory_buffer_alloc.c
common_c_files += mbedTLS/library/oid.c
common_c_files += mbedTLS/library/padlock.c
common_c_files += mbedTLS/library/pem.c
common_c_files += mbedTLS/library/pk.c
common_c_files += mbedTLS/library/pkcs11.c
common_c_files += mbedTLS/library/pkcs12.c
common_c_files += mbedTLS/library/pkcs5.c
common_c_files += mbedTLS/library/pkparse.c
common_c_files += mbedTLS/library/pkwrite.c
common_c_files += mbedTLS/library/pk_wrap.c
common_c_files += mbedTLS/library/platform.c
common_c_files += mbedTLS/library/ripemd160.c
common_c_files += mbedTLS/library/rsa.c
common_c_files += mbedTLS/library/sha1.c
common_c_files += mbedTLS/library/sha256.c
common_c_files += mbedTLS/library/sha512.c
common_c_files += mbedTLS/library/ssl_cache.c
common_c_files += mbedTLS/library/ssl_ciphersuites.c
common_c_files += mbedTLS/library/ssl_cli.c
common_c_files += mbedTLS/library/ssl_cookie.c
common_c_files += mbedTLS/library/ssl_srv.c
common_c_files += mbedTLS/library/ssl_ticket.c
common_c_files += mbedTLS/library/ssl_tls.c
common_c_files += mbedTLS/library/threading.c
common_c_files += mbedTLS/library/timing.c
common_c_files += mbedTLS/library/version.c
common_c_files += mbedTLS/library/version_features.c
common_c_files += mbedTLS/library/x509.c
common_c_files += mbedTLS/library/x509write_crt.c
common_c_files += mbedTLS/library/x509write_csr.c
common_c_files += mbedTLS/library/x509_create.c
common_c_files += mbedTLS/library/x509_crl.c
common_c_files += mbedTLS/library/x509_crt.c
common_c_files += mbedTLS/library/x509_csr.c
common_c_files += mbedTLS/library/xtea.c

common_c_flags := -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\" -Wall -Wextra -ImbedTLS/include -ImbedTLS/include/mbedtls

c_files := $(common_c_files)

c_files += main.c
c_files += https.c
c_files += net_sockets.c
app_name := https_client
LOCAL_CFLAGS := $(common_c_flags) -g
LOCAL_LDFLAGS := -Wl,-Map,main.map
include $(BUILD_APP)

include $(ADD_TARGET)
