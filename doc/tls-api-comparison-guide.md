# TLS ライブラリ API 比較ガイド

## API 設計哲学とアプローチ

### 設計原則の比較

| ライブラリ | 設計哲学 | API 設計原則 | 対象開発者 |
|-----------|----------|-------------|-----------|
| **Mbed TLS** | モジュラー・組み込み特化 | PSA準拠、設定駆動 | 組み込み開発者 |
| **wolfSSL** | 高性能・商用グレード | 最適化重視、柔軟性 | 商用製品開発者 |
| **s2n-tls** | セキュリティ最優先 | シンプル・安全 | クラウド開発者 |
| **OpenSSL** | 包括的・互換性重視 | レイヤード、拡張可能 | 一般開発者 |
| **BoringSSL** | Chrome最適化 | 簡素化・高性能 | Google製品開発者 |
| **LibreSSL** | OpenBSD流品質 | クリーン・セキュア | UNIX系開発者 |

## 基本 API 構造比較

### 1. 初期化パターン

#### Mbed TLS - PSA Crypto API

```c
// PSA Cryptography API (推奨)
#include <psa/crypto.h>
#include <mbedtls/ssl.h>

// 1. PSA初期化
psa_status_t status = psa_crypto_init();

// 2. SSL設定構造体
mbedtls_ssl_config conf;
mbedtls_ssl_config_init(&conf);
mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

// 3. SSL文脈
mbedtls_ssl_context ssl;
mbedtls_ssl_init(&ssl);
mbedtls_ssl_setup(&ssl, &conf);
```

#### wolfSSL - 統合アプローチ

```c
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

// 1. ライブラリ初期化
int ret = wolfSSL_Init();

// 2. コンテキスト作成
WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());

// 3. SSL接続オブジェクト
WOLFSSL* ssl = wolfSSL_new(ctx);
```

#### s2n-tls - AWS最適化

```c
#include <s2n.h>

// 1. s2n初期化
s2n_init();

// 2. 設定作成
struct s2n_config *config = s2n_config_new();
s2n_config_set_check_stapled_ocsp_response(config, 0);

// 3. 接続作成
struct s2n_connection *conn = s2n_connection_new(S2N_CLIENT);
s2n_connection_set_config(conn, config);
```

#### OpenSSL - レイヤードアプローチ

```c
#include <openssl/ssl.h>
#include <openssl/err.h>

// 1. ライブラリ初期化
SSL_library_init();
SSL_load_error_strings();

// 2. メソッドとコンテキスト
const SSL_METHOD *method = TLS_client_method();
SSL_CTX *ctx = SSL_CTX_new(method);

// 3. SSL接続
SSL *ssl = SSL_new(ctx);
```

### 2. 証明書・鍵管理

#### Mbed TLS - PSA鍵管理統合

```c
// PSA鍵インポート
psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);

psa_key_id_t key_id;
psa_status_t status = psa_import_key(&attributes, key_data, key_size, &key_id);

// SSL設定に統合
mbedtls_ssl_conf_own_cert(&conf, &cert, &key);
```

#### wolfSSL - ファイル・メモリ両対応

```c
// 証明書ファイル読み込み
int ret = wolfSSL_CTX_use_certificate_file(ctx, "client-cert.pem", WOLFSSL_FILETYPE_PEM);

// メモリからの読み込み
ret = wolfSSL_CTX_use_certificate_buffer(ctx, cert_buffer, cert_size, WOLFSSL_FILETYPE_DER);

// 秘密鍵設定
ret = wolfSSL_CTX_use_PrivateKey_file(ctx, "client-key.pem", WOLFSSL_FILETYPE_PEM);
```

#### s2n-tls - セキュリティ重視

```c
// 証明書チェーン設定
s2n_config_add_cert_chain_and_key(config, cert_chain, private_key);

// 信頼できるCA設定
s2n_config_set_verification_ca_location(config, ca_file, ca_dir);

// 証明書検証コールバック
s2n_config_set_verify_host_callback(config, verify_host_fn, data);
```

### 3. ハンドシェイク実行パターン

#### 非ブロッキング I/O 対応比較

**Mbed TLS**:

```c
int ret;
do {
    ret = mbedtls_ssl_handshake(&ssl);
} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

if (ret == 0) {
    // ハンドシェイク成功
    printf("TLS接続確立: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));
}
```

**wolfSSL**:

```c
int ret = wolfSSL_connect(ssl);
if (ret == WOLFSSL_SUCCESS) {
    // ハンドシェイク成功
} else if (wolfSSL_want_read(ssl) || wolfSSL_want_write(ssl)) {
    // 非ブロッキング処理継続
} else {
    // エラー処理
    int error = wolfSSL_get_error(ssl, ret);
}
```

**s2n-tls**:

```c
s2n_blocked_status blocked;
int ret = s2n_negotiate(conn, &blocked);
if (ret == S2N_SUCCESS) {
    // ハンドシェイク成功
} else if (ret == S2N_ERR_T_BLOCKED) {
    // blocked値を確認して再実行
}
```

## データ送受信 API 比較

### 1. 同期 I/O パターン

#### Mbed TLS

```c
// データ送信
int sent = mbedtls_ssl_write(&ssl, buffer, length);
if (sent < 0) {
    if (sent == MBEDTLS_ERR_SSL_WANT_WRITE) {
        // 再試行必要
    } else {
        // エラー処理
    }
}

// データ受信
int received = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
```

#### wolfSSL

```c
// データ送信
int sent = wolfSSL_write(ssl, buffer, length);
if (sent < 0) {
    int error = wolfSSL_get_error(ssl, sent);
    // エラー分析
}

// データ受信
int received = wolfSSL_read(ssl, buffer, sizeof(buffer));
```

#### s2n-tls

```c
// データ送信
s2n_blocked_status blocked;
int sent = s2n_send(conn, buffer, length, &blocked);

// データ受信
int received = s2n_recv(conn, buffer, sizeof(buffer), &blocked);
```

### 2. ゼロコピー最適化

#### s2n-tls - 高性能 I/O

```c
// sendfile() システムコール利用
ssize_t bytes_written;
int ret = s2n_sendfile(conn, in_fd, offset, count, &bytes_written);
```

#### wolfSSL - バッファ最適化

```c
// アプリケーションバッファ直接利用
wolfSSL_SetIOWriteCtx(ssl, write_context);
wolfSSL_SetIOReadCtx(ssl, read_context);
```

## エラーハンドリング比較

### 1. エラー情報取得

#### Mbed TLS - 構造化エラー

```c
int ret = mbedtls_ssl_handshake(&ssl);
if (ret < 0) {
    char error_buf[256];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("SSL Error: %s (code: -0x%04X)\n", error_buf, -ret);
}
```

#### wolfSSL - 詳細エラー分析

```c
int ret = wolfSSL_connect(ssl);
if (ret != WOLFSSL_SUCCESS) {
    int error = wolfSSL_get_error(ssl, ret);
    char* error_string = wolfSSL_ERR_error_string(error, NULL);
    printf("wolfSSL Error: %s\n", error_string);
}
```

#### s2n-tls - シンプルエラー

```c
int ret = s2n_negotiate(conn, &blocked);
if (ret < 0) {
    printf("s2n Error: %s\n", s2n_strerror(s2n_errno, "EN"));
}
```

#### OpenSSL - 包括的エラー

```c
int ret = SSL_connect(ssl);
if (ret <= 0) {
    int ssl_error = SSL_get_error(ssl, ret);
    unsigned long err_code = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
    printf("OpenSSL Error: %s\n", err_buf);
}
```

## 設定・カスタマイゼーション

### 1. 暗号化スイート選択

#### Mbed TLS - 設定駆動

```c
// コンパイル時設定
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_CIPHER_MODE_GCM

// ランタイム設定
int ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    0
};
mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);
```

#### wolfSSL - 文字列指定

```c
// OpenSSL互換文字列
wolfSSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");

// TLS 1.3 暗号化スイート
wolfSSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
```

#### s2n-tls - セキュリティポリシー

```c
// 事前定義されたセキュリティポリシー
s2n_config_set_cipher_preferences(config, "default_tls13");
s2n_config_set_cipher_preferences(config, "CloudFront-TLS-1-2-2019-07");
```

### 2. 証明書検証カスタマイズ

#### 高度な検証ロジック

**Mbed TLS**:

```c
int verify_callback(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    // カスタム検証ロジック
    if (depth == 0) {
        // リーフ証明書の追加検証
    }
    return 0;
}

mbedtls_ssl_conf_verify(&conf, verify_callback, &verify_data);
```

**wolfSSL**:

```c
int verify_callback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store) {
    // 証明書チェーン検証
    WOLFSSL_X509* cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    // カスタム検証処理
    return preverify_ok;
}

wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_callback);
```

## パフォーマンス最適化 API

### 1. セッション管理

#### セッション再開最適化

**Mbed TLS**:

```c
// セッション保存
mbedtls_ssl_session saved_session;
mbedtls_ssl_get_session(&ssl, &saved_session);

// セッション復元
mbedtls_ssl_set_session(&ssl, &saved_session);
```

**wolfSSL**:

```c
// セッションキャッシュ設定
wolfSSL_CTX_set_session_cache_mode(ctx, WOLFSSL_SESS_CACHE_CLIENT);
wolfSSL_CTX_set_timeout(ctx, 3600); // 1時間

// セッション再開
WOLFSSL_SESSION* session = wolfSSL_get_session(ssl);
wolfSSL_set_session(new_ssl, session);
```

### 2. ハードウェア加速

#### wolfSSL - 包括的ハードウェア支援

```c
// Intel AES-NI使用
#ifdef HAVE_INTEL_AES
    ret = wolfSSL_CTX_set_cipher_list(ctx, "AES128-GCM-SHA256");
#endif

// ハードウェア乱数生成器
#ifdef HAVE_INTEL_RDRAND
    wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
#endif
```

#### Mbed TLS - ハードウェア抽象化

```c
// ハードウェア加速設定
#if defined(MBEDTLS_AES_ALT)
    // 代替AES実装使用
#endif

// PSA Crypto ドライバー
psa_crypto_driver_t custom_driver = {
    .accelerated_algorithms = PSA_ALG_AES_CTR,
    // ドライバー実装
};
```

## 非同期・イベント駆動対応

### 1. コールバック設定

#### Mbed TLS - I/O コールバック

```c
void my_send(void *ctx, const unsigned char *buf, size_t len) {
    // カスタム送信実装
}

int my_recv(void *ctx, unsigned char *buf, size_t len) {
    // カスタム受信実装
}

mbedtls_ssl_set_bio(&ssl, net_ctx, my_send, my_recv, NULL);
```

#### wolfSSL - I/O コールバック

```c
int my_io_send(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    // 非ブロッキング送信
    return send(fd, buf, sz, MSG_DONTWAIT);
}

int my_io_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx) {
    // 非ブロッキング受信
    return recv(fd, buf, sz, MSG_DONTWAIT);
}

wolfSSL_SetIOSend(ctx, my_io_send);
wolfSSL_SetIORecv(ctx, my_io_recv);
```

### 2. イベントループ統合

#### s2n-tls - epoll統合例

```c
// s2n-tlsは内部的にnon-blocking I/Oを前提とした設計
int handle_tls_event(struct s2n_connection *conn, int events) {
    if (events & EPOLLIN) {
        s2n_blocked_status blocked;
        int ret = s2n_recv(conn, buffer, sizeof(buffer), &blocked);
        if (ret > 0) {
            // データ処理
        } else if (blocked == S2N_BLOCKED_ON_READ) {
            // 読み込み待ち
        }
    }
    if (events & EPOLLOUT) {
        // 送信処理
    }
    return 0;
}
```

## メモリ管理比較

### 1. メモリ使用量制御

#### Mbed TLS - 詳細制御

```c
// コンパイル時メモリ制限
#define MBEDTLS_SSL_MAX_CONTENT_LEN 1024
#define MBEDTLS_SSL_IN_CONTENT_LEN  1024
#define MBEDTLS_SSL_OUT_CONTENT_LEN 1024

// 動的メモリ使用量監視
size_t heap_used = mbedtls_memory_buffer_get_size() - mbedtls_memory_buffer_get_free();
```

#### wolfSSL - 効率的メモリ管理

```c
// メモリプール使用
#ifdef WOLFSSL_STATIC_MEMORY
    static unsigned char memory_buffer[65536];
    static unsigned char io_buffer[16384];
    
    wolfSSL_CTX_load_static_memory(&ctx, wolfTLSv1_3_client_method_ex,
                                   memory_buffer, sizeof(memory_buffer),
                                   io_buffer, sizeof(io_buffer));
#endif
```

### 2. セキュアメモリ操作

#### 全ライブラリ共通 - 秘密鍵保護

```c
// Mbed TLS
mbedtls_platform_zeroize(sensitive_data, size);

// wolfSSL
ForceZero(sensitive_data, size);

// s2n-tls
s2n_blob_zero(&sensitive_blob);

// OpenSSL
OPENSSL_cleanse(sensitive_data, size);
```

## デバッグ・診断機能

### 1. ログ・トレース出力

#### Mbed TLS - 詳細デバッグ

```c
void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
    printf("[%s:%d] %s", file, line, str);
}

mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
mbedtls_debug_set_threshold(4); // 最大詳細レベル
```

#### wolfSSL - ログレベル制御

```c
#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
    wolfSSL_SetLoggingCb(my_logging_callback);
#endif

void my_logging_callback(const int logLevel, const char* const logMessage) {
    printf("[%d] %s\n", logLevel, logMessage);
}
```

### 2. 接続状態診断

#### 接続情報取得比較

```c
// Mbed TLS
const char* version = mbedtls_ssl_get_version(&ssl);
const char* cipher = mbedtls_ssl_get_ciphersuite(&ssl);
size_t bytes_avail = mbedtls_ssl_get_bytes_avail(&ssl);

// wolfSSL
const char* cipher = wolfSSL_get_cipher_name(ssl);
const char* version = wolfSSL_get_version(ssl);
int bits = wolfSSL_GetCipherBits(ssl, &alg_bits);

// s2n-tls
const char* cipher = s2n_connection_get_cipher(conn);
int version = s2n_connection_get_protocol_version(conn);
```

## API 使いやすさ評価

### 学習難易度

1. **s2n-tls**: ★★★★★ (最もシンプル)
2. **wolfSSL**: ★★★★☆ (OpenSSL互換で親しみやすい)
3. **Mbed TLS**: ★★★☆☆ (設定が多く初期学習コスト高)
4. **OpenSSL**: ★★☆☆☆ (豊富だが複雑)
5. **BoringSSL**: ★★☆☆☆ (文書化限定的)
6. **LibreSSL**: ★★★☆☆ (OpenSSL知識が前提)

### エラーハンドリングの分かりやすさ

- **s2n-tls**: 簡潔で分かりやすい
- **Mbed TLS**: 構造化されたエラーコード
- **wolfSSL**: OpenSSL互換で慣れ親しまれた方式
- **OpenSSL**: 包括的だが複雑
- **LibreSSL**: OpenSSL互換
- **BoringSSL**: シンプルだが情報が限定的

### 用途別推奨 API

- **学習・プロトタイピング**: s2n-tls → Mbed TLS
- **組み込み開発**: Mbed TLS → wolfSSL  
- **Webサーバー**: s2n-tls → OpenSSL
- **既存システム統合**: OpenSSL → LibreSSL
- **高性能要求**: wolfSSL → BoringSSL
- **セキュリティ最優先**: s2n-tls → LibreSSL

このガイドを参考に、プロジェクトの要件に最適なTLSライブラリを選択し、効率的にAPI活用を進めることができます。