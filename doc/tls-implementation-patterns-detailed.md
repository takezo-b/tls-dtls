# TLS 実装パターン詳細ガイド

## 実装パターンの分類と特徴

### 1. アーキテクチャパターン

#### レイヤードアーキテクチャ (OpenSSL, LibreSSL)
```
アプリケーション層
    ↓
SSL/TLS プロトコル層 (libssl)
    ↓
暗号化ライブラリ層 (libcrypto)
    ↓
プラットフォーム抽象化層
    ↓
OS/ハードウェア層
```

**特徴**:
- 明確な責任分離
- 各層の独立性
- 後方互換性の維持
- 複雑性の管理

**実装例 (OpenSSL)**:
```c
// プロトコル層の分離
// libssl/ssl_lib.c
SSL *SSL_new(SSL_CTX *ctx) {
    SSL *s = OPENSSL_zalloc(sizeof(*s));
    // SSL プロトコル固有の初期化
    return s;
}

// 暗号化層の分離
// libcrypto/evp/evp_enc.c
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ENGINE *impl, const unsigned char *key,
                       const unsigned char *iv) {
    // 暗号化アルゴリズム固有の処理
}
```

#### モジュラーアーキテクチャ (Mbed TLS)
```
PSA Crypto API
    ↓
Mbed TLS API Modules
├── SSL/TLS Module
├── X.509 Module  
├── PK Module
└── Cipher Module
    ↓
HAL (Hardware Abstraction Layer)
    ↓
Platform Layer
```

**特徴**:
- 選択的モジュール使用
- コンパイル時最適化
- リソース効率性
- カスタマイズ容易性

**実装例 (Mbed TLS)**:
```c
// モジュール選択設定
// mbedtls_config.h
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#undef MBEDTLS_SSL_SRV_C        // サーバー機能無効

// 条件コンパイル
#if defined(MBEDTLS_SSL_TLS_C)
    // SSL/TLS機能のみ含める
    #include "ssl_tls.c"
#endif

// PSA統合
psa_status_t psa_crypto_init(void) {
    return mbedtls_psa_crypto_init();
}
```

#### ミニマルアーキテクチャ (s2n-tls)
```
TLS State Machine
    ↓
Crypto Operations Interface
    ↓
External libcrypto (OpenSSL/AWS-LC)
```

**特徴**:
- 単一責任原則
- 外部依存の最小化
- 理解しやすさ
- 監査の容易性

**実装例 (s2n-tls)**:
```c
// シンプルな状態機械
// s2n_handshake.c
struct s2n_handshake_state {
    handshake_type_t handshake_type;
    message_type_t message_type;
    int state;
};

int s2n_handshake_step(struct s2n_connection *conn) {
    switch (conn->handshake.state) {
        case CLIENT_HELLO:
            return s2n_client_hello_send(conn);
        case SERVER_HELLO:
            return s2n_server_hello_recv(conn);
        // ... 簡潔な状態遷移
    }
}
```

### 2. メモリ管理パターン

#### 静的メモリ管理パターン (組み込み特化)

**wolfSSL - メモリプール使用**:
```c
// 静的メモリプール設定
#ifdef WOLFSSL_STATIC_MEMORY
static unsigned char memory_buffer[MEMORY_SIZE];
static WOLFSSL_HEAP_HINT heap_hint;

int wolfSSL_init_static_memory(void) {
    // メモリプール初期化
    if (wc_LoadStaticMemory(&heap_hint, memory_buffer, 
                           sizeof(memory_buffer), 
                           WOLFMEM_GENERAL, 1) != 0) {
        return -1;
    }
    return 0;
}

// 使用例
WOLFSSL_CTX* ctx = wolfSSL_CTX_new_ex(wolfTLSv1_3_client_method(), 
                                      &heap_hint);
```

**Mbed TLS - プラットフォーム抽象化**:
```c
// カスタムメモリ管理
// platform.c
void *mbedtls_platform_calloc(size_t nmemb, size_t size) {
#ifdef MBEDTLS_PLATFORM_MEMORY
    return mbedtls_calloc(nmemb, size);
#else
    return calloc(nmemb, size);
#endif
}

// 組み込み向け固定サイズ割り当て
#ifdef CONSTRAINED_ENVIRONMENT
static unsigned char ssl_buffer[SSL_BUFFER_SIZE];
static size_t buffer_offset = 0;

void *custom_calloc(size_t nmemb, size_t size) {
    size_t total = nmemb * size;
    if (buffer_offset + total > SSL_BUFFER_SIZE) {
        return NULL; // メモリ不足
    }
    void *ptr = &ssl_buffer[buffer_offset];
    buffer_offset += total;
    memset(ptr, 0, total);
    return ptr;
}
#endif
```

#### 動的メモリ管理パターン

**OpenSSL - 柔軟なメモリ管理**:
```c
// カスタムメモリアロケータ設定
int CRYPTO_set_mem_functions(
    void *(*malloc_fn)(size_t, const char *, int),
    void *(*realloc_fn)(void *, size_t, const char *, int),
    void (*free_fn)(void *, const char *, int)
) {
    // カスタムアロケータ登録
}

// メモリプールの実装例
typedef struct {
    unsigned char *pool;
    size_t size;
    size_t offset;
} memory_pool_t;

void *pool_malloc(size_t size, const char *file, int line) {
    // プールからの割り当て
    if (current_pool->offset + size > current_pool->size) {
        return NULL;
    }
    void *ptr = &current_pool->pool[current_pool->offset];
    current_pool->offset += size;
    return ptr;
}
```

#### セキュアメモリ消去パターン

```c
// Mbed TLS - コンパイラ最適化対策
void mbedtls_platform_zeroize(void *buf, size_t len) {
    if (len > 0) {
        memset(buf, 0, len);
        // コンパイラ最適化を防ぐバリア
        __asm__ __volatile__("" : : "r"(buf) : "memory");
    }
}

// wolfSSL - 同様の実装
void ForceZero(void* mem, unsigned int len) {
    volatile unsigned char* z = (volatile unsigned char*)mem;
    while (len--) *z++ = 0;
}

// s2n-tls - 構造化アプローチ
int s2n_blob_zero(struct s2n_blob *b) {
    POSIX_ENSURE_REF(b);
    if (b->size > 0) {
        memset_s(b->data, b->size, 0, b->size);
    }
    return S2N_SUCCESS;
}
```

### 3. エラーハンドリングパターン

#### 構造化エラーコードパターン (Mbed TLS)

```c
// エラーコードの体系的定義
#define MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE    -0x7080
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA         -0x7100
#define MBEDTLS_ERR_SSL_INVALID_MAC            -0x7180

// エラー情報の構造化
typedef struct {
    int error_code;
    const char *error_string;
    const char *file;
    int line;
} mbedtls_error_info_t;

// エラーハンドリング関数
int mbedtls_ssl_handshake_step(mbedtls_ssl_context *ssl) {
    int ret = MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE;
    
    // バリデーション
    if (ssl == NULL) {
        MBEDTLS_SSL_DEBUG_MSG(1, ("null ssl context"));
        return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    }
    
    // 状態チェック
    if (ssl->state >= MBEDTLS_SSL_HANDSHAKE_OVER) {
        MBEDTLS_SSL_DEBUG_MSG(2, ("handshake already completed"));
        return 0;
    }
    
    // エラー伝播
    if ((ret = ssl_handshake_step_internal(ssl)) != 0) {
        MBEDTLS_SSL_DEBUG_RET(1, "ssl_handshake_step_internal", ret);
        return ret;
    }
    
    return 0;
}
```

#### Result型パターン (s2n-tls)

```c
// Result型の定義
typedef enum {
    S2N_RESULT_OK = 0,
    S2N_RESULT_ERROR = -1
} s2n_result;

// マクロによるエラーチェック
#define RESULT_ENSURE_REF(x) \
    do { \
        if ((x) == NULL) { \
            POSIX_BAIL(S2N_ERR_NULL); \
        } \
    } while (0)

#define RESULT_ENSURE(condition, error) \
    do { \
        if (!(condition)) { \
            POSIX_BAIL(error); \
        } \
    } while (0)

// 使用例
S2N_RESULT s2n_handshake_validate(struct s2n_connection *conn) {
    RESULT_ENSURE_REF(conn);
    RESULT_ENSURE(s2n_connection_check_io_status(conn), S2N_ERR_BLOCKED);
    RESULT_ENSURE(conn->mode != S2N_UNKNOWN_MODE, S2N_ERR_INVALID_STATE);
    return S2N_RESULT_OK;
}
```

#### チェーンエラーパターン (OpenSSL)

```c
// エラースタックによる詳細情報
void handle_ssl_error(SSL *ssl, int ret) {
    int ssl_error = SSL_get_error(ssl, ret);
    unsigned long err_code;
    char err_buf[256];
    
    switch (ssl_error) {
        case SSL_ERROR_ZERO_RETURN:
            printf("SSL connection closed cleanly\n");
            break;
            
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            printf("SSL operation would block\n");
            break;
            
        case SSL_ERROR_SSL:
            // エラースタックから詳細取得
            while ((err_code = ERR_get_error()) != 0) {
                ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
                printf("SSL Error: %s\n", err_buf);
            }
            break;
            
        default:
            printf("Unknown SSL error: %d\n", ssl_error);
            break;
    }
}
```

### 4. 並行処理パターン

#### スレッドローカルストレージパターン

```c
// OpenSSL - スレッドセーフティ
// スレッドローカルエラーキュー
__thread ERR_STATE *thread_err_state = NULL;

ERR_STATE *ERR_get_state(void) {
    if (thread_err_state == NULL) {
        thread_err_state = OPENSSL_zalloc(sizeof(ERR_STATE));
    }
    return thread_err_state;
}

// Mbed TLS - 文脈分離
typedef struct {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    // スレッド固有データ
    pthread_t thread_id;
} thread_ssl_context_t;

void *ssl_thread_worker(void *arg) {
    thread_ssl_context_t *ctx = (thread_ssl_context_t *)arg;
    ctx->thread_id = pthread_self();
    
    // スレッド固有の初期化
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);
    
    // TLS処理
    handle_tls_connection(ctx);
    
    return NULL;
}
```

#### 非同期I/Oパターン

```c
// s2n-tls - 非ブロッキング設計
typedef enum {
    S2N_BLOCKED_ON_READ,
    S2N_BLOCKED_ON_WRITE,
    S2N_NOT_BLOCKED
} s2n_blocked_status;

// 状態保持による継続可能設計
struct s2n_connection {
    s2n_blocked_status blocked;
    struct s2n_handshake handshake;
    struct s2n_record_protocol_version version;
    // ... 状態情報
};

int s2n_negotiate(struct s2n_connection *conn, s2n_blocked_status *blocked) {
    int result = S2N_SUCCESS;
    
    while (conn->handshake.handshake_type != NEGOTIATED) {
        result = s2n_handshake_step(conn);
        
        if (result == S2N_ERR_T_BLOCKED) {
            *blocked = conn->blocked;
            return S2N_ERR_T_BLOCKED;  // 呼び出し元で継続
        }
        
        if (result < S2N_SUCCESS) {
            return result;
        }
    }
    
    *blocked = S2N_NOT_BLOCKED;
    return S2N_SUCCESS;
}
```

### 5. 暗号化実装パターン

#### ハードウェア抽象化パターン (Mbed TLS)

```c
// ハードウェア特化実装の選択
typedef struct mbedtls_aes_context {
    uint32_t nr;                    /*!< rounds数 */
    uint32_t *rk;                   /*!< AES round keys */
    uint32_t buf[68];               /*!< 未整列データバッファ */
#if defined(MBEDTLS_AES_ALT)
    mbedtls_aes_alt_context alt_ctx; /*!< ハードウェア実装 */
#endif
} mbedtls_aes_context;

int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                          int mode,
                          const unsigned char input[16],
                          unsigned char output[16]) {
#if defined(MBEDTLS_AES_ALT)
    return mbedtls_aes_crypt_ecb_alt(ctx, mode, input, output);
#else
    return mbedtls_aes_crypt_ecb_sw(ctx, mode, input, output);
#endif
}
```

#### 最適化実装パターン (wolfSSL)

```c
// 動的最適化選択
int AES_encrypt(const unsigned char *in, unsigned char *out,
                const AES_KEY *key) {
#ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(cpu_flags)) {
        return AES_encrypt_avx2(in, out, key);
    }
#endif

#ifdef HAVE_INTEL_AES
    if (IS_INTEL_AES(cpu_flags)) {
        return AES_encrypt_aes_ni(in, out, key);
    }
#endif

#ifdef HAVE_ARM_CRYPTO
    if (IS_ARM_CRYPTO(cpu_flags)) {
        return AES_encrypt_arm_crypto(in, out, key);
    }
#endif

    // ソフトウェア実装
    return AES_encrypt_software(in, out, key);
}

// アセンブリ最適化例
#ifdef HAVE_INTEL_AES
__inline static void AES_encrypt_aes_ni(const unsigned char *in,
                                        unsigned char *out,
                                        const AES_KEY *key) {
    __m128i m = _mm_loadu_si128((__m128i*)in);
    __m128i k = _mm_loadu_si128((__m128i*)key->rd_key);
    
    m = _mm_xor_si128(m, k);
    
    for (int i = 1; i < key->rounds; i++) {
        k = _mm_loadu_si128((__m128i*)(key->rd_key + i * 4));
        m = _mm_aesenc_si128(m, k);
    }
    
    k = _mm_loadu_si128((__m128i*)(key->rd_key + key->rounds * 4));
    m = _mm_aesenclast_si128(m, k);
    
    _mm_storeu_si128((__m128i*)out, m);
}
#endif
```

### 6. I/O抽象化パターン

#### コールバック駆動I/Oパターン

```c
// Mbed TLS - カスタムI/O
typedef int (*mbedtls_ssl_send_t)(void *ctx,
                                  const unsigned char *buf,
                                  size_t len);
typedef int (*mbedtls_ssl_recv_t)(void *ctx,
                                  unsigned char *buf,
                                  size_t len);

void mbedtls_ssl_set_bio(mbedtls_ssl_context *ssl,
                         void *p_bio,
                         mbedtls_ssl_send_t f_send,
                         mbedtls_ssl_recv_t f_recv,
                         mbedtls_ssl_recv_timeout_t f_recv_timeout) {
    ssl->p_bio = p_bio;
    ssl->f_send = f_send;
    ssl->f_recv = f_recv;
    ssl->f_recv_timeout = f_recv_timeout;
}

// カスタムI/O実装例
int custom_send(void *ctx, const unsigned char *buf, size_t len) {
    network_context_t *net_ctx = (network_context_t *)ctx;
    
    // 非ブロッキングソケット送信
    ssize_t sent = send(net_ctx->fd, buf, len, MSG_DONTWAIT);
    
    if (sent < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return MBEDTLS_ERR_SSL_WANT_WRITE;
        }
        return MBEDTLS_ERR_NET_SEND_FAILED;
    }
    
    return (int)sent;
}
```

#### ゼロコピーI/Oパターン (s2n-tls)

```c
// sendfile() システムコール活用
ssize_t s2n_sendfile(struct s2n_connection *conn,
                     int in_fd,
                     off_t offset,
                     size_t count,
                     size_t *bytes_written) {
    POSIX_ENSURE_REF(conn);
    POSIX_ENSURE_REF(bytes_written);
    
    *bytes_written = 0;
    
    if (!s2n_connection_check_io_status(conn, S2N_IO_WRITABLE)) {
        POSIX_BAIL(S2N_ERR_CLOSED);
    }
    
    // TLS レコード暗号化は内部で処理
    // ゼロコピーでファイルからソケットへ直接転送
    ssize_t result = sendfile(conn->writefd, in_fd, &offset, count);
    
    if (result > 0) {
        *bytes_written = result;
    }
    
    return result;
}
```

### 7. テストパターン

#### ユニットテストパターン

```c
// Mbed TLS - 構造化テスト
// test_aes.c
void test_aes_encrypt_decrypt(void) {
    mbedtls_aes_context ctx;
    unsigned char key[32] = {0};
    unsigned char plaintext[16] = "Hello, World!!!";
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    
    // 初期化
    mbedtls_aes_init(&ctx);
    TEST_ASSERT(mbedtls_aes_setkey_enc(&ctx, key, 256) == 0);
    
    // 暗号化
    TEST_ASSERT(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, 
                                      plaintext, ciphertext) == 0);
    
    // 復号化
    mbedtls_aes_setkey_dec(&ctx, key, 256);
    TEST_ASSERT(mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, 
                                      ciphertext, decrypted) == 0);
    
    // 検証
    TEST_ASSERT_EQUAL_MEMORY(plaintext, decrypted, 16);
    
    mbedtls_aes_free(&ctx);
}
```

#### 統合テストパターン

```c
// s2n-tls - ハンドシェイクテスト
void test_tls13_handshake(void) {
    struct s2n_connection *client_conn = s2n_connection_new(S2N_CLIENT);
    struct s2n_connection *server_conn = s2n_connection_new(S2N_SERVER);
    
    // 設定
    struct s2n_config *client_config = s2n_config_new();
    struct s2n_config *server_config = s2n_config_new();
    
    s2n_config_set_cipher_preferences(client_config, "default_tls13");
    s2n_config_set_cipher_preferences(server_config, "default_tls13");
    
    // 証明書設定（テスト用）
    s2n_config_add_cert_chain_and_key(server_config, test_cert, test_key);
    
    // ハンドシェイク実行
    s2n_blocked_status client_blocked, server_blocked;
    
    do {
        s2n_negotiate(client_conn, &client_blocked);
        s2n_negotiate(server_conn, &server_blocked);
        
        // メッセージ交換シミュレーション
        exchange_handshake_messages(client_conn, server_conn);
        
    } while (client_blocked != S2N_NOT_BLOCKED || 
             server_blocked != S2N_NOT_BLOCKED);
    
    // 検証
    assert(s2n_connection_get_protocol_version(client_conn) == S2N_TLS13);
    assert(s2n_connection_get_protocol_version(server_conn) == S2N_TLS13);
    
    // クリーンアップ
    s2n_connection_free(client_conn);
    s2n_connection_free(server_conn);
    s2n_config_free(client_config);
    s2n_config_free(server_config);
}
```

#### ファジングテストパターン

```c
// libFuzzer 統合例
// fuzz_handshake.c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 10) return 0;
    
    struct s2n_connection *conn = s2n_connection_new(S2N_SERVER);
    struct s2n_config *config = s2n_config_new();
    
    // ファジング入力を設定
    s2n_connection_set_config(conn, config);
    
    // 入力データでハンドシェイク実行
    s2n_blocked_status blocked;
    int result = s2n_recv(conn, (void*)data, size, &blocked);
    
    // エラーは期待される（無効入力のため）
    // クラッシュしないことが重要
    
    s2n_connection_free(conn);
    s2n_config_free(config);
    
    return 0;
}
```

## 実装パターン選択指針

### 用途別パターン推奨

#### 組み込み・リソース制約環境
- **メモリ管理**: 静的メモリプール (wolfSSL, Mbed TLS)
- **アーキテクチャ**: モジュラー (Mbed TLS)
- **暗号化**: ハードウェア抽象化 (Mbed TLS)
- **エラー処理**: 構造化エラーコード (Mbed TLS)

#### サーバー・クラウド環境
- **メモリ管理**: 動的メモリ管理 (OpenSSL, s2n-tls)
- **アーキテクチャ**: レイヤード (OpenSSL) またはミニマル (s2n-tls)
- **並行処理**: 非同期I/O (s2n-tls)
- **I/O**: ゼロコピー最適化 (s2n-tls)

#### 学習・研究環境
- **アーキテクチャ**: ミニマル (s2n-tls)
- **エラー処理**: Result型 (s2n-tls)
- **テスト**: 包括的ユニットテスト
- **コード**: 可読性重視

### パフォーマンス重視選択

#### 高スループット要求
1. **wolfSSL**: アセンブリ最適化
2. **BoringSSL**: Chrome実績
3. **OpenSSL**: ハードウェア支援

#### 低レイテンシ要求
1. **s2n-tls**: ミニマル設計
2. **wolfSSL**: 効率的メモリ管理
3. **Mbed TLS**: 軽量実装

#### メモリ効率重視
1. **Mbed TLS**: 最小フットプリント
2. **wolfSSL**: 静的メモリ管理
3. **s2n-tls**: シンプル構造

このガイドにより、要件に応じた最適なTLS実装パターンを選択し、効率的な開発を進めることができます。