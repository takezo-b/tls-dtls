# MCP GitHub 段階的学習計画

## 前提条件の確認

- ✅ Git CLI 操作は熟練者レベル
- ❓ GitHub Web UI機能は未習熟
- ✅ GitLab Merge Request経験あり（企業環境）
- ✅ MCP GitHub接続テスト完了済み

## 学習目標

TLS実装プロジェクトでMCP GitHubを効率的に活用できるようになる

---

## 📚 段階1: GitHub基本概念の理解 (30分)

**目的**: GitLabとの違いを理解し、GitHub固有の概念を習得

### 1.1 GitHub vs GitLab 概念マッピング

- Issue vs Issue（ほぼ同じ）
- Pull Request vs Merge Request（GitHubではPR）
- Repository settings vs Project settings
- Organization vs Group

### 1.2 実践演習

```bash
# リポジトリ検索でTLS関連プロジェクト調査
search_repositories("language:c tls wolfssl openssl")
# 有名プロジェクトの構造を把握
get_file_contents("openssl/openssl", "CONTRIBUTING.md")
```

**実践課題**:

- OpenSSL, wolfSSL, s2n-tlsの3つのプロジェクトを比較
- 各プロジェクトのCONTRIBUTING.mdを読み、開発プロセスの違いを理解

---

## 🔍 段階2: リポジトリ調査・検索技術 (45分)

**目的**: 効率的な情報収集技術の習得

### 2.1 高度な検索技術

```bash
# 特定技術での検索
search_repositories("language:c stars:>100 tls implementation")
# Issue/PR検索
search_issues("repo:wolfssl/wolfssl tls handshake error")
# コード検索
search_code("q=tls_client_hello language:c")
```

### 2.2 検索クエリのベストプラクティス

| 検索目的 | クエリ例 | 説明 |
|---------|---------|------|
| 人気のTLSライブラリ | `language:c tls stars:>500` | スター数500以上のC言語TLSプロジェクト |
| 特定の実装パターン | `"SSL_connect" language:c` | SSL_connect関数を使用するコード例 |
| 最近更新されたプロジェクト | `tls pushed:>2024-01-01` | 2024年以降に更新されたTLS関連プロジェクト |
| セキュリティ関連のIssue | `repo:openssl/openssl label:security` | OpenSSLのセキュリティラベル付きIssue |

### 2.3 実践プロジェクト

- TLS実装の参考プロジェクト5つを選定
- 各プロジェクトのアーキテクチャ調査
- 実装パターンの比較分析表を作成

**成果物**: `tls-projects-comparison.md`

---

## 📝 段階3: Issue管理の実践 (60分)

**目的**: プロジェクト管理とコミュニケーション

### 3.1 Issue操作の習得

```bash
# Issue作成
create_issue(
  title="TLS handshake implementation",
  body="## 要件\n- [ ] Client Hello\n- [ ] Server Hello\n- [ ] Certificate Exchange",
  labels=["enhancement", "tls", "priority-high"]
)

# Issue管理
update_issue(issue_number=1, labels=["enhancement", "tls"])
list_issues(state="open", labels=["tls"])
add_issue_comment(issue_number=1, body="実装方針を検討中")
```

### 3.2 Issue テンプレートの設計

**バグレポート用テンプレート**:

```markdown
## 問題の説明
<!-- 何が起きているかを簡潔に説明 -->

## 再現手順
1. 
2. 
3. 

## 期待される動作
<!-- 何が起きるべきかを説明 -->

## 実際の動作
<!-- 実際に何が起きたかを説明 -->

## 環境情報
- OS: 
- コンパイラ: 
- OpenSSLバージョン: 

## 追加情報
<!-- スクリーンショット、ログ、その他の関連情報 -->
```

**機能要求用テンプレート**:

```markdown
## 機能の概要
<!-- 実装したい機能の概要 -->

## 動機・背景
<!-- なぜこの機能が必要か -->

## 詳細設計
### API仕様

```c
// 関数プロトタイプ例
int tls_new_feature(const char* param);
```

### 実装方針

- [ ] ステップ1:
- [ ] ステップ2:
- [ ] ステップ3:

## テスト計画
<!-- どのようにテストするか -->
```text

### 3.3 ラベル体系の設計

| カテゴリ | ラベル | 説明 |
|---------|-------|------|
| 種類 | `bug` | バグレポート |
| 種類 | `enhancement` | 新機能・改善 |
| 種類 | `documentation` | ドキュメント関連 |
| 優先度 | `priority-high` | 高優先度 |
| 優先度 | `priority-medium` | 中優先度 |
| 優先度 | `priority-low` | 低優先度 |
| 技術領域 | `tls` | TLS関連 |
| 技術領域 | `crypto` | 暗号化関連 |
| 技術領域 | `networking` | ネットワーク関連 |
| 状態 | `help-wanted` | 協力者募集 |
| 状態 | `good-first-issue` | 初心者向け |

### 3.4 実践演習

自分のTLSプロジェクト用の包括的なIssue管理システムを構築：
1. Issue テンプレート作成
2. ラベル体系の実装
3. マイルストーン設定
4. 実際のIssue作成と管理

---

## 🔄 段階4: Pull Request ワークフロー (75分)

**目的**: コードレビューとコラボレーション

### 4.1 PR操作の習得

```bash
# ブランチ作成
create_branch(branch="feature/tls-client", from_branch="main")

# ファイル更新
create_or_update_file(
  path="src/tls_client.c", 
  content="// TLS client implementation\n#include <stdio.h>...", 
  message="Add TLS client skeleton",
  branch="feature/tls-client"
)

# PR作成
create_pull_request(
  title="Add TLS client implementation",
  head="feature/tls-client",
  base="main",
  body="## 概要\nTLSクライアントの基本実装を追加\n\n## 変更内容\n- [ ] Client Hello実装\n- [ ] ハンドシェイク処理"
)
```

### 4.2 高度なPR管理

```bash
# PR詳細取得
get_pull_request(pull_number=1)
get_pull_request_files(pull_number=1)

# レビュー機能
create_pull_request_review(
  pull_number=1, 
  event="APPROVE", 
  body="LGTM! 実装が清潔で理解しやすい。"
)

# コメント機能
get_pull_request_comments(pull_number=1)
```

### 4.3 PR テンプレートの設計

```markdown
## 変更内容の概要
<!-- このPRで何を変更したかの概要 -->

## 変更の種類
- [ ] バグ修正
- [ ] 新機能
- [ ] 破壊的変更
- [ ] ドキュメント更新
- [ ] その他（説明: ）

## 詳細な変更内容
<!-- 技術的な詳細、設計判断、実装上の考慮事項 -->

## テスト
- [ ] 既存のテストがパスする
- [ ] 新しいテストを追加した
- [ ] 手動テストを実施した

### テスト内容
<!-- テストの詳細、テストケース -->

## チェックリスト
- [ ] コードレビューを受けた
- [ ] ドキュメントを更新した
- [ ] セキュリティへの影響を検討した
- [ ] パフォーマンスへの影響を検証した

## 関連Issue
<!-- Closes #123 -->

## スクリーンショット（該当する場合）
<!-- ビジュアルな変更がある場合 -->
```

### 4.4 実践プロジェクト

実際のTLS実装でPRワークフローを体験：

1. Feature branch作成
2. 段階的なコミット
3. PR作成とテンプレート活用
4. セルフレビューの実施
5. マージとクリーンアップ

---

## 🚀 段階5: 実プロジェクト適用 (90分)

**目的**: 学習した技術の統合活用

### 5.1 TLS実装プロジェクトのセットアップ

```bash
# プロジェクト用リポジトリ作成
create_repository(
  name="c-tls-implementation",
  description="C言語でのTLS 1.3実装プロジェクト - 学習とプロトタイピング用",
  private=false,
  auto_init=true
)

# 初期ファイル構造作成
push_files(
  branch="main",
  message="Initial project structure setup",
  files=[
    {
      path: "src/tls_client.c",
      content: "// TLS client implementation\n#include \"tls.h\"\n\nint main() {\n    // TODO: Implement\n    return 0;\n}"
    },
    {
      path: "include/tls.h", 
      content: "// TLS header definitions\n#ifndef TLS_H\n#define TLS_H\n\n// TLS version constants\n#define TLS_VERSION_1_3 0x0304\n\n#endif // TLS_H"
    },
    {
      path: "tests/test_handshake.c",
      content: "// Unit tests for TLS handshake\n#include <assert.h>\n#include \"../include/tls.h\"\n\nvoid test_client_hello() {\n    // TODO: Implement test\n}\n\nint main() {\n    test_client_hello();\n    return 0;\n}"
    },
    {
      path: "Makefile",
      content: "CC=gcc\nCFLAGS=-Wall -Wextra -std=c99 -Iinclude\n\nall: client\n\nclient: src/tls_client.c\n\t$(CC) $(CFLAGS) -o $@ $<\n\ntest: tests/test_handshake.c\n\t$(CC) $(CFLAGS) -o $@ $<\n\nclean:\n\trm -f client test\n\n.PHONY: all test clean"
    },
    {
      path: "README.md",
      content: "# C TLS Implementation\n\n## 概要\nC言語でのTLS 1.3実装の学習プロジェクト\n\n## ビルド方法\n```bash\nmake all\n```\n\n## テスト実行\n```bash\nmake test\n./test\n```\n\n## 実装予定\n- [ ] TLS 1.3 Client Hello\n- [ ] Server Hello処理\n- [ ] Certificate Exchange\n- [ ] Handshake完了\n- [ ] Application Data送受信\n"
    }
  ]
)
```

### 5.2 Issue Driven Development の実践

```bash
# 実装タスクのIssue化
create_issue(
  title="TLS 1.3 Client Hello メッセージ実装",
  body="## 概要\nTLS 1.3のClient Helloメッセージを構築・送信する機能を実装する\n\n## 実装内容\n### Required Extensions\n- [ ] supported_versions (TLS 1.3)\n- [ ] key_share (X25519, P-256)\n- [ ] signature_algorithms\n- [ ] supported_groups\n\n### Optional Extensions  \n- [ ] server_name (SNI)\n- [ ] application_layer_protocol_negotiation\n\n## 参考資料\n- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446)\n- [OpenSSL implementation](https://github.com/openssl/openssl)\n\n## テスト方針\n- Wiresharkでパケット解析\n- 既存のTLSサーバーとの接続テスト",
  labels=["enhancement", "tls", "priority-high"]
)

create_issue(
  title="暗号化ライブラリの選定と統合",
  body="## 概要\nTLS実装で使用する暗号化ライブラリを選定し、プロジェクトに統合する\n\n## 候補\n1. **OpenSSL**: 最も一般的、豊富な機能\n2. **wolfSSL**: 軽量、組み込み向け\n3. **libsodium**: モダンな暗号化API\n4. **自前実装**: 学習目的\n\n## 評価基準\n- 学習のしやすさ\n- ドキュメントの充実度\n- ライセンス（MIT/Apache preferred）\n- コミュニティの活発さ",
  labels=["research", "crypto", "priority-medium"]
)

# マイルストーン設定
# create_milestone(title="TLS Handshake v1.0", description="基本的なTLSハンドシェイクの実装")
```

### 5.3 継続的なプロジェクト管理

**週次レビューのテンプレート**:

```markdown
# 週次進捗レビュー - Week of YYYY-MM-DD

## 完了したタスク
- [ ] Issue #1: TLS Client Hello実装
- [ ] Issue #3: テストケース追加

## 今週の学び
### 技術的な発見
- TLS 1.3では...
- 暗号化の実装で注意点として...

### 課題・問題点
- パフォーマンスの問題
- メモリリークの可能性

## 来週の計画
- [ ] Server Hello処理の実装
- [ ] 証明書検証ロジック

## リソース・参考資料
- [RFC 8446の特定セクション](...)
- [参考実装](...)
```

---

## 📊 段階6: 高度な活用・自動化 (60分)

**目的**: 効率化とベストプラクティス

### 6.1 プロジェクト管理の自動化

```bash
# 一括操作と分析
list_commits(sha="main") # コミット履歴分析
get_pull_request_status(pull_number=1) # CI状態確認
list_issues(state="all", sort="updated") # Issue活動分析
```

### 6.2 情報収集の最適化

**定期的な技術調査のルーチン**:

```bash
# 1. 最新のTLS関連プロジェクト調査
search_repositories("tls created:>2024-01-01 language:c")

# 2. セキュリティアップデート監視
search_issues("repo:openssl/openssl label:security state:open")

# 3. 実装パターンの調査
search_code("q=SSL_connect language:c")
```

### 6.3 コミュニティとの連携

```bash
# 関連プロジェクトのフォーク
fork_repository(owner="wolfssl", repo="wolfssl")

# Issueでの質問・議論参加
add_issue_comment(
  owner="openssl",
  repo="openssl", 
  issue_number=12345,
  body="TLS 1.3の実装について質問があります..."
)
```

### 6.4 ベストプラクティスの実装

**セキュリティチェックリスト**:

- [ ] 秘密鍵をリポジトリにコミットしない
- [ ] セキュリティに関わるIssueは適切にラベリング
- [ ] 脆弱性発見時の対応プロセス文書化
- [ ] 定期的な依存関係の脆弱性チェック

**コードレビューのガイドライン**:

- [ ] セキュリティへの影響を必ず検討
- [ ] メモリ安全性の確認（C言語特有）
- [ ] エラーハンドリングの妥当性
- [ ] テストカバレッジの確認

---

## 🎯 最終目標の確認

### 習得予定スキル

- [ ] 効率的なリポジトリ検索・調査技術
- [ ] Issue driven development の実践
- [ ] Pull Request ワークフローの習得
- [ ] プロジェクト管理の自動化手法
- [ ] TLS実装プロジェクトでの実践的活用

### 継続学習項目

1. **GitHub Actions連携（CI/CD）**
   - 自動テスト実行
   - セキュリティスキャン
   - 自動デプロイ

2. **セキュリティ機能の活用**
   - Dependabot
   - Code scanning
   - Secret scanning

3. **コミュニティとのコラボレーション**
   - OSS貢献のベストプラクティス
   - メンテナとの効果的なコミュニケーション

---

## 📋 学習進捗トラッキング

### 段階1: GitHub基本概念 ✅/❌

- [ ] GitLab vs GitHub概念の理解
- [ ] 基本的な検索操作
- [ ] 有名プロジェクトの調査完了

### 段階2: 検索技術 ✅/❌

- [ ] 高度な検索クエリの習得
- [ ] コード検索の活用
- [ ] プロジェクト比較分析の完了

### 段階3: Issue管理 ✅/❌

- [ ] Issue作成・管理の習得
- [ ] テンプレート・ラベル体系の構築
- [ ] 実践的なIssue運用

### 段階4: Pull Request ✅/❌

- [ ] PR作成・管理の習得
- [ ] レビューワークフローの理解
- [ ] 実際のPR運用経験

### 段階5: 実プロジェクト ✅/❌

- [ ] プロジェクトセットアップ完了
- [ ] Issue driven development実践
- [ ] 継続的なプロジェクト管理

### 段階6: 高度な活用 ✅/❌

- [ ] 自動化手法の実装
- [ ] 効率的な情報収集体制
- [ ] コミュニティ連携の実現

---

## 💡 Tips & Notes

### 効率化のコツ

- **検索履歴の活用**: よく使う検索クエリをメモ
- **ブックマーク機能**: 重要なIssue/PRをブックマーク
- **通知の最適化**: 重要なリポジトリのみ通知設定

### トラブルシューティング

- **API制限**: 認証済みリクエストは5000/hour
- **大容量ファイル**: 100MB以上はGit LFS使用
- **プライベートリポジトリ**: トークンの権限確認

### セキュリティベストプラクティス

- **トークン管理**: 定期的なローテーション
- **権限の最小化**: 必要最小限のスコープ設定
- **監査ログ**: 重要な操作の記録確認

**総学習時間**: 約6時間（実践含む）  
**推奨期間**: 2-3日間で段階的に実施  
**更新日**: 2025-08-12
