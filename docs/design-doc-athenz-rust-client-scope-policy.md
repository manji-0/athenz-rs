# Athenz Rust Client Scope & Policy

## Summary
- Athenz Rust クライアントとしての機能スコープ、OpenSSL非依存方針、テスト方針を開発者向けに定義する。
- 既存実装（reqwest + rustls など）に倣い、実用的で保守しやすい開発・検証ルールを明文化する。

## Goals
- Athenz Service が提供するすべての API に対応する方針を明記する。
- 特に以下をプロダクションレベルで実装する方針を固定する。
  - 秘密鍵/証明書による署名済 JWT の発行
  - クライアント署名済 JWT の検証
  - mTLS 用サーバ/クライアント x.509 証明書の発行/更新
- OpenSSL 非依存の方針を明確化する。
- テスト戦略（Mock 方針と e2e の範囲/非範囲）を明文化する。

## Non-Goals
- Athenz サーバ実装の挙動差異を吸収するための互換層の提供
- Athenz 以外の認証/認可基盤への適用
- OpenSSL 依存を許容する構成（FIPS 対応など）を現時点で優先実装すること

## Background / Context
- athenz-rs は Athenz の Rust クライアント実装であり、API カバレッジの拡大と安定した検証が求められる。
- 既存実装は reqwest + rustls を採用し、OpenSSL への依存を避けている。

## Requirements
### Functional
- ZTS/ZMS の API を段階的にフルカバレッジへ拡大する。
- JWT/NToken/Policy の発行・検証・評価を安定実装する。
- mTLS 認証および証明書関連 API を本番品質で提供する。

### Non-Functional
- OpenSSL への依存を避ける（rustls/tls を標準）。
- テストは可搬性・再現性を優先し、外部依存を最小化する。
- 仕様変更に追従しやすい構成を維持する（API 追加のコストを抑える）。

## Proposed Design
### Architecture Overview
- 既存のモジュール構成（zts / zms / jwt / ntoken / policy）を維持。
- API ラッパは reqwest blocking を基準とし、必要に応じて async を検討。

### Components
- ZTS client: OAuth/JWKS/インスタンス/証明書/ポリシー取得など
- ZMS client: ドメイン/ロール/ポリシー/サービス/グループなど
- JWT/Policy/NToken: 署名・検証・評価のユーティリティ群

### Data Model
- Athenz RDL に準拠したモデル定義（serde を利用）

### APIs / Interfaces
- ZTS/ZMS は REST API ラッパとして提供
- JWT/Policy はオフライン検証を中心に設計

### Data Flow
- オンライン: API → JSON → model
- オフライン: JWKS/署名鍵 → JWT/Policy/NToken 検証

## Operational Plan
### Deployment / Environments
- Rust の standard toolchain で利用可能
- TLS は rustls を標準とし、OpenSSL 依存を避ける

### Observability
- 現状はログ/エラーの返却に留め、追加のメトリクスは任意

### Reliability / Failure Modes
- API エラーは ResourceError を返却
- JWT/署名検証エラーは明示的なエラー型で伝搬

### Security / Privacy
- OpenSSL 非依存（rustls）
- 署名検証は許可アルゴリズムの allowlist を維持

## Rollout / Migration Plan
- API 追加/変更は段階的に行い、既存メソッドの互換性を維持する

## Alternatives Considered
- OpenSSL 依存: プラットフォーム差異と依存コストが大きいため不採用
- 外部 ZTS/ZMS 統合テスト: 再現性と安定性の観点から最小化

## Risks and Mitigations
- **仕様差異リスク**: RDL との差異が生じうる → Schema 参照とテスト追加でカバー
- **API 追加漏れ**: 未実装 API の拡張計画を Linear issue として管理
- **暗号互換性**: 署名検証の仕様差異 → allowlist とテストで明示的に検証

## Open Questions
- async クライアントを正式サポートするか
- FIPS 必須環境への対応要否

## Appendix
### Testing Strategy (Mock 方針と e2e 範囲)
- **Mock 方針**
  - HTTP 通信はローカル TCP サーバ/モックで再現（パス/ヘッダ/クエリ/レスポンス）
  - JWKS / JWT / NToken / Policy の署名検証はローカル生成鍵で検証
  - ZTS/ZMS 依存部分は最小限のリクエスト/レスポンスパターンで代替

- **Mock により実現できる e2e 範囲**
  - クライアントの URL/パラメータ生成、レスポンスパース
  - JWT/NToken/Policy のオフライン検証
  - 署名検証の正常/異常パターン

- **Mock では実現できない範囲**
  - 実サーバ環境依存の動作（権限設定、DB連携、実際の署名鍵更新）
  - 実 ZTS/ZMS との統合動作（本番と同等の設定に依存）
