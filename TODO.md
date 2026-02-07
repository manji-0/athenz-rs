# TODO (優先順: テスト拡充 → 修正 → 機能追加)

## テスト拡充 (P0)
- [x] ZTS: AccessTokenRequest/IdTokenRequest のフォーム・クエリ生成テスト追加
- [x] JWT: JWKS sanitize report の除外アルゴリズムテスト追加
- [x] Policy: case_sensitive/conditions を無視する（ZPE準拠）挙動のテスト追加
- [x] Policy: JWS/署名検証 + 期限切れ境界のテスト追加
- [x] ZTS/ZMS: HTTP リクエスト生成（パス/ヘッダ/クエリ）をモックで確認するテスト追加

## 修正 (P1)
- [x] README の JWKS エンドポイントを /oauth2/keys に修正
- [x] canonical_json の文字列エスケープを正規実装に置換（署名検証ずれ対策）
- [x] PolicyStore は case_sensitive/conditions を無視（ZPE準拠）。README に明記
- [x] AccessTokenRequest の scope 生成を ID Token 要求（openid + service）に対応

## 機能追加 (P2)
- [x] AccessTokenRequest に raw scope/ID token service を指定できる builder を追加
- [x] ZTS 未実装エンドポイント追加: /access*, /domain/*/token, /providerdomain, /domain/*/creds, /instance/*/refresh など
- [ ] ZMS 未実装エンドポイント追加: template/meta/system-meta/ownership/entity/review/pending 等
- [ ] async クライアント（reqwest async）追加検討
