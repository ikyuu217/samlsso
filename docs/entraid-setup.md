# Microsoft Entra ID 側の設定手順(検証用 Enterprise Application)

samlsso(このリポジトリの SAML SP)を Entra ID と接続するための、ポータルでの設定手順。SP メタデータのアップロードは使わず、必要な 2 項目(識別子・応答 URL)を手動で入力する。

## 前提

- 対象テナントに Enterprise Application を登録できるロールを持っていること(クラウド アプリケーション管理者、アプリケーション管理者など)。
- 作るアプリは検証用。**検証用と分かる名前を付け、検証が終わったら削除する**(後片付けの節を参照)。

## 1. Enterprise Application の新規登録(非ギャラリ)

1. [Microsoft Entra 管理センター](https://entra.microsoft.com) にサインインする。
2. **ID > アプリケーション > エンタープライズ アプリケーション** を開き、**新しいアプリケーション** をクリックする。
3. **独自のアプリケーションの作成** をクリックする。
4. アプリ名に検証用と分かる名前を入力する(例: `samlsso-verification-<自分の名前>`)。
5. 「**ギャラリーに見つからないその他のアプリケーションを統合します (ギャラリー以外)**」を選んで **作成** する。

## 2. SAML SSO の構成

1. 作成したアプリの管理画面で **シングル サインオン** を開き、方式として **SAML** を選ぶ。
2. 「**基本的な SAML 構成**」の **編集** をクリックし、次の 2 項目を手動で設定して **保存** する。

   | ポータルの項目 | 設定値 | SP 側の対応する環境変数 |
   |---|---|---|
   | 識別子 (エンティティ ID) | 任意の一意な URI(例: `urn:samlsso:verification`) | `SAML_SP_ENTITY_ID` に同じ値を設定 |
   | 応答 URL (Assertion Consumer Service URL) | `http://localhost:8080/saml/acs` | `SAML_SP_BASE_URL` + `/saml/acs`(既定のままなら左の値) |

   - 識別子はテナント内で一意であればよい。他アプリと衝突しない URI にする。
   - 応答 URL は通常 HTTPS が必須だが、`localhost` に限り HTTP でも登録できる想定。**保存時にエラーになる場合はここで手順を止め、HTTPS 化(ngrok 等)の検討に切り替える**(spec の未確定事項)。
3. 「**属性とクレーム**」は既定のままでよい。既定では NameID に `user.userprincipalname`、追加クレームとして `givenname` / `surname` / `emailaddress` / `name` が送られる。SP はここに含まれる属性をすべて表示する。
4. 「**SAML 証明書**」セクションにある「**アプリのフェデレーション メタデータ URL**」をコピーする。形式は次のとおりで、これを SP の `SAML_IDP_METADATA_URL` に設定する。

   ```
   https://login.microsoftonline.com/<テナント ID>/federationmetadata/2007-06/federationmetadata.xml?appid=<アプリケーション ID>
   ```

## 3. テストユーザーの割り当て

1. アプリの管理画面で **ユーザーとグループ** を開く。
2. **ユーザーまたはグループの追加** で自分のアカウントを選び、**割り当て** る。

割り当てていないユーザーでサインインすると、Entra ID が `AADSTS50105`(ユーザーが割り当てられていない)エラーを返す。

## 4. 動作確認

[README](../README.md) の「Running」「Verifying the login flow」に従って SP を起動し、ブラウザでログインフローを一周させる。

うまくいかないときの確認ポイント:

- **`AADSTS700016`(アプリが見つからない)**: AuthnRequest の Issuer(= `SAML_SP_ENTITY_ID`)が「識別子 (エンティティ ID)」と一致しているか。
- **`AADSTS50011`(応答 URL の不一致)**: 「応答 URL」と SP の ACS URL(起動ログの `ACS URL:`)が完全一致しているか(ポート・末尾スラッシュ含む)。
- **SP 側で `audience does not include our entity ID`**: `SAML_SP_ENTITY_ID` と「識別子 (エンティティ ID)」の不一致。
- 設定変更が反映されない場合は数分待つ(ポータルの変更が伝播するまでラグがあることがある)。

## 5. 後片付け(検証完了後に必ず実施)

1. アプリの管理画面で **プロパティ** を開き、**削除** する。
2. 必要なら **ID > アプリケーション > アプリの登録 > 削除済みのアプリケーション** からも完全削除する(Enterprise Application の作成時に対のアプリ登録が作られているため)。
