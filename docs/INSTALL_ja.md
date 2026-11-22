# jt-oz-bridge のインストール

[English](INSTALL.md) · [繁體中文](INSTALL_zh-tw.md) · 日本語 · [アップグレード](UPGRADE_ja.md) · [アンインストール](UNINSTALL_ja.md) · [概要](../README_ja.md)

このガイドでは、すでに OpenCode が動いている Linux ホストに、ブリッジを systemd サービスとしてインストールします。インターネットから、またはオフライン（エアギャップ）バンドルからインストールできます。jt-oz-bridge `0.1.0` は**開発プレビュー**であり、実際の利用者とモバイルでの受け入れは完了していません。まずは使い捨ての OpenCode プロジェクトで始めてください。

ブリッジが OpenCode をインストール、起動、再起動、アップグレードすることはなく、OpenCode のデータベースを読むことも、問題を回避するためにセッションを作成またはコピーすることもありません。インストール作業中もこの原則を守ってください。

## 1. 要件

| 項目 | 要件 |
|---|---|
| ホスト | systemd を使う Linux（x86_64）。開発環境は Ubuntu 24.04。ほかのアーキテクチャは未検証です。 |
| Python | CPython 3.13。サービスユーザーが読み取れ、かつ `/root` や `/home` の下に**置かない**こと（ユニットは `ProtectHome=true` を設定しています）。ディストリビューションのパッケージでも、共有ディレクトリに置いた uv 管理の Python でも構いません。第 4 節を参照してください。 |
| ツール | `uv`（推奨）または `pip`、`sha256sum`、`curl`。インストールには root 権限が必要です。 |
| OpenCode | 専用の OS アカウントで動作し、ループバックで待ち受けている OpenCode サーバー（V2 API。開発は 2.0.32 で実施。[互換性](COMPATIBILITY.md)（英語）を参照）。ブリッジは検証時の正確なバージョンを固定します。 |
| Zulip | Bot とプライベートチャンネルを作成できるセルフホストの Zulip サーバー（開発は 12.3 で実施）。 |
| リソース | ブリッジのユニットのメモリ上限は 1 GiB です。データベース、暗号化された添付ファイル、バックアップ用のディスクを見込んでください（添付ファイルの既定のクォータは 2 GiB）。 |

## 2. 既定のレイアウト

| パス | 内容 | 所有者とモード |
|---|---|---|
| `/opt/jt-oz-bridge/releases/<wheel-sha256>/` | リリースごとに 1 ディレクトリ：wheel、`requirements.txt`、SBOM、チェックサム、`venv/` | `root:jtoz`、ディレクトリ 755、ファイル 644 |
| `/opt/jt-oz-bridge/` | 補助スクリプト（`owner-probe.py`、`directory-probe.py`、`bridge-notice.py`、`bridge-standby.py`）と任意の共有 Python | `root`、755／644 |
| `/etc/jt-oz-bridge/config.toml` | 設定ファイル | `root:jtoz`、640 |
| `/etc/jt-oz-bridge/secrets/` | 暗号鍵、Zulip Bot の API キー、OpenCode の認証情報 | `jtoz:jtoz`、ディレクトリ 700、ファイル 600 |
| `/var/lib/jt-oz-bridge/` | 状態：`bridge.db` と `artifacts/` | `jtoz:jtoz`、700 |
| `/etc/systemd/system/` | `ops/server/` のユニットと drop-in | `root`、644 |
| `/usr/local/bin/jt-oz-bridge` | 稼働中リリースの CLI へのシンボリックリンク | `root` |

`jtoz` は同梱のユニットが使うサービスユーザーです。パスは既定値であり、変更する場合はユニットと設定ファイルを一緒に変更してください。状態ディレクトリとシークレットは、同期フォルダーやネットワークファイルシステム（Nextcloud、NFS、SMB）に置かないでください。

特に断りがない限り、このガイドのコマンドは root シェル（`sudo -i`）で、通常の umask で実行します。

```sh
umask 022
export UV_LINK_MODE=copy   # venv files are copies, not hard links into root's uv cache
```

## 3. サービスユーザーとディレクトリ

```sh
useradd --system --user-group --home-dir /var/lib/jt-oz-bridge --no-create-home \
  --shell /usr/sbin/nologin jtoz
install -d -o root -g root -m 755 /opt/jt-oz-bridge /opt/jt-oz-bridge/releases
install -d -o root -g jtoz -m 750 /etc/jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /etc/jt-oz-bridge/secrets /var/lib/jt-oz-bridge
```

## 4. Python 3.13

ディストリビューションの Python が 3.13 なら、それを使います。

```sh
PY=/usr/bin/python3.13
"$PY" --version
```

そうでなければ、uv 管理の Python を共有ディレクトリにインストールするか（オンライン）、オフラインバンドルの Python を展開します（第 5.2 節）。

```sh
uv python install 3.13 --install-dir /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
"$PY" --version
```

## 5. リリースファイルの入手

リリースは、wheel、ハッシュで固定された `requirements.txt`、SBOM `jt-oz-bridge-<version>.sbom.cdx.json`（CycloneDX 1.5）、そして設定例と systemd ユニットを含むソースアーカイブで構成されます。ネットワーク、`git`、`uv` のあるマシンで作成します。

```sh
git clone https://github.com/jasoncheng7115/jt-oz-bridge.git
cd jt-oz-bridge
git checkout <release tag or commit>
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
OUT=../jt-oz-bridge-$VERSION
mkdir "$OUT"
uv build --wheel --out-dir "$OUT"
uv export --frozen --no-dev --no-emit-project --no-header --format requirements-txt \
  -o "$OUT/requirements.txt"
git archive --format=tar.gz --prefix=jt-oz-bridge-src/ -o "$OUT/jt-oz-bridge-src.tar.gz" HEAD
```

GitHub の各リリースには wheel と `jt-oz-bridge-<version>.sbom.cdx.json`、`SHA256SUMS` が付いています。その wheel と SBOM を組にしてインストールしてください。自分でビルドした wheel の場合は、同じチェックアウトで先にテストを実行し（非 root ユーザーで）、そこから SBOM を作成します。

```sh
uv sync --locked --python 3.13
uv run --no-sync python -m scripts.make_sbom --uv uv \
  --wheel "$OUT/jt_oz_bridge-$VERSION-py3-none-any.whl" \
  --output "$OUT/jt-oz-bridge-$VERSION.sbom.cdx.json"
```

実行環境に、ロックされた実行時依存パッケージがそのバージョンどおりにインストールされていなければ、`make_sbom` は失敗します。

### 5.1 オンラインのターゲット

チェックサムを書き出し、ディレクトリをターゲットにコピーします。

```sh
(cd "$OUT" && sha256sum *.whl requirements.txt *.sbom.cdx.json *.tar.gz > SHA256SUMS)
```

### 5.2 オフライン（エアギャップ）バンドル

接続できるマシンで、**ターゲット**のプラットフォームと Python 向けに、すべての依存パッケージの wheel もダウンロードします。ダウンロード時に `requirements.txt` のハッシュが強制的に照合されます。

```sh
uv venv --seed --python 3.13 ../dl-tools        # a throwaway venv that has pip
mkdir "$OUT/wheels"
../dl-tools/bin/python -m pip download --require-hashes --only-binary=:all: \
  --implementation cp --python-version 3.13 --abi cp313 --abi abi3 --abi none \
  --platform manylinux_2_28_x86_64 --platform manylinux_2_17_x86_64 \
  --platform manylinux2014_x86_64 --platform any \
  -r "$OUT/requirements.txt" -d "$OUT/wheels"
```

`manylinux_2_28` の wheel には、ターゲット側に glibc 2.28 以降が必要です。ほかのアーキテクチャでは、プラットフォームタグの `x86_64` を置き換えてください（未検証）。

ターゲットに Python 3.13 や `uv` がない場合は、それらも持ち込みます。次のコマンドは実行したマシン自身のものを取得するため、ターゲットと同じアーキテクチャのマシンで実行してください。

```sh
uv python install 3.13 --install-dir ../py313
tar -C ../py313 -czf "$OUT/cpython-3.13-linux-x86_64.tar.gz" .
cp "$(command -v uv)" "$OUT/uv"
```

最後にすべてのファイルのチェックサムを書き出し、承認された媒体でディレクトリをターゲットへ運びます。

```sh
(cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
```

バンドルの内容は次のとおりです。

```text
jt-oz-bridge-<version>/
├── jt_oz_bridge-<version>-py3-none-any.whl
├── requirements.txt                    # hash-locked runtime dependencies
├── jt-oz-bridge-<version>.sbom.cdx.json
├── jt-oz-bridge-src.tar.gz             # config.example.toml, ops/server/ units and helpers
├── wheels/                             # dependency wheels for the target
├── cpython-3.13-linux-x86_64.tar.gz    # optional
├── uv                                  # optional
└── SHA256SUMS
```

Python 3.13 のないオフラインのターゲットでは、第 4 節のオンライン用コマンドの代わりに、持ち込んだ Python を共有ディレクトリに展開します。

```sh
install -d -m 755 /opt/jt-oz-bridge/python
tar -xzf cpython-3.13-linux-x86_64.tar.gz -C /opt/jt-oz-bridge/python
chmod -R go+rX /opt/jt-oz-bridge/python
PY=$(echo /opt/jt-oz-bridge/python/cpython-3.13.*/bin/python3.13)
```

## 6. リリースのインストール

ターゲット上で、コピーしたリリースディレクトリに移動します。

```sh
cd /path/to/jt-oz-bridge-<version>
sha256sum -c SHA256SUMS
VERSION=0.1.0
WHEEL=jt_oz_bridge-$VERSION-py3-none-any.whl
SHA=$(sha256sum "$WHEEL" | cut -d' ' -f1)
R=/opt/jt-oz-bridge/releases/$SHA
test ! -e "$R"            # a release directory is never reused
install -d -m 755 "$R"
cp "$WHEEL" requirements.txt "jt-oz-bridge-$VERSION.sbom.cdx.json" SHA256SUMS "$R/"
```

**オンライン**の場合は、固定された依存パッケージをインストールしてから、wheel を依存なしでインストールします。

```sh
uv venv --python "$PY" "$R/venv"
uv pip install --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

**オフライン**の場合は、バンドルだけからインストールします（`uv` を持ち込んだ場合は `./uv` を使います）。

```sh
uv venv --offline --python "$PY" "$R/venv"
uv pip install --offline --no-index --find-links ./wheels \
  --python "$R/venv/bin/python" --require-hashes -r "$R/requirements.txt"
uv pip install --offline --no-index --python "$R/venv/bin/python" --no-deps "$R/$WHEEL"
```

`uv` の代わりに `pip` を使う場合、venv の作成を含めた同じオフラインインストールは次のとおりです。

```sh
"$PY" -m venv "$R/venv"
"$R/venv/bin/pip" install --no-index --find-links ./wheels --require-hashes -r "$R/requirements.txt"
"$R/venv/bin/pip" install --no-index --no-deps "$R/$WHEEL"
```

続いてリリースをサービスグループに渡し、ホスト上で CLI を使えるようにします。

```sh
chown -R root:jtoz "$R"
chmod -R go+rX "$R"
ln -sfn "$R/venv/bin/jt-oz-bridge" /usr/local/bin/jt-oz-bridge
```

## 7. SBOM の検証

SBOM は、この wheel そのものを指し、リリースの venv に実際にインストールされたサードパーティのパッケージと完全に一致していなければなりません。

```sh
F=$(mktemp)
uv pip freeze --python "$R/venv/bin/python" | grep -v '^jt-oz-bridge' > "$F"
"$R/venv/bin/python" -I - "$R/jt-oz-bridge-$VERSION.sbom.cdx.json" "$SHA" "$F" <<'PY'
import json, re, sys
bom = json.load(open(sys.argv[1]))
assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
assert bom["metadata"]["component"]["hashes"] == [{"alg": "SHA-256", "content": sys.argv[2]}], "wheel hash"
norm = lambda name: re.sub(r"[-_.]+", "-", name).lower()
listed = {(norm(c["name"]), c["version"]) for c in bom["components"]}
frozen = {(norm(a), b) for a, b in (l.strip().split("==") for l in open(sys.argv[3]) if l.strip())}
assert listed == frozen, (sorted(listed - frozen), sorted(frozen - listed))
print("SBOM matches:", len(listed), "components and the wheel hash")
PY
rm -f "$F"
```

pip で作成した venv では、`uv pip freeze` の行を `"$R/venv/bin/pip" freeze` に置き換えてください。

## 8. 設定

ソースアーカイブを一時的な場所に展開し、設定例から始めます。

```sh
tar -xzf jt-oz-bridge-src.tar.gz            # creates ./jt-oz-bridge-src/
install -o root -g jtoz -m 640 jt-oz-bridge-src/config.example.toml /etc/jt-oz-bridge/config.toml
```

最初の起動では鍵の参照だけを変更し、連携はすべて無効のままにします。

```toml
[app]
state_dir = "/var/lib/jt-oz-bridge"
bind_host = "127.0.0.1"
bind_port = 8765

[database]
url = "sqlite+aiosqlite:////var/lib/jt-oz-bridge/bridge.db"

[security]
secret_key_ref = "file:/etc/jt-oz-bridge/secrets/master.key"
```

シークレットの参照は `env:NAME` または `file:/absolute/path` の形式です。シークレットファイルは通常のファイル（シンボリックリンク不可）で、所有者がサービスユーザー、所有者だけが読める（モード 600）、64 KiB 以下でなければなりません。未知の設定キーは拒否されます。`JTOZ__SECTION__FIELD` 環境変数で個々の設定を上書きできます。

サービスユーザーとして設定ファイルを検証し（接続も認証情報の解決も行いません）、暗号鍵を一度だけ作成し、データベースを作成します。

```sh
B="runuser -u jtoz -- $R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml"
$B validate
$B generate-key --secret-output /etc/jt-oz-bridge/secrets/master.key
$B migrate
```

`generate-key` は既存のファイルを上書きせず、鍵を表示することもありません。**今すぐ鍵を別にバックアップしてください**（例：オフラインの媒体）。鍵がなければデータベースもバックアップも読めず、また鍵をバックアップと一緒に保管してはいけません。`migrate` は明示的に実行するもので、繰り返し実行できます。`serve` はマイグレーションされていないデータベースを拒否し、root での実行も拒否します。

## 9. サービスのインストールと起動

メインのユニットをインストールし、drop-in でリリースを指定します。以後のアップグレードでは drop-in だけを変更します。

```sh
SRC=jt-oz-bridge-src/ops/server
install -m 644 "$SRC/jt-oz-bridge.service" /etc/systemd/system/
install -d -m 755 /etc/systemd/system/jt-oz-bridge.service.d
cat > /etc/systemd/system/jt-oz-bridge.service.d/50-release.conf <<EOF
[Service]
ExecStart=
ExecStart=$R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml serve
EOF
systemctl daemon-reload
systemctl enable --now jt-oz-bridge
```

このユニットは `jtoz` として capability なしで動作し、`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome=true` を有効にし、書き込みは `/var/lib/jt-oz-bridge` のみ、メモリ上限は 1 GiB です。ユニットは `jt-opencode-owner.service` と停止通知ユニット（第 12 節）を参照していますが、それらが未インストールの間は systemd が注意を記録するだけです。

## 10. スモークチェック

```sh
systemctl is-active jt-oz-bridge
systemctl show jt-oz-bridge -p NRestarts -p ExecStart
curl -s http://127.0.0.1:8765/healthz     # {"status":"alive"}
curl -s http://127.0.0.1:8765/readyz      # {"ready":true,"mode":"foundation","agent_consumers":false}
journalctl -u jt-oz-bridge --since -5min -p warning --no-pager
```

`foundation` は、サービス、設定、鍵、データベースは動作しているが、連携はまだ何も動いていない状態を表します。データベースやランタイムの準備ができていない間、`/readyz` は 503 と `"ready":false` を返します。1 つ目のサービスがリースを保持している間、2 つ目のインスタンスは拒否されます。

## 11. Zulip と OpenCode の接続

プロジェクトは 1 つずつ、使い捨てのものから始めてください。詳しい手順は [Operations](OPERATIONS_SOP.md)（英語）にあります。

### Zulip

1. Zulip で **generic bot** を作成します（個人設定 → ボット → 新しいボットを追加）。管理者権限は与えないでください。
2. API キーを、コマンドラインに出さずに保存します。

   ```sh
   runuser -u jtoz -- sh -c 'umask 077; cat > /etc/jt-oz-bridge/secrets/zulip-api-key'
   # paste the key, press Enter, then Ctrl-D
   ```

3. 履歴を保護した**プライベート**チャンネルを作成します。Bot と、そのチャンネルが扱うプロジェクトを使ってよい人だけを追加してください。チャンネルのメンバーは全員そのトピックを読めます。
4. それらの人の数値のユーザー ID とチャンネル ID を控えます（各プロフィールとチャンネル設定に表示されます）。
5. `[[zulip_realms]]` で `enabled = true`、`url`、`bot_email`、`api_key_ref = "file:/etc/jt-oz-bridge/secrets/zulip-api-key"`、`allowed_user_ids`、`allowed_channel_ids` を設定します。`request_budget` は Zulip サーバーがその Bot に適用するレート制限より低くしてください。

### OpenCode

1. OpenCode は専用のアカウントですでに動作し、ループバックで待ち受けている必要があります（例：`opencode serve --hostname 127.0.0.1 --port 4096`。`ops/server/opencode.service` はユニットの例です）。ブリッジの設定作業の一環として OpenCode を再起動させないでください。
2. `[[opencode_backends]]` で `enabled = true`、`base_url` を設定し、サーバーが認証を求める場合は `credential_ref` を `file:` 参照で設定します。`[[projects]]` にはプロジェクトとそのワークスペースディレクトリを記述します。
3. どの OpenCode プロセス、データセット、ディレクトリが本物かを証明する、読み取り専用の補助サービスをインストールします。`ops/server/owner-probe.py` と `directory-probe.py` を `/opt/jt-oz-bridge/` にコピーし、`jt-opencode-owner.socket`／`.service` と `jt-opencode-directory.socket`／`.service` をインストールして、両方のサービスの `User=`／`Group=` を OpenCode を動かしているアカウントに変更します。ソケットは、JSON 設定（登録手順で作成されます）ができてから有効にします。
4. `ops/server/onboard_root.py`（`prepare`、`directory`、`probe`、`cleanup`、`seal`）でプロジェクトを登録します。手順は [Operations: onboard a project](OPERATIONS_SOP.md#onboard-a-project)（英語）にあります。読み取り専用のリクエストと管理されたテストファイルで既存のセッションを 1 つ証明し、封印された設定、ランタイムの登録情報、ローカルオブザーバーのポリシーを書き出します。OpenCode のデータベースを開くことも、OpenCode を再起動することもありません。
5. ブリッジを停止した状態で、封印された設定を使ってサービスユーザーとして `enroll-runtime` を実行し、封印されたファイルを配置して、再び起動します。

   ```sh
   systemctl stop jt-oz-bridge
   runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config <sealed config> enroll-runtime
   # install the sealed config.toml and local-observer.json into /etc/jt-oz-bridge/
   systemctl start jt-oz-bridge
   curl -s http://127.0.0.1:8765/readyz      # expect "mode":"managed","agent_consumers":true
   ```

6. `jt-oz-bridge sessions` と `doctor` のためにローカルオブザーバーをインストールします。`jt-oz-observer.service` に、第 9 節と同じ形の drop-in `/etc/systemd/system/jt-oz-observer.service.d/50-release.conf` を追加します（空の `ExecStart=` の後に `ExecStart=$R/venv/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml observe-serve --policy /etc/jt-oz-bridge/local-observer.json`）。有効化し、起動は `/readyz` が準備完了を返してからにしてください。
7. Zulip のチャンネルで新しいトピックを作り、何か入力します。会話を選び、タスクを入力します。

## 12. 任意のユニット

**停止と復帰の通知。** `ops/server/bridge_notice.py` を `/opt/jt-oz-bridge/bridge-notice.py` に、`bridge_standby.py` を `/opt/jt-oz-bridge/bridge-standby.py` にコピーし、`jt-oz-bridge-notice.service`、`jt-oz-bridge-standby.service`、`jt-oz-bridge-recovered.service`、`jt-oz-bridge-recovered.timer` をインストールしてから、次を実行します。

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/bridge-notice.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-bridge-recovered.timer
```

systemd がブリッジの再起動をあきらめると、最初に許可されたチャンネル（トピック `Bridge 狀態`）に通知が 1 件投稿され、standby が各トピックに 1 回だけ返信し、`/readyz` が再び準備完了になるとタイマーが「復帰」通知を 1 件投稿します。これらのスクリプトは Python の標準ライブラリだけを使い、root としてブリッジの設定とシークレットを読みます。

**リリース監視（任意）。** `ops/server/release_watch.py` を `/opt/jt-oz-bridge/release-watch.py` にコピーし、`jt-oz-release-watch.service` と `jt-oz-release-watch.timer` をインストールしてから、次を実行します。

```sh
/usr/bin/python3 -I /opt/jt-oz-bridge/release-watch.py --dry-run   # prints, sends nothing
systemctl daemon-reload
systemctl enable --now jt-oz-release-watch.timer
```

1 日 1 回、GET だけで稼働中の Zulip のバージョン、GitHub で公開されている Zulip のリリース一覧、OpenCode の更新情報を確認し、新しいリリースごとに 1 回だけ `Bridge 狀態` に投稿して、このブリッジが受け入れるかどうかを書きます。何もインストールしません。Zulip をアップグレードする前に `ops/server/check_zulip_upgrade.py` を実行してください（運用 SOP を参照）。

**管理コンソール。** `runuser -u jtoz -- "$R/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml bootstrap-admin --username admin` は、初回ログイン時に変更が必要なワンタイムパスワードを表示します。コンソールは Secure Cookie を使うため、HTTPS のリバースプロキシと `admin.public_url` が必要です。ブリッジ自体はループバックのままにしてください。

## 13. トラブルシューティング

| 症状 | 確認すること |
|---|---|
| `Configuration/operation rejected` | `jtoz` として `validate` を実行します。第 2 節のパス、所有者、モードを確認してください。シークレットファイルはモード 600 で所有者が `jtoz` である必要があります。このメッセージは入力値をあえて表示しません。 |
| サービスがすぐに終了する | `journalctl -u jt-oz-bridge -n 50`。このリリースで `migrate` を実行しましたか。インタープリターは `/root` と `/home` の外にありますか。 |
| `/readyz` が 503 | データベース、リース、ランタイムのいずれかがまだ準備できていません。journal を確認してください。登録後は `jt-oz-bridge doctor` が不足している部分を示します。 |
| `pip download` で wheel が見つからない | その依存パッケージにはそのプラットフォームタグの wheel がありません。正しい `--platform` タグを追加するか、ターゲットと同じプラットフォームのマシンで wheel をビルドしてください。 |
| `--require-hashes` が失敗する | ファイルがロックと一致していません。このオプションを外さず、公式のインデックスからファイルを取得し直してください。 |

次へ：[アップグレード](UPGRADE_ja.md) · [アンインストール](UNINSTALL_ja.md) · [Operations](OPERATIONS_SOP.md)（英語）
