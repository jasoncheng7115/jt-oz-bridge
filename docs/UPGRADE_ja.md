# jt-oz-bridge のアップグレード

[English](UPGRADE.md) · [繁體中文](UPGRADE_zh-tw.md) · 日本語 · [インストール](INSTALL_ja.md) · [アンインストール](UNINSTALL_ja.md) · [概要](../README_ja.md)

アップグレードでは、新しいリリースを稼働中のリリースの**隣に**インストールし、ブリッジ自身のデータベースをバックアップしてマイグレーションし、systemd の drop-in でサービスを切り替え、準備完了を確認し、ロールバックに備えて前のリリースを残します。手順はオンラインでもオフラインでも同じで、違うのはリリースファイルの届け方だけです。

OpenCode はブリッジのアップグレードに一切含まれません。ここで停止、再起動、アップグレードをしないでください。ブリッジが止まっている間も OpenCode の作業は続き、ブリッジは復帰後に追いつきます（直近 10 分以内のメッセージは自動で送信され、それより古いものは利用者が `!go` か `!no` で答えるまで待ちます）。

レイアウトと前提は[インストール](INSTALL_ja.md)と同じです。root シェルで `umask 022` と `UV_LINK_MODE=copy`、サービスユーザー `jtoz`、リリースは `/opt/jt-oz-bridge/releases/<wheel-sha256>/`、リリースの選択は drop-in `50-release.conf` で行います。

## 始める前に

- リリースノート、または現在のリリース以降のコミットを読みます。データベースのスキーマは変わりますか。設定の変更、新しいユニット、新しい補助スクリプトは必要ですか。それより前へのロールバックができないと書かれていませんか。
- 完全なテストゲートに合格した wheel と、その SBOM を使います。
- 落ち着いた時間帯を選びます。`jt-oz-bridge sessions --active` で進行中の作業がわかります。ブリッジは 1 分ほど停止します。
- 完全なバックアップを取れるだけのディスク容量を確認します。
- 現在のリリースと OpenCode のプロセスの識別情報を控えます。

```sh
OLD=$(systemctl show jt-oz-bridge -p ExecStart --value | grep -o '/opt/jt-oz-bridge/releases/[0-9a-f]\{64\}' | head -1)
echo "$OLD"
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # use your OpenCode unit name
```

## 1. 新しいリリースを並べてインストール

新しいリリースファイルで[インストール](INSTALL_ja.md)の第 5〜7 節を実行します。オンラインでビルドまたは入手するか、オフラインバンドル（第 5.2 節）を持ち込んで `--offline --no-index --find-links ./wheels` でインストールします。`SHA256SUMS` と SBOM も同ガイドのとおり検証してください。**`ln -sfn` の行はまだ実行しません。** CLI のシンボリックリンクは手順 4 で切り替えます。

```sh
NEW=/opt/jt-oz-bridge/releases/<new wheel sha256>
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml validate
```

ここまでの作業は稼働中のサービスに一切影響しません。新しいリリースで設定の変更が必要なら、コピー（`/etc/jt-oz-bridge/config.toml.new`、`root:jtoz` 640）に書き、新しいリリースでそのコピーを検証し、現在のファイルはロールバック用に残します。リリースに変更された補助スクリプトやユニットが含まれる場合は（インストール済みのものと `cmp` で比較）、それらも準備しておきます。

## 2. ブリッジを停止してバックアップ

```sh
STAMP=$(date +%Y%m%d-%H%M%S)
C=/var/backups/jt-oz-bridge-upgrade/$STAMP
install -d -m 700 /var/backups/jt-oz-bridge-upgrade "$C"
install -d -o jtoz -g jtoz -m 700 /var/backups/jt-oz-bridge
cp -a /etc/jt-oz-bridge/config.toml /etc/systemd/system/jt-oz-bridge.service.d "$C/"
cp -a /etc/systemd/system/jt-oz-observer.service.d "$C/" 2>/dev/null || true
readlink /usr/local/bin/jt-oz-bridge > "$C/cli.before"

systemctl stop jt-oz-observer jt-oz-bridge
runuser -u jtoz -- "$OLD/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml \
  backup --output "/var/backups/jt-oz-bridge/pre-upgrade-$STAMP" | tee "$C/backup.json"
```

このバックアップは、データベース、暗号化された添付ファイル、有効な設定を含む、検証付きのスナップショットです。ブリッジが稼働中だと実行を拒否します。暗号鍵、シークレットファイル、登録ファイルは**含まれない**ため、別途バックアップしてください。出力の `schema_revision` が現在のスキーマです。

## 3. 新しいリリースでマイグレーション

```sh
runuser -u jtoz -- "$NEW/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml migrate
"$NEW/venv/bin/python" -I -c 'import sqlite3; db = sqlite3.connect("file:/var/lib/jt-oz-bridge/bridge.db?mode=ro", uri=True); print(db.execute("select version_num from alembic_version").fetchone()[0])'
```

表示されたリビジョンを `$C/backup.json` の `schema_revision` と比べます。**変わっていれば、前のリリースはこのデータベースではもう動きません。** ここから先のロールバックは、コードの切り替えだけでなく、バックアップの復元（手順 6 のケース B）を意味します。スキーマがすでに最新なら `migrate` は何もしません。PostgreSQL を使っている場合は、データベースのツールで同じ `alembic_version` テーブルを確認してください。

## 4. 切り替え

```sh
sed -i "s#$OLD#$NEW#g" /etc/systemd/system/jt-oz-bridge.service.d/50-release.conf
sed -i "s#$OLD#$NEW#g" /etc/systemd/system/jt-oz-observer.service.d/50-release.conf 2>/dev/null || true
# only if prepared in step 1:
#   install -o root -g jtoz -m 640 /etc/jt-oz-bridge/config.toml.new /etc/jt-oz-bridge/config.toml
ln -sfn "$NEW/venv/bin/jt-oz-bridge" /usr/local/bin/jt-oz-bridge
systemctl daemon-reload
systemctl start jt-oz-bridge
for i in $(seq 1 45); do curl -sf http://127.0.0.1:8765/readyz && break; sleep 2; done
systemctl start jt-oz-observer    # only after /readyz is ready; skip if not installed
```

オブザーバーは、ブリッジが準備完了を返してから起動してください。オブザーバーはマイグレーション後のスキーマを必要とし、同時に起動すると一度失敗することがあります。

## 5. スモークチェック

30 秒ほど待ってから実行します。

```sh
systemctl is-active jt-oz-bridge jt-oz-observer
systemctl show jt-oz-bridge -p NRestarts -p ExecStart      # NRestarts=0, ExecStart names $NEW
curl -s http://127.0.0.1:8765/readyz                        # "ready":true
journalctl -u jt-oz-bridge --since -2min -p warning --no-pager
systemctl show opencode -p MainPID -p NRestarts -p InvocationID   # identical to before
jt-oz-bridge doctor
```

ここで何かが失敗したら、ロールバックしてください。スモークチェックの合格はサービスが起動したことを示すだけです。使い捨てのトピックに短いメッセージを送り、チャットの経路も確認してください。

## 6. ロールバック

**ケース A：スキーマが変わっていない。** サービスを前のリリースに戻します。

```sh
systemctl stop jt-oz-observer jt-oz-bridge
cp -a "$C/jt-oz-bridge.service.d/." /etc/systemd/system/jt-oz-bridge.service.d/
test -d "$C/jt-oz-observer.service.d" && cp -a "$C/jt-oz-observer.service.d/." /etc/systemd/system/jt-oz-observer.service.d/
cp -a "$C/config.toml" /etc/jt-oz-bridge/config.toml
ln -sfn "$(cat "$C/cli.before")" /usr/local/bin/jt-oz-bridge
systemctl daemon-reload
systemctl start jt-oz-bridge
for i in $(seq 1 45); do curl -sf http://127.0.0.1:8765/readyz && break; sleep 2; done
systemctl start jt-oz-observer
```

その後、スモークチェックをやり直します。

**ケース B：スキーマが変わった。** 前のリリースはマイグレーション後のデータベースを読めません。また、古いデータベースファイルを新しいデータの上にコピーしてはいけません。選択肢は 2 つです。

1. **前に進めて修正する（推奨）。** 新しいスキーマを維持し、同じ手順で修正済みの新しいリリースをデプロイします。
2. **アップグレード前のバックアップを復元する。** 前のリリースでスナップショットを**新しい**ディレクトリに復元し、保留付きリカバリーをレビューします。復元したコピーは、レビューが終わるまですべての機能が無効、すべてのトピックが一時停止の状態で起動し、最後に `complete-restore` で完了します。アップグレード後にブリッジが記録した内容はブリッジ自身の記録から失われます（OpenCode で起きたことは OpenCode に残ります）。利用者に自分のトピックを確認してもらう必要があるかもしれません。

```sh
systemctl stop jt-oz-observer jt-oz-bridge
cp -a "$C/config.toml" /etc/jt-oz-bridge/config.toml
install -d -o jtoz -g jtoz -m 700 /var/lib/jt-oz-bridge-recovery
runuser -u jtoz -- "$OLD/venv/bin/jt-oz-bridge" --config /etc/jt-oz-bridge/config.toml \
  restore --backup "/var/backups/jt-oz-bridge/pre-upgrade-$STAMP" \
  --destination "/var/lib/jt-oz-bridge-recovery/restore-$STAMP"
```

レビューが終わったら、ケース A と同じように drop-in と CLI のシンボリックリンクを前のリリースに戻します。

リリースによっては、スキーマが変わらなくても古いリリースが再生できないデータを記録するものがあります（例：チャットから作成した会話）。その場合はリリースノートに記載されており、対処はやはり前に進めて修正することです。

## 7. 後片付け

新しいリリースが受け入れられるまでは、前のリリース、バックアップ、`$C` を残しておきます。その後、どこからも参照されていないリリースディレクトリを削除します。

```sh
grep -h ExecStart= /etc/systemd/system/jt-oz-*.service.d/*.conf
readlink /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge/releases/<old wheel sha256>     # never the active or the previous one
```

venv は作成時に使った Python へのリンクを保持しています。`/opt/jt-oz-bridge/python` に新しい Python 3.13 を入れた場合は、残っているリリースがどれも使わなくなるまで古いものを残してください（`readlink -f <release>/venv/bin/python`）。

## オフラインでのアップグレード

接続できるマシンで、[インストールの第 5.2 節](INSTALL_ja.md)とまったく同じように新しいバンドルを作成します。wheel、`requirements.txt`、SBOM、ソースアーカイブ、ターゲットのプラットフォーム向けの `wheels/`、任意で Python と `uv`、そして `SHA256SUMS` です。ターゲットでは `sha256sum -c SHA256SUMS` で検証し、`--offline --no-index --find-links ./wheels --require-hashes` で新しいリリースディレクトリにインストールし、SBOM を検証してから、上の手順 2〜7 に進みます。手順 2〜7 で、チャットでの確認以外にネットワークは必要ありません。

## OpenCode のアップグレードは別作業

同じメンテナンス時間に OpenCode をアップグレードしないでください。ブリッジは検証時の OpenCode の正確なバージョンとポリシーを固定しており、それ以外に対しては再検証されるまで起動を拒否します。OpenCode のアップグレードは `ops/server/check_native_upgrade.py` で評価してください。
