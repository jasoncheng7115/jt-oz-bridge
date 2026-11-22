# jt-oz-bridge のアンインストール

[English](UNINSTALL.md) · [繁體中文](UNINSTALL_zh-tw.md) · 日本語 · [インストール](INSTALL_ja.md) · [アップグレード](UPGRADE_ja.md) · [概要](../README_ja.md)

[インストール](INSTALL_ja.md)の手順で構築したホストから、ブリッジとそのユニット、リリース、状態、設定、サービスユーザーを削除します。OpenCode には触れず、Zulip のものも何も削除しません。コマンドは root シェルで実行してください。手順 1 と 5 は任意ですが、状態と鍵の削除は元に戻せません。

## 1. 必要なものを残す（任意）

ブリッジを停止した状態で最後のスナップショットを取り、暗号鍵はそれとは**別に**保管します。鍵がなければスナップショットは読めません。

```sh
systemctl stop jt-oz-observer jt-oz-bridge
install -d -o jtoz -g jtoz -m 700 /var/backups/jt-oz-bridge
runuser -u jtoz -- /usr/local/bin/jt-oz-bridge --config /etc/jt-oz-bridge/config.toml \
  backup --output "/var/backups/jt-oz-bridge/final-$(date +%Y%m%d-%H%M%S)"
```

`/etc/jt-oz-bridge/` のうち残したいもの（設定、ランタイムの登録情報、オブザーバーのポリシー）と `/etc/jt-oz-bridge/secrets/master.key` も、スナップショットとは別の保護された場所にコピーしてください。

## 2. すべてのユニットを停止して無効化

```sh
systemctl disable --now jt-oz-observer.service jt-oz-bridge.service
systemctl disable --now jt-oz-bridge-recovered.timer 2>/dev/null || true
systemctl disable --now jt-oz-release-watch.timer 2>/dev/null || true
systemctl disable --now jt-opencode-owner.socket jt-opencode-directory.socket 2>/dev/null || true
systemctl stop jt-oz-bridge-standby.service jt-oz-bridge-notice.service jt-oz-bridge-recovered.service \
  jt-opencode-owner.service jt-opencode-directory.service 2>/dev/null || true
systemctl list-units --all 'jt-oz-*' 'jt-opencode-*'      # nothing should be active
```

オーナー、ディレクトリ、プロキシの補助サービスを止めても OpenCode 自体には影響しません。停止通知のタイマーはブリッジを削除する前に無効化してください。そうしないと、存在しないサービスを確認し続けます。

## 3. ユニットと drop-in の削除

```sh
cd /etc/systemd/system
rm -f jt-oz-bridge.service jt-oz-observer.service \
  jt-oz-bridge-notice.service jt-oz-bridge-standby.service \
  jt-oz-bridge-recovered.service jt-oz-bridge-recovered.timer \
  jt-oz-release-watch.service jt-oz-release-watch.timer \
  jt-opencode-owner.service jt-opencode-owner.socket \
  jt-opencode-directory.service jt-opencode-directory.socket
rm -rf jt-oz-bridge.service.d jt-oz-observer.service.d
systemctl daemon-reload
systemctl reset-failed
```

`jt-opencode-*` の補助サービスは、このホストにそれを使うほかのブリッジがない場合にだけ削除してください。`opencode.service` とその drop-in は OpenCode のものなので、そのままにします。

## 4. プログラムの削除

```sh
rm -f /usr/local/bin/jt-oz-bridge
rm -rf /opt/jt-oz-bridge          # releases, venvs, helper scripts and the shared Python, if installed there
```

各リリースディレクトリは自己完結しており（それぞれの wheel、venv、SBOM）、ホストに `pip` や `uv` でシステム全体にインストールしたものはありません。`uv` をブリッジのためだけに入れた場合は、入れたときの方法で削除してください。

## 5. 状態、設定、シークレットの削除

何かを残す場合は、手順 1 を終えてから実行します。

```sh
rm -rf /var/lib/jt-oz-bridge                  # bridge.db, WAL files, encrypted artifacts
rm -rf /var/lib/jt-oz-bridge-notice           # stop-notice state, if installed
rm -rf /var/lib/jt-oz-release-watch           # release-watch state, if installed
rm -rf /var/lib/jt-oz-bridge-recovery         # held restores, if any
rm -rf /etc/jt-oz-bridge                      # config.toml, enrollment, observer policy, secrets/
rm -f /etc/opencode-owner-probe.json /etc/opencode-directory-probe.json
```

削除したファイルをディスクから復元できるかどうかは、ストレージ（SSD、スナップショット、コピーオンライトのファイルシステム）によって異なります。重要であれば、削除に頼らず手順 7 の認証情報のローテーションを行ってください。`/var/backups/jt-oz-bridge*` のバックアップは保存ポリシーに従って扱ってください。

## 6. サービスユーザーの削除

```sh
userdel jtoz
getent group jtoz && groupdel jtoz
find / -xdev \( -user jtoz -o -group jtoz \) -print 2>/dev/null | head
```

最後のコマンドは何も出力しないはずです。登録時にオブザーバーのソケットやプロジェクトディレクトリへ POSIX ACL を追加した場合は、確認して削除してください。

## 7. Zulip と OpenCode

どちらでも自動的に削除されるものはありません。

| 場所 | 残るもの | 必要に応じて行うこと |
|---|---|---|
| Zulip | Bot アカウントとその API キー、プライベートチャンネル、すべてのトピックとメッセージ、アップロードされたファイル、ブリッジの通知 | Bot を無効化して（個人設定 → ボット）API キーを使えなくする。保存ポリシーに従ってチャンネルやトピックをアーカイブまたは削除する |
| OpenCode | すべてのセッション（チャットから作成や fork した会話も、恒久的な OpenCode セッションです）、その履歴、エージェントがプロジェクトディレクトリに作成したファイル、OpenCode の設定 | 必須の作業はありません。チャットから作成したセッションを見直し、不要なら OpenCode で削除する |
| OpenCode の認証情報 | ブリッジが OpenCode API に使ったパスワードやトークン | ブリッジ専用の認証情報があったならローテーションする |
| ネットワーク | 管理コンソールや OpenCode の中継のために追加したリバースプロキシやファイアウォールのルール | 削除する |

## 8. 確認

```sh
systemctl list-unit-files 'jt-oz-*' 'jt-opencode-*'   # no units
ss -ltnp | grep -w 8765                               # no listener
systemctl is-active opencode                          # OpenCode still running, untouched
```
