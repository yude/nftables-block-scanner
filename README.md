# internet-scanner-blocker

[OpenFilters/internet-scanners](https://github.com/OpenFilters/internet-scanners) の `cidr/` を取得し、公開インターフェースから来る送信元 IP を nftables で遮断するツールです。Docker と Tailscale が作るテーブルやチェーンは変更しません。Python 3、Git、nftables、systemd を使用します。

**未適用のソースです。** このリポジトリを作成しただけではホストの通信は変わりません。

## 仕組み

- HTTPS で上流を shallow clone し、CIDR ファイル名、件数、IP の種類、公開アドレス、最小プレフィックス長を検証します。ホストビットの付いた CIDR は正規化します。
- 重複・包含・隣接範囲を統合し、直前に適用した一覧と比較します。変更が大きいと自動適用を止めます。
- 専用の `inet internet_scanner_blocker` テーブルだけを nftables の単一バッチで置き換えます。`prerouting` の priority `-150` で判定するため、Docker の公開ポートの DNAT より前に遮断できます。明示したインターフェースからの入力だけに適用します。
- 取得または検証に失敗すると、稼働中のフィルターを変更しません。最後に正常適用した一覧と nftables スクリプトを `state_dir` に保存します。

## 事前確認

`ip -brief link` と `ip route get 1.1.1.1` などで OCI の外部入力インターフェースを特定してください。**`tailscale0`、`docker0`、`br-*`、`veth*` は指定できません。** ホストに複数の外部インターフェースがある場合、実際に到達するものだけ指定します。リポジトリには調査・測定組織も含まれるため、遮断するとその組織からの正当なアクセスも失われます。

## 導入

1. `config.example.json` を `/etc/internet-scanner-blocker.json` にコピーし、`interfaces` を実際の外部入力インターフェースに編集します。`state_dir` は root のみが書き込める場所にします。
2. `internet_scanner_blocker.py` を `/usr/local/libexec/internet-scanner-blocker` にインストールし、実行権限を付けます。
3. `python3 /usr/local/libexec/internet-scanner-blocker` で dry run を確認します。`--from-dir /path/to/checkout` でオフラインの一覧も検査できます。
4. 初回だけ `sudo /usr/local/libexec/internet-scanner-blocker --apply` を実行し、`sudo nft list table inet internet_scanner_blocker` でルールと入力インターフェースを確認します。Docker 公開ポート、ホストの公開サービス、Tailscale の疎通を実際に試してください。
5. `systemd/` の 2 ファイルを `/etc/systemd/system/` にコピーし、`systemctl daemon-reload && systemctl enable --now internet-scanner-blocker.service internet-scanner-blocker.timer` を実行します。起動時と約 6 時間ごとに更新します。

このホストの `/etc/nftables.conf` は先頭で `flush ruleset` を実行します。**再起動・`nftables.service` 再読込直後にも遮断を維持したい場合**、初回の正常適用後に `/etc/nftables.conf` の末尾へ次の行を追加してください。ファイルの存在を確認し、`nft -c -f /etc/nftables.conf` で検証してから再読込します。更新時には `active.nft` が原子的に置き換わります。

```nft
include "/var/lib/internet-scanner-blocker/active.nft"
```

`state_dir` を変更した場合は include パスも合わせて変更します。`nftables.service` の `ProtectHome=true` により、状態ファイルをホームディレクトリには置かないでください。`flush ruleset` が実行されると Docker/Tailscale の動的ルールにも影響し得るため、このツールのために `nftables.service` の再読込を行う必要はありません。

## 運用

- 差分確認: `python3 internet_scanner_blocker.py --config config.json`
- 手動更新: `sudo /usr/local/libexec/internet-scanner-blocker --apply`
- 大量変更の承認後に適用: `sudo /usr/local/libexec/internet-scanner-blocker --apply --accept-large-change`
- ログ: `journalctl -u internet-scanner-blocker.service`
- 停止: `systemctl disable --now internet-scanner-blocker.timer internet-scanner-blocker.service`。必要なら `nft delete table inet internet_scanner_blocker` を実行し、`/etc/nftables.conf` の include 行も削除します。

検証には `python3 -m unittest discover -s tests -v` を使います。OCI 側の Security List/NSG の許可ルールや、Tailscale のアクセス制御は別途有効です。
