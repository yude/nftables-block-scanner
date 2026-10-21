# nftables-block-scanner

[OpenFilters/internet-scanners](https://github.com/OpenFilters/internet-scanners) の `cidr/` を取得し、公開インターフェースから来る送信元 IP を nftables で遮断するツールです。Docker と Tailscale が作るテーブルやチェーンは変更しません。Python 3、Git、nftables、systemd を使用します。

## 仕組み

- HTTPS で上流を shallow clone し、CIDR ファイル名、件数、IP の種類、公開アドレス、最小プレフィックス長を検証します。ホストビットの付いた CIDR は正規化します。
- 重複・包含・隣接範囲を統合し、直前に適用した一覧と比較します。変更が大きいと自動適用を止めます。
- 専用の `inet nftables_block_scanner` テーブルだけを nftables の単一バッチで置き換えます。`prerouting` の priority `-150` で判定するため、Docker の公開ポートの DNAT より前に遮断できます。明示したインターフェースからの入力だけに適用します。
- 取得または検証に失敗すると、稼働中のフィルターを変更しません。再起動直後で専用テーブルがない場合は、最後に正常適用した一覧を `state_dir` から復元します。

## 遮断範囲

- `interfaces` に指定したインターフェースから入るパケットの**送信元 IP**がリストの CIDR に含まれる場合、宛先ポートやプロトコルを問わず `drop` します。ホスト上のサービスに加え、Docker の公開ポート宛ても対象です。
- `tailscale0` や Docker ブリッジから入るパケットは対象外です。ただし、Tailscale の暗号化された外側の通信が指定インターフェースへ到着し、その送信元 IP がリストに含まれる場合、その通信は遮断されます。
- ロードバランサーやプロキシで送信元 IP が書き換わる場合は、ホストで実際に見える送信元 IP で判定します。リストにない送信元からの通信は、このツールでは遮断しません。

## 事前確認

`ip -brief link` と `ip route get 1.1.1.1` などで OCI の外部入力インターフェースを特定してください。**`tailscale0`、`docker0`、`br-*`、`veth*` は指定できません。** ホストに複数の外部インターフェースがある場合、実際に到達するものだけ指定します。リポジトリには調査・測定組織も含まれるため、遮断するとその組織からの正当なアクセスも失われます。

## 導入

1. `config.example.json` を `/etc/nftables-block-scanner.json` にコピーし、`interfaces` を実際の外部入力インターフェースに編集します。`state_dir` は root のみが書き込める場所にします。
2. `nftables_block_scanner.py` を `/usr/local/libexec/nftables-block-scanner` にインストールし、実行権限を付けます。
3. `python3 /usr/local/libexec/nftables-block-scanner` で dry run を確認します。`--from-dir /path/to/checkout` でオフラインの一覧も検査できます。
4. 初回だけ `sudo /usr/local/libexec/nftables-block-scanner --apply` を実行し、`sudo nft list table inet nftables_block_scanner` でルールと入力インターフェースを確認します。Docker 公開ポート、ホストの公開サービス、Tailscale の疎通を実際に試してください。
5. `systemd/` の 2 ファイルを `/etc/systemd/system/` にコピーし、`systemctl daemon-reload && systemctl enable --now nftables-block-scanner.service nftables-block-scanner.timer` を実行します。起動時と約 6 時間ごとに更新します。

旧名 `internet-scanner-blocker` から移行する場合は、新しい設定・サービスを導入して `inet nftables_block_scanner` テーブルへの適用と疎通を確認してから、旧 timer を無効化し、旧 `inet internet_scanner_blocker` テーブルを削除してください。新旧のテーブルが一時的に共存しても、互いのルールは変更しません。

`systemd` のサービスが起動時に適用し、上流へ接続できなくても最後に正常適用したリストを復元します。`/etc/nftables.conf` が `flush ruleset` を実行するホストで、**`nftables.service` を手動再読込した直後にも遮断を維持したい場合**、初回の正常適用後に `/etc/nftables.conf` の末尾へ次の行を追加してください。ファイルの存在を確認し、`nft -c -f /etc/nftables.conf` で検証してから再読込します。更新時には `active.nft` が原子的に置き換わります。

```nft
include "/var/lib/nftables-block-scanner/active.nft"
```

`state_dir` を変更した場合は include パスも合わせて変更します。`nftables.service` の `ProtectHome=true` により、状態ファイルをホームディレクトリには置かないでください。`flush ruleset` が実行されると Docker/Tailscale の動的ルールにも影響し得るため、このツールのために `nftables.service` の再読込を行う必要はありません。

## 運用

- 差分確認: `python3 nftables_block_scanner.py --config config.json`
- 手動更新: `sudo /usr/local/libexec/nftables-block-scanner --apply`
- 大量変更の承認後に適用: `sudo /usr/local/libexec/nftables-block-scanner --apply --accept-large-change`
- ログ: `journalctl -u nftables-block-scanner.service`
- 停止: `systemctl disable --now nftables-block-scanner.timer nftables-block-scanner.service`。必要なら `nft delete table inet nftables_block_scanner` を実行し、`/etc/nftables.conf` の include 行も削除します。

検証には `python3 -m unittest discover -s tests -v` を使います。OCI 側の Security List/NSG の許可ルールや、Tailscale のアクセス制御は別途有効です。
