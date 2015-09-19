ISUCON
==================================

ISUCONのめも

## MySQL

[MySQL :: MySQL 5.1 リファレンスマニュアル :: 4.10.6 ログ ファイルの保守](http://dev.mysql.com/doc/refman/5.1/ja/log-file-maintenance.html)

    grant all privileges on wordpress.* to 'wp_user'@'localhost' identified by 'wp_pass' with grant option;

### mysqldump

    mysqldump -uroot データベース名 > dump.sql
    mysql -uroot データベース名 < dump.sql

### Slow Query

#### 有効にする

```
SET GLOBAL slow_query_log = 1;
show variables like '%slow%';
SET GLOBAL slow_query_log_file = '/tmp/mysql-slow.log';
SET GLOBAL long_query_time = 0.0;
show variables like 'long%';
FLUSH LOGS;
```

#### 無効にする

```
SET GLOBAL slow_query_log = 0;
```

#### pt-query-digest

[Download the Latest Percona Toolkit for Debian and RPM Packages](http://www.percona.com/downloads/percona-toolkit/LATEST/)

    yum localinstall -y http://percona.com/get/percona-toolkit.rpm

（依存も入るけど`sudo yum install -y perl-DBI perl-DBD-MySQL perl-Time-HiRes`で自前で入れることもできる）

Ubuntuなら`aptitude install percona-toolkit`

## tmpfs

`/etc/fstab`

```
tmpfs  /mnt/tmpfs  tmpfs  defaults,size=8G  0  0
```

## sysctl.conf

`sysctl -p` で適用

  * cannot assign requested はローカルポート
  * ip_conntrack: table full, dropping packet (`/var/log/messages`)

## nginx

[Ruby - ltsv access log summary tool - Qiita](http://qiita.com/edvakf@github/items/3bdd46b53d65cf407fa2)

`parse.rb`を使う

```
cat access.log | ruby parse.rb --since='2015-10-05T02:23' | gist -p
```

`path = log[:path]` を gsub で適当に縮める
（例：`log[:path].gsub(/memo\/(\d+)/, 'memo/:id').gsub(/recent\/(\d+)/, 'recent/:id')`）

`nginx -V` で configure オプション確認

`/home/isucon` の権限を 755 にすること

### OpenResty

```
sudo aptitude install libreadline-dev libncurses5-dev libpcre++-dev libssl-dev perl make build-essential
./configure --with-pcre-jit --with-luajit --with-http_gzip_static_module
```

## ulimit

`too many open files` はファイルディスクリプタ

[ulimitが効かない不安を無くす設定 | 外道父の匠](http://blog.father.gedow.net/2012/08/08/ulimit-configuration/)

`ulimit -n 65536` が一番良さそう

```/etc/security/limits.conf
isucon hard nofile 65535
isucon soft nofile 65535
```

## gzip

    gzip -r js css
    gzip -k index.html

## supervisord

    sudo supervisorctl status
    sudo supervisorctl reload

環境変数を渡したいとき

```
environment=MARTINI_ENV="production",PORT="8080"
```

## netstat

```
sudo netstat -tlnp
sudo netstat -tnp | grep ESTABLISHED
```

## lsof

```
sudo lsof -nP -i4TCP -sTCP:LISTEN
sudo lsof -nP -i4TCP -sTCP:ESTABLISHED
```

## go

### Martini でログを吐かない

`MARTINI_ENV=production` ではログは消えない

[DSAS開発者の部屋:ISUCON4 予選で workload=5 で 88000点出す方法 (lily white 参戦記)](http://dsas.blog.klab.org/archives/52171878.html)

テンプレートのパース回数が減るらしいので有効にはすべき

```go:app.go
m := martini.Classic()
devnull, err := os.Open(os.DevNull)
if err != nil {
	log.Fatal(err)
}
m.Map(log.New(devnull, "", 0))
```

本当に消したいなら martini のソースコードをいじるしかない


### UNIX domain Socket

```go:app.go
// グローバル変数にしておく
var port = flag.Uint("port", 0, "port to listen")

func init() {
	flag.Parse()
}

// 以下は main() で
sigchan := make(chan os.Signal)
signal.Notify(sigchan, syscall.SIGTERM)
signal.Notify(sigchan, syscall.SIGINT)

var l net.Listener
var err error
sock := "/tmp/server.sock"
if *port == 0 {
	ferr := os.Remove(sock)
	if ferr != nil {
		if !os.IsNotExist(ferr) {
			panic(ferr.Error())
		}
	}
	l, err = net.Listen("unix", sock)
	cerr := os.Chmod(sock, 0666)
	if cerr != nil {
		panic(cerr.Error())
	}
} else {
	l, err = net.ListenTCP("tcp", &net.TCPAddr{Port: int(*port)})
}
if err != nil {
	panic(err.Error())
}
go func() {
	// func Serve(l net.Listener, handler Handler) error
	log.Println(http.Serve(l, nil))
}()

<-sigchan
```

### Goアプリケーションの状況を見たい

  * [golang-stats-api-handler/handler.go at master · fukata/golang-stats-api-handler](https://github.com/fukata/golang-stats-api-handler/blob/master/handler.go)

## Gitでpatchファイルを生成する

    git diff --no-prefix HEAD > ~/thisis.patch
    patch --dry-run -p0 < thisis.patch
    patch -p0 < thisis.patch

## おまじない集

### dstat

    dstat -tlamp

これに cpu の状況を確認したいなら `--top-cpu-adv`，IO を確認したいなら `--top-io-adv` でブロッキング IO を確認したいなら `--top-bio-adv` を付ける

### rsync

    rsync -vau -e 'ssh -c arcfour256' /hoge/fuga/ catatsuy.org:/hoge/fuga/

ディレクトリの最後には必ず `/` を付ける

### netstat

    netstat -tlnp

tcp の通信だけ見れる

### 参考 URL

  * [にひりずむ::しんぷる - ngrep 便利！](http://blog.livedoor.jp/xaicron/archives/54419469.html)
  * [dstatの便利なオプションまとめ - Qiita](http://qiita.com/harukasan/items/b18e484662943d834901)
  * [Linux - rsync したいときの秘伝のタレ - Qiita](http://qiita.com/catatsuy/items/66aa402cbb4c9cffe66b)
