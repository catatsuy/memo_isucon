ISUCON
==================================

    curl -L https://raw.githubusercontent.com/catatsuy/dotfiles_isucon/master/quick.sh | bash
    # not installed curl
    wget -O - https://raw.githubusercontent.com/catatsuy/dotfiles_isucon/master/quick.sh | bash

`screen -S catatsuy -c ~/.screenrc_catatsuy`


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


## sysctl.conf

`sysctl -p` で適用

## nginx

[Ruby - ltsv access log summary tool - Qiita](http://qiita.com/edvakf@github/items/3bdd46b53d65cf407fa2)

`path = log[:path]` を gsub で適当に縮める
（例：`log[:path].gsub(/memo\/(\d+)/, 'memo/:id').gsub(/recent\/(\d+)/, 'recent/:id')`）

`nginx -V` で configure オプション確認

`/home/isucon` の権限を 755 にすること


## go

### Martini でログを吐かない

`MARTINI_ENV=production` ではログは消えない

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

// 以下は main() で
flag.Parse()

sigchan := make(chan os.Signal)
signal.Notify(sigchan, os.Interrupt)
signal.Notify(sigchan, syscall.SIGTERM)
signal.Notify(sigchan, syscall.SIGINT)

var l net.Listener
var err error
sock := "/dev/shm/server.sock"
if *port == 0 {
	ferr := os.Remove(sock)
	if ferr != nil {
		if !os.IsNotExist(ferr) {
			panic(ferr.Error())
		}
	}
	l, err = net.Listen("unix", sock)
	os.Chmod(sock, 0777)
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
