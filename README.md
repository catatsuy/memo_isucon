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
