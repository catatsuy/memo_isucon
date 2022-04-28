ISUCON
==================================

ISUCONのめも

```
curl -L https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash
# not installed curl
wget -O - https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash
```

## 作業リスト

```
## インフラ担当

* [ ] ポータルサイトにログインしてsshできることを確認
* [ ] 何もせずにベンチマークを流す
* [ ] 動作しているプロセスを確認しておおよその構成を理解する
* [ ] Go実装に切り替えてベンチマークを流す
* [ ] 必要なパッケージなどインストール
* [ ] データベースなど各アプリケーションの設定値を確認してgitにコミットする
* [ ] nginxで計測できるようにする（alpを使う）
* [ ] ハードウェアの構成を調べる
* [ ] netdata導入

## アプリケーション担当1

* [ ] 全員共通の~/.ssh/configを作る
* [ ] MySQL・画像などのバックアップを開発環境用に作成
* [ ] スキーマ一覧を共有
* [ ] 各テーブルのサイズを共有
* [ ] ローカルで開発環境を作れないか考えて、作れそうなら作る
* [ ] デプロイスクリプトを作る
* [ ] initialize の動作を確認する

## アプリケーション担当2

* [ ] ssh-keygenして鍵をdeploy keyに登録 ssh -T git@github.com
* [ ] コードをリポジトリにpushする
* [ ] キーになる関数があれば特定する
```

## MySQL

```
CREATE DATABASE `isucari`;

DROP USER IF EXISTS 'isucari'@'localhost';
CREATE USER 'isucari'@'localhost' IDENTIFIED BY 'isucari';
GRANT ALL PRIVILEGES ON `isucari`.* TO 'isucari'@'localhost';

DROP USER IF EXISTS 'isucari'@'%';
CREATE USER 'isucari'@'%' IDENTIFIED BY 'isucari';
GRANT ALL PRIVILEGES ON `isucari`.* TO 'isucari'@'%';

CREATE USER 'isucari'@'localhost' IDENTIFIED WITH mysql_native_password BY 'isucari';
```

MySQL8以降で簡単なパスワードを設定できなくなった。my.cnfで以下のようにする。

```my.cnf
validate_password.length = 0
validate_password.policy = LOW
```

my.cnfの場所は以下のように調べる。

```
$ mysql --help | grep my.cnf
                      order of preference, my.cnf, $MYSQL_TCP_PORT,
/etc/my.cnf /etc/mysql/my.cnf /usr/local/etc/my.cnf ~/.my.cnf
```

Ubuntuなら`/etc/mysql/debian.cnf`にパスワードがある。`/var/log/mysqld.log`をgrepする手もある。

`/etc/mysql/debian.cnf`を`$HOME/.my.cnf`にコピーすればパスワードをなしにアクセスできる。

日本語が入力できない場合は以下の設定をコメントアウトすると直るかも。

```
[mysql]
default-character-set=utf8mb4
[client]
default-character-set=utf8mb4
```

### mysqldump

```
mysqldump -uroot データベース名 > dump.sql
mysql -uroot データベース名 < dump.sql
```

スキーマだけを得たい場合

```
mysqldump -u root --compact --no-data データベース名 | grep -v "^SET" | grep -v "^/\*\!" | perl -ple 's@CREATE TABLE @\nCREATE TABLE @g'
```

テーブルのサイズを得る

```sql
SELECT
  table_name, engine, table_rows,
  floor((data_length+index_length)/1024/1024) AS total_mb,
  floor((data_length)/1024/1024) AS data_mb,
  floor((index_length)/1024/1024) AS index_mb
FROM
  information_schema.tables
WHERE
  table_schema=database()
ORDER BY
  (data_length+index_length) DESC;
```

### Slow Query

#### 有効にする

```
SET GLOBAL slow_query_log = 1;
# MySQL 8.0.14 above
# SET GLOBAL log_slow_extra = 1;
show variables like '%slow%';
SET GLOBAL slow_query_log_file = '/var/log/mysql/slow.log';
SET GLOBAL long_query_time = 0.0;
show variables like 'long%';
FLUSH LOGS;
```

#### 無効にする

```
SET GLOBAL slow_query_log = 0;
```

`slow_query_log`はsessionで切り替えられないので、都度無効にする場合はsession毎に`SET long_query_time = 60.0`を実行する。

#### pt-query-digest

[Download the Latest Percona Toolkit for Debian and RPM Packages](http://www.percona.com/downloads/percona-toolkit/LATEST/)

```
# RedHat
yum install percona-toolkit

# Debian
apt install percona-toolkit
```

（依存も入るけど`sudo yum install -y perl-DBI perl-DBD-MySQL perl-Time-HiRes`で自前で入れることもできる）

```
pt-query-digest --since "`date '+%F %T' -d '-5 minutes' --utc`" /var/log/mysql/slow.log | tee slowq.txt
```

`--since="5m"` みたいな設定もできるが、MySQLのタイムゾーンとOSのタイムゾーンが異なっている場合、pt-query-digest上ではOSのタイムゾーンが使われる。UTCを使いたい場合はdateコマンドを使った方が楽。

### binlog削除

```
PURGE BINARY LOGS BEFORE NOW()
```

```
SHOW GLOBAL VARIABLES LIKE 'log_bin';
```

### MySQL 8

MySQL 8はデフォルトでbinlogを出力するのですごい勢いでディスクを使う。なぜかmy.cnfでは無効にできないみたいなので `sudo systemctl status mysql` で設定ファイルを探して直接書き換える。

```
ExecStart=/usr/sbin/mysqld --disable-log-bin
```

`systemctl daemon-reload`を忘れないこと

https://dev.mysql.com/downloads/

```
[mysqld]
default-authentication-plugin = mysql_native_password
```

### MySQL Trigger

```
alter table posts add column count_comment int NOT NULL default 0

create trigger comment_insert_trigger before insert on comments for each row update posts set posts.count_comment = posts.count_comment + 1 where posts.id = NEW.post_id

create trigger comment_delete_trigger before delete on comments for each row update posts set posts.count_comment = posts.count_comment - 1 where posts.id = OLD.post_id

UPDATE posts, (select `post_id`,count(*) as `cnt` from `comments` group by `post_id`) as cc set posts.count_comment = cc.cnt where posts.id = cc.post_id

create trigger playlist_favorite_insert_trigger before insert on playlist_favorite for each row insert into playlist_favorite_count (playlist_id,count) values (NEW.playlist_id, 1) on duplicate key update playlist_favorite_count.count = playlist_favorite_count.count + 1

create trigger playlist_favorite_delete_trigger before delete on playlist_favorite for each row update playlist_favorite_count set playlist_favorite_count.count = playlist_favorite_count.count - 1 where playlist_favorite_count.playlist_id = OLD.playlist_id

INSERT INTO playlist_favorite_count (`playlist_id`, `count`) SELECT `playlist_id`,count(*) FROM `playlist_favorite` GROUP BY `playlist_id`;
```

## docker compose

```sh
docker compose build app
docker compose logs nginx --no-log-prefix --tail=10000 --since 5m
```

## tmpfs

`/etc/fstab`

```
tmpfs  /mnt/tmpfs  tmpfs  defaults,size=8G  0  0
```

`sudo mount -a`で適用

## swap

```sh
sudo fallocate -l 512m /mnt/512MiB.swap
sudo chmod 600 /mnt/512MiB.swap
sudo mkswap /mnt/512MiB.swap
sudo swapon /mnt/512MiB.swap

# 再起動しても有効にしたい場合
echo "\n/mnt/512MiB.swap  none  swap  sw  0 0" >> /etc/fstab
```

[SwapFaq - Community Help Wiki](https://help.ubuntu.com/community/SwapFaq)

## ダミーファイル作成

50MBの`/dummy`を作る。

```
sudo dd if=/dev/zero of=/dummy bs=1M count=50
```

## sysctl.conf

`sysctl -p` で適用。もしくは `sudo service procps reload`。

  * cannot assign requested はローカルポート
  * ip_conntrack: table full, dropping packet (`dmesg`)
    * 有効でない場合は `modprobe ip_conntrack`

## nginx

```sh
cat /var/log/nginx/access.log | alp ltsv -m "^/items/\d+\.json" --sort=sum --reverse --filters 'Time > TimeAgo("5m")'

cat /var/log/nginx/access.log | alp ltsv -m "^/items/\d+\.json","^/new_items/\d+\.json","/users/\d+\.json","/transactions/\d+.png","/upload/[0-9a-f]+\.jpg" --sort=sum --reverse --filters 'Time > TimeAgo("5m")' | notify_slack -snippet -filetype txt
```

https://github.com/tkuchiki/alp/blob/master/docs/usage_samples.md

キャッシュがHITしているか確認したい場合はログに `"\tcache_status:$upstream_cache_status"` を追加

### nginx-build

```
nginx-build -d work -openssl -pcre -zlib \
 --sbin-path=/usr/sbin/nginx \
 --conf-path=/etc/nginx/nginx.conf \
 --http-log-path=/var/log/nginx/access.log \
 --error-log-path=/var/log/nginx/error.log \
 --pid-path=/run/nginx.pid \
 --lock-path=/var/lock/nginx.lock \
 --http-client-body-temp-path=/var/lib/nginx/body \
 --http-proxy-temp-path=/var/lib/nginx/proxy \
 --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
 --with-debug \
 --with-pcre-jit \
 --with-http_gunzip_module \
 --with-http_gzip_static_module \
 --with-http_v2_module \
 --with-http_dav_module
```

## ulimit

systemdの方が楽。

```
[Service]
LimitNOFILE=1006500
LimitNPROC=1006500
```

`too many open files` はファイルディスクリプタ

## Ubuntu

### AppArmor

```
sudo systemctl stop apparmor
sudo systemctl disable apparmor
```

### update-notifier

update-notifierがメモリを食い潰すことがある。

```
sudo apt purge update-notifier-common
```

### snapd

snapdがメモリを食い潰すことがある。

```
sudo systemctl stop snapd
sudo systemctl disable snapd
sudo systemctl stop snapd.socket
sudo systemctl disable snapd.socket

sudo systemctl disable snap.amazon-ssm-agent.amazon-ssm-agent.service
```

## netdata

分解能1秒・設定不要・省メモリ・1時間分のデータ保持・台数制限なしのクラウドサービスあり

```
# install
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --no-updates --stable-channel

# set netdata.cloud (Add nodes to General)
sudo netdata-claim.sh -token=aaaaaa -rooms=bbbbb -url=https://app.netdata.cloud

# stop
sudo systemctl stop netdata
sudo systemctl disable netdata
```

## htop

| key | effect |
|:---:|:---:|
|  H  |  ユーザースレッド表示・非表示  |
|  K  |  カーネルスレッド表示・非表示  |
|  t  |  ツリー表示  |
|  h  |  help |
|  q  |  quit |

## gzip

```sh
gzip -r js css
gzip -k index.html
```

## ss

```sh
sudo ss -tlnp
sudo ss -tnp | grep ESTABLISHED
```

## lsof

```sh
sudo lsof -nP -i4TCP -sTCP:LISTEN
sudo lsof -nP -i4TCP -sTCP:ESTABLISHED
```

## git init

```sh
git init
git config --global user.name "isucon"
git config --global user.email "isucon@isucon"
```

```sh
git init
git config --global user.name "catatsuy"
git config --global user.email "catatsuy@catatsuy.org"
```

## ディスクが枯渇しそうなとき

```sh
sudo du -m --max-depth 2 / | sort -nr | head -10
```

## deploy

### .ssh/config

```
Host isu01
  HostName xxx
  User isucon
  Port 22
  IdentityFile ~/.ssh/id_rsa.github
  ForwardAgent yes

Host isu02
  HostName yyy
  User isucon
  Port 22
  ProxyCommand ssh isu01 nc %h %p
  ForwardAgent yes

Host *
  ServerAliveInterval 5
  ServerAliveCountMax 12
```

### deploy.sh

``` shell
## deploy.sh

#!/bin/bash

set -x

./deploy_body.sh | notify_slack

## deploy_body.sh
#!/bin/bash

set -x

echo "start deploy ${USER}"
GOOS=linux GOARCH=amd64 go build -o isucari_linux
for server in isu01 isu02; do
  ssh -t $server "sudo systemctl stop isucari.golang.service"
  scp ./isucari_linux $server:/home/isucon/isucari/webapp/go/isucari
  rsync -vau ../sql/ $server:/home/isucon/isucari/webapp/sql/
  ssh -t $server "sudo systemctl start isucari.golang.service"
done

echo "finish deploy ${USER}"
```

## go

### UNIX domain Socket

注：変数名が被りにくいように少し変な変数名にしてある。

```go
var hport int

flag.IntVar(&hport, "port", 0, "port to listen")
flag.Parse()

var li net.Listener
var herr error
hsock := "server.sock"
if hport == 0 {
	ferr := os.Remove(hsock)
	if ferr != nil {
		if !os.IsNotExist(ferr) {
			panic(ferr)
		}
	}
	li, herr = net.Listen("unix", hsock)
	cerr := os.Chmod(hsock, 0666)
	if cerr != nil {
		panic(cerr)
	}
} else {
	li, herr = net.ListenTCP("tcp", &net.TCPAddr{Port: hport})
}
if herr != nil {
	panic(herr)
}

// func Serve(l net.Listener, handler Handler) error
log.Println(http.Serve(li, nil))
```

```shell
curl --unix-socket server.sock http:/
```

### Goでインメモリキャッシュ

``` go
type cache[K comparable, V any] struct {
	// Setが多いならsync.Mutex
	sync.RWMutex
	items map[K]V
}

func NewCache[K comparable, V any]() *cache[K, V] {
	m := make(map[K]V)
	c := &cache[K, V]{
		items: m,
	}
	return c
}

func (c *cache[K, V]) Set(key K, value V) {
	c.Lock()
	c.items[key] = value
	c.Unlock()
}

func (c *cache[K, V]) Get(key K) (V, bool) {
	c.RLock()
	v, found := c.items[key]
	c.RUnlock()
	return v, found
}

type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

type Integer interface {
	Signed | Unsigned
}

type cacheInteger[K comparable, V Integer] struct {
	// Setが多いならsync.Mutex
	sync.RWMutex
	items map[K]V
}

func NewCacheInteger[K comparable, V Integer]() *cacheInteger[K, V] {
	m := make(map[K]V)
	c := &cacheInteger[K, V]{
		items: m,
	}
	return c
}

func (c *cacheInteger[K, V]) Set(key K, value V) {
	c.Lock()
	c.items[key] = value
	c.Unlock()
}

func (c *cacheInteger[K, V]) Get(key K) (V, bool) {
	c.RLock()
	v, found := c.items[key]
	c.RUnlock()
	return v, found
}

func (c *cacheInteger[K, V]) Incr(key K, value V) {
	c.Lock()
	v, found := c.items[key]
	if found {
		c.items[key] = v + value
	} else {
		c.items[key] = value
	}
	c.Unlock()
}

var mCache = NewCache[int64, string]()
var mCacheInteger = NewCacheInteger[string, int64]()
```

### Goでexpire付きのインメモリキャッシュ

```go
type expiredValue[V any] struct {
	value  V
	expire time.Time
}

type cacheExpired[K comparable, V any] struct {
	sync.RWMutex
	items map[K]expiredValue[V]
}

func NewCacheExpired[K comparable, V any]() *cacheExpired[K, V] {
	c := &cacheExpired[K, V]{
		items: make(map[K]expiredValue[V]),
	}
	return c
}

func (c *cacheExpired[K, V]) Set(key K, value V) {
	val := expiredValue[V]{
		value:  value,
		expire: time.Now().Add(80 * time.Second),
	}
	c.Lock()
	defer c.Unlock()
	c.items[key] = val
}

func (c *cacheExpired[K, V]) Get(key K) (V, bool) {
	c.RLock()
	defer c.RUnlock()
	v, found := c.items[key]
	if !found {
		var zero V
		return zero, false
	}
	if time.Now().After(v.expire) {
		var zero V
		return zero, false
	}
	return v.value, found
}

var mCacheExpired = NewCacheExpired[string, string]()
```

### Goで簡易ジョブキュー

```go
type cacheLog struct {
	// Setが多いならsync.Mutex
	sync.Mutex
	items  []isulogger.Log
	logger *isulogger.Isulogger
}

func SetLogger(d QueryExecutor) error {
	var err error
	mCacheLog.logger, err = Logger(d)

	return err
}

func SetDB(d QueryExecutor) {
	var err error
	mCacheLog.logger, err = Logger(d)
	if err != nil {
		log.Printf("[WARN] new logger failed. err:%s", err)
		panic(err)
	}

	c := time.Tick(1 * time.Second)
	go func() {
		for {
			ls := mCacheLog.Rotate()
			err := mCacheLog.logger.SendBulk(ls)
			if err != nil {
				log.Printf("[WARN] logger send failed. err:%s", err)
			}
			<-c
		}
	}()
}

var mCacheLog = NewCacheLog()

func NewCacheLog() *cacheLog {
	m := make([]isulogger.Log, 0, 100)
	c := &cacheLog{
		items: m,
	}
	return c
}

func (c *cacheLog) Append(value isulogger.Log) {
	c.Lock()
	c.items = append(c.items, value)
	c.Unlock()
}

func (c *cacheLog) Rotate() []isulogger.Log {
	c.Lock()
	tmp := c.items
	c.items = make([]isulogger.Log, 0, 100)
	c.Unlock()
	return tmp
}
```

### Go側でSQLをtraceする

```go
import (
	_ "github.com/go-sql-driver/mysql"
	proxy "github.com/shogo82148/go-sql-proxy"
)

var isDev bool
if os.Getenv("DEV") == "1" {
	isDev = true
}

var err error
if isDev {
	proxy.RegisterTracer()

	db, err = sql.Open("mysql:trace", dsn)
} else {
	db, err = sql.Open("mysql", dsn)
}
```

デフォルトだとprepare statementを実行するので、そのタイミングで`ErrSkip`が発生して余計なログが出る。
`interpolateParams=true`を使えばprepare statementを実行しなくなる。

cf: https://github.com/DataDog/dd-trace-go/issues/270

### GoでINに渡すPrepared Statementの?を生成する

```go
levels := []int{4, 6, 7}
query, args, err := sqlx.In("SELECT * FROM users WHERE level IN (?);", levels)

users := make([]User, 0, len(levels))
err = db.SelectContext(
		ctx,
		&users,
		query,
		args...,
	)
```

```go
func InStatement(count int) string {
	return strings.Repeat(",?", count)[1:]
}
```

### GoでMySQLの接続をUNIXドメインソケットにする

https://github.com/go-sql-driver/mysql

```go
// tcp
dsn := fmt.Sprintf(
	"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
	user,
	password,
	host,
	port,
	dbname,
)

cfg := mysql.NewConfig()
cfg.Net = "tcp"
cfg.Addr = "127.0.0.1:3306"

// unix domain socket
dsn := fmt.Sprintf(
	"%s:%s@unix(%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
	user,
	password,
	socket,
	dbname,
)

cfg.Net = "unix"
cfg.Addr = "/tmp/mysql.sock"
```

### GoでMySQLのコネクションを管理する

* `db.SetMaxOpenConns`はデフォルト無限なので制限する必要がある
  * ISUCONだと25くらいから調整するのがよいかも
  * `db.SetMaxIdleConns`は同じか、少し大きくすればよい
* `db.SetConnMaxIdleTime`を使えば、idleになったコネクションをいい感じに掃除してもらえる
  * https://github.com/go-sql-driver/mysql#important-settings
* 再起動試験対策で実際に接続に成功するまでfor文で待つようにすると安心
  * [アプリ起動時にDB起動を待つ](https://zenn.dev/methane/articles/020f037513cd6b701aee)

``` go
maxConns := os.Getenv("DB_MAXOPENCONNS")
maxConnsInt := 25
if maxConns != "" {
	maxConnsInt, err = strconv.Atoi(maxConns)
	if err != nil {
		panic(err)
	}
}
db.SetMaxOpenConns(maxConnsInt)
db.SetMaxIdleConns(maxConnsInt*2)
// db.SetConnMaxLifetime(time.Minute * 2)
db.SetConnMaxIdleTime(time.Minute * 2)

for {
	err := db.Ping()
	// _, err := db.Exec("SELECT 42")
	if err == nil {
		break
	}
	log.Print(err)
	time.Sleep(time.Second * 2)
}
log.Print("DB ready!")
```

* [DSAS開発者の部屋:Re: Configuring sql.DB for Better Performance](http://dsas.blog.klab.org/archives/2018-02/configure-sql-db.html)
* [Three bugs in the Go MySQL Driver - The GitHub Blog](https://github.blog/2020-05-20-three-bugs-in-the-go-mysql-driver/)
* [Go の sql.DB がコネクションプールを管理する仕組み - Please Sleep](https://please-sleep.cou929.nu/go-sql-db-connection-pool.html)

### Goでプレースホルダ置換

[DSAS開発者の部屋:go-sql-driver/mysql でプレースホルダ置換をサポートしました](http://dsas.blog.klab.org/archives/52191467.html)

`interpolateParams=true`をつける。

```go
// tcp
dsn := fmt.Sprintf(
	"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
	user,
	password,
	host,
	port,
	dbname,
)
```

### http.Clientについて

  * `http.Client`を都度作成するのではなく、グローバル変数に持って使い回す
    * 内部の`http.Transport`を使い回さないとTCPコネクションを都度貼ってしまう
    * 複数のgoroutineから利用しても安全
  * `http.Get`などは内部的にグローバル変数の`http.DefaultClient`を使い回す構成になっている
    * 大量のリクエストを外部サービスに送らないなら`http.Get`のままが無難
  * デフォルトだと同一ホストへのコネクション数は`http.DefaultMaxIdleConnsPerHost`の2に制限されている
    * 他サービスに大量のリクエストを送る必要がある場合は大きくした方がよい
    * `MaxIdleConns`(default: 100)と`IdleConnTimeout`(default: 90s)もいじった方が良い可能性がある
    * 最適な値は問題や状況により異なる
  * デフォルトだと`http.Client`の`Timeout`は無限になっているので、制限した方が安全
    * いくつかタイムアウトの設定があるので適宜設定する
  * レスポンスを受け取ったら必ずBodyをCloseする
    * Closeを忘れるとTCPコネクションが再利用されない
    * （ISUCONではあまりないと思うが）`res.Body`をReadせずにCloseするとコネクションが切断されるので、`ioutil.ReadAll`などを使って読み切る
    * 本来はISUCONの初期実装で実装されているはずだが、初期実装がバグっている可能性もあるので確認すること

``` go
var (
	IsuconClient http.Client
)

func init() {
	IsuconClient = http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 200,
			IdleConnTimeout:     120 * time.Second,
		},
	}
}
```

``` go
res, err := http.DefaultClient.Do(req)
if err != nil {
	return err
}
defer res.Body.Close()
_, err = ioutil.ReadAll(res.Body)
if err != nil {
	log.Fatal(err)
}
```

参考URL

  * [Goでnet/httpを使う時のこまごまとした注意 - Qiita](https://qiita.com/ono_matope/items/60e96c01b43c64ed1d18)
  * [The complete guide to Go net/http timeouts](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/)
  * [Accelerating real applications in Go](https://talks.godoc.org/github.com/cubicdaiya/talks/2017/01/golang-tokyo.slide#16)

### Goアプリケーションのプロファイリング

#### pprof

pprofではネットワークで待ちになっている時間などは顕在化しないので、ボトルネックがアプリケーションのCPUに移らない限り、取る意味はほぼない。

https://godoc.org/github.com/pkg/profile を使うと楽。必ずStopを呼び出す必要があるので以下のようにして無理矢理呼び出すのがおすすめ。

デフォルトは`ioutil.TempDir("", "profile")`で指定されたディレクトリにファイルができる。環境変数`TMPDIR`にもよるが、Linuxなら`/tmp/profile/cpu.pprof`というファイルができるはず。systemdならPrivateTmpがデフォルトで有効なので注意。

```go
import "github.com/pkg/profile"

var (
	profileProfile interface{ Stop() }
)

func init() {
	profileProfile = profile.Start(profile.ProfilePath("/home/isucon/profile"))
	// memory
	// profile.Start(profile.MemProfile, profile.ProfilePath("/home/isucon/profile"))
}

func getProfileStop(w http.ResponseWriter, r *http.Request) {
	profileProfile.Stop()
}
```

`apt install graphviz`してから`go tool pprof --pdf /tmp/profile/cpu.pprof > tmp.pdf`するとPDFになる。LinuxのpprofファイルをMacで処理することもできる。

### Goでボトルネックになりやすいところ

文字列はimmutableなので文字列結合はimmutableな文字列を生成し続けることになる。バイト列ならそういうことはないので予めある程度の大きさのバイトのスライスを作成してappendする方がよい。

``` go
b := make([]byte, 0, 40)
b = append(b, request.ID...)
b = append(b, ' ')
b = append(b, client.Addr().String()...)
b = append(b, ' ')
b = time.Now().AppendFormat(b, "2006-01-02 15:04:05.999999999 -0700 MST")
r = string(b)
```

profiling結果に`runtime.mallocgc`が多い場合はこういった小さいメモリのアロケートが多い可能性がある。

  * [Debugging performance issues in Go programs | Intel® Software](https://software.intel.com/en-us/blogs/2014/05/10/debugging-performance-issues-in-go-programs)
  * [High Performance Go](https://talks.godoc.org/github.com/davecheney/high-performance-go-workshop/high-performance-go-workshop.slide)
  * [Profiling Go Programs - The Go Blog](https://blog.golang.org/profiling-go-programs)

Goの正規表現は基本遅い。リクエストの度に生成は絶対にしてはいけない。できれば`strings`パッケージの関数に置き換えられそうなら置き換えること。

  * [Remove regex match use Index and replace - walf443/yisucon_practice](https://github.com/walf443/yisucon_practice/pull/18/files)

### measure

https://github.com/najeira/measure を使えば各関数の実時間を取れる。

https://github.com/tenntenn/isucontools/tree/master/cmd/measuregen

を使うとソースコードを変更できる。`runtime.nanotime`と`runtime.walltime`を結構呼び出すので最後に消すのを忘れないこと。

```go
s.mux.HandleFunc("/debug/measure", measure.HandleStats)
```

CSVとして保存して表計算ソフトで開く。

```
curl http://localhost:8000/debug/measure -o measure.csv
```

#### net/http/pprof

``` go
import "net/http/pprof"

// blocking profiler
// cf: http://blog.livedoor.jp/sonots/archives/39879160.html
runtime.SetBlockProfileRate(1)

// Register pprof handlers
s.mux.HandleFunc("/debug/pprof/", pprof.Index)
s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

go func() {
	log.Println(http.Serve(l, nil))
}()
```

### templateの使い方

  * [Writing Web Applications - The Go Programming Language](https://golang.org/doc/articles/wiki/#tmp_10)
  * [(*Template) Funcs](https://golang.org/pkg/html/template/#Template.Funcs)
  * [template.ParseFiles](https://golang.org/pkg/html/template/#ParseFiles)

リクエストの度にtemplateを毎回Parseするのはマズい。グローバル変数を定義して起動時にParseを済ませておく。ただし`template.FuncMap`を使っている場合はParseする前に呼び出す必要がある。

ISUCONの問題はGo以外の他言語で初期実装が作られてからGo実装が作られるという事情上、`template.FuncMap`を使う実装になっている可能性はかなり高い。

``` go
var templates *template.Template

func init() {
	// FuncMapを使わない場合
	templates = template.Must(template.ParseFiles("templates/edit.html", "templates/view.html"))

	// FuncMapを使う場合
	fmap := template.FuncMap{}
	templates = template.Must(template.New("").Funcs(fmap).ParseFiles("templates/edit.html", "templates/view.html"))
}

func main() {
	// ...
	err := templates.ExecuteTemplate(w, "view.html", struct{}{})
}
```

`.ExecuteTemplate`に渡すのはtemplateの名前でParseFilesを使った場合はファイル名になる（ディレクトリ名は含まない）。これはテンプレート内で`{{template}}`を使用することで呼び出すこともできる。ParseFilesには使うすべてのファイルを渡す。

  * [templateをグローバルにキャッシュする by catatsuy · Pull Request #19 · walf443/isucon5-practice](https://github.com/walf443/isucon5-practice/pull/19/files)
  * [remove render by catatsuy · Pull Request #21 · walf443/yisucon_practice](https://github.com/walf443/yisucon_practice/pull/21/files)

ISUCON5予選のようにリクエストの度に変わる関数を`template.FuncMap{}`を渡す場合、毎回Parseする必要が出てしまう。変数で渡すようにするなどして該当関数を排除してから行う。


### jsonが遅い場合

https://github.com/goccy/go-json

### Goの書き方

  * [The Go Programming Language Specification - The Go Programming Language](https://golang.org/ref/spec)
  * [SliceTricks · golang/go Wiki](https://github.com/golang/go/wiki/SliceTricks)

## Gitでpatchファイルを生成する

```
git diff --no-prefix HEAD > ~/thisis.patch
patch --dry-run -p0 < thisis.patch
patch -p0 < thisis.patch
```

## 参考URL

  * [GoでISUCONを戦う話](https://gist.github.com/catatsuy/e627aaf118fbe001f2e7c665fda48146)

## おまじない集

### dstat

```
dstat -tlamp
```

これに cpu の状況を確認したいなら `--top-cpu-adv`，IO を確認したいなら `--top-io-adv` でブロッキング IO を確認したいなら `--top-bio-adv` を付ける

### rsync

```
rsync -vau /hoge/fuga/ catatsuy.org:/hoge/fuga/
```

ディレクトリの最後には必ず `/` を付ける

### 参考 URL

  * [にひりずむ::しんぷる - ngrep 便利！](http://blog.livedoor.jp/xaicron/archives/54419469.html)
  * [dstatの便利なオプションまとめ - Qiita](https://qiita.com/harukasan/items/b18e484662943d834901)
  * [Linux - rsync したいときの秘伝のタレ - Qiita](https://qiita.com/catatsuy/items/66aa402cbb4c9cffe66b)
