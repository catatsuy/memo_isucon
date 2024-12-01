ISUCON
==================================

ISUCONのめも

## 作業リスト

```
## 最初の作業

* [ ] ポータルサイトにログインしてsshできることを確認
* [ ] 全員共通の~/.ssh/configを作る

## インフラ担当

* [ ] 何もせずにベンチマークを流す
* [ ] 動作しているプロセスを確認しておおよその構成を理解する
* [ ] Go実装に切り替えてベンチマークを流す
* [ ] 必要なパッケージなどインストール
* [ ] データベースなど各アプリケーションの設定値を確認してgitにコミットする
* [ ] nginxで計測できるようにする（alpを使う）
* [ ] ハードウェアの構成を把握する

## アプリケーション担当1

* [ ] ssh-keygenして鍵をdeploy keyに登録 ssh -T git@github.com
* [ ] コードをリポジトリにpushする
* [ ] スキーマ一覧を共有
* [ ] 各テーブルのサイズを共有
* [ ] デプロイスクリプトを作る
* [ ] initialize の動作を確認する
* [ ] キーになる関数があれば特定する

時間が余ったら

* レギュレーションを読む
* アプリケーションを使ってみる
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
mysqldump データベース名 > dump.sql
mysql データベース名 < dump.sql
```

スキーマだけを得たい場合

```
mysqldump --compact --no-data データベース名 | grep -v "^SET" | grep -v "^/\*\!" | perl -ple 's@CREATE TABLE @\nCREATE TABLE @g'
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

#### 高速なdump

MySQL Shellを使う方法。MySQL ShellはMySQL公式のリポジトリからインストールする必要があり、LinuxのARM用は存在しない。出力されるファイルはtsvベースでmysqldumpなどとは異なる。

https://dev.mysql.com/doc/mysql-shell/8.0/en/mysql-shell-install-linux-quick.html

```
mysqlsh -uroot
> util.dumpInstance("/var/tmp/shell")

> util.loadDump("/var/tmp/shell")
```

MySQL 8.0.17で追加されたcloneプラグインを使う

```
mysql> INSTALL PLUGIN clone SONAME 'mysql_clone.so';
Query OK, 0 rows affected (0.00 sec)

mysql> CLONE LOCAL DATA DIRECTORY = '/var/tmp/clone';
```

```sh
cp -r /var/tmp/clone /var/lib/mysql
chown -R mysql. /var/lib/mysql
```

MariaDBにはPercona XtraBackupのForkのmariabackupがある。

datadirを直接コピーする方法もあるが、my.cnfの兼ね合いもあるので他のサーバーに持って行くのは面倒。安全に停止する方法は以下。

```sql
SET GLOBAL innodb_fast_shutdown=0;
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

```
truncate -s 0 /var/log/mysql/slow.log
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
pt-query-digest --limit 100% --since "`date '+%F %T' -d '-5 minutes' --utc`" /var/log/mysql/slow.log | tee slowq.txt
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

https://dev.mysql.com/downloads/

* MySQL 8はデフォルトでbinlogを出力するのですごい勢いでディスクを使う
* 複数台構成にするときはbind-addressを0.0.0.0にする

#### 書き込みパフォーマンスを向上させる危険なオプション

https://atsuizo.hatenadiary.jp/entry/2020/07/16/140000
https://dev.mysql.com/doc/refman/8.0/en/innodb-redo-log.html#:~:text=An%20ALTER%20INSTANCE%20%5BENABLE%7CDISABLE,to%20be%20released%20before%20executing.

```
ALTER INSTANCE DISABLE INNODB REDO_LOG;
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
docker compose up app
docker compose logs nginx --no-log-prefix --tail=10000 --since 5m
docker ps -a
docker cp 34757ddbe7a3:/etc/nginx/nginx.conf .
docker cp $(docker ps -q --filter "name=nginx"):/etc/nginx/nginx.conf .
docker exec -it 97d91b5a58ed /bin/bash
docker exec -it $(docker ps -q --filter "name=nginx") /bin/bash
```

```yaml
environment:
  DEV: "${DEV:-0}"
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

sudo swapon --show
```

[SwapFaq - Community Help Wiki](https://help.ubuntu.com/community/SwapFaq)

## ダミーファイル作成

50MBの`/dummy`を作る。

```
sudo dd if=/dev/zero of=/dummy bs=1M count=50
```

## sysctl.conf

`sudo service procps force-reload` or `sudo systemctl force-reload procps`

  * cannot assign requested はローカルポート
  * ip_conntrack: table full, dropping packet (`dmesg`)
    * 有効でない場合は `modprobe ip_conntrack`

## nginx

```sh
cat /var/log/nginx/access.log | alp ltsv -m "^/items/\d+\.json" --sort=sum --reverse --filters 'Time > TimeAgo("5m")'

cat /var/log/nginx/access.log | alp ltsv -m "^/items/\d+\.json","^/new_items/\d+\.json","/users/\d+\.json","/transactions/\d+.png","/upload/[0-9a-f]+\.jpg" --sort=sum --reverse --filters 'Time > TimeAgo("5m")' | notify_slack -snippet -filetype txt

truncate -s 0 /var/log/nginx/access.log
```

https://github.com/tkuchiki/alp/blob/master/docs/usage_samples.md

* query parameterが必要な場合は`-q`を付与する
* キャッシュがHITしているか確認したい場合はログに `"\tcache_status:$upstream_cache_status"` を追加

### nginx-build

```
nginx-build -d work -openssl -pcre -zlib -c configure

sudo rm -rf /etc/nginx/modules-enabled/
```

### kTLS対応のnginx

OpenSSL 3.0以降ならkTLSが使える可能性がある。Ubuntu 24.04なら使える。最短作業。

```shell
# lsmodでtlsが有効になっているか確認
$ sudo lsmod | grep tls
tls                   155648  0
# Ubuntuなら多分デフォルト有効だが、何も出なければ有効にする
$ sudo modprobe tls
# 再起動しても有効にする。最初から有効になっていたら不要
$ echo "tls" | sudo tee -a /etc/modules
```

nginx.confに以下の設定を追加。

```
ssl_conf_command Options KTLS;
```

有効になっているか確認するのはerror.logをdebugにした上でリクエストを飛ばして、以下のログが出るか確認する。

```shell
ubuntu@ip-172-31-7-186:~$ sudo grep SSL_sendfile /var/log/nginx/error.log
2024/10/20 07:18:37 [debug] 2530#2530: *1 SSL_sendfile: 615
2024/10/20 07:21:55 [debug] 2530#2530: *3 SSL_sendfile: 615
ubuntu@ip-172-31-7-186:~$ sudo grep BIO /var/log/nginx/error.log
2024/10/20 07:18:37 [debug] 2530#2530: *1 BIO_get_ktls_send(): 1
2024/10/20 07:21:55 [debug] 2530#2530: *3 BIO_get_ktls_send(): 1
```

nginx-buildを使う場合は以下のオプションを追加する。

```
 --with-openssl-opt=enable-ktls \
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
sudo systemctl stop snapd.socket
sudo systemctl disable snapd.socket
sudo systemctl stop snapd
sudo systemctl disable snapd

sudo systemctl disable snap.amazon-ssm-agent.amazon-ssm-agent.service
```

## htop

|  key  |            effect            |
| :---: | :--------------------------: |
|   H   | ユーザースレッド表示・非表示 |
|   K   | カーネルスレッド表示・非表示 |
|   t   |          ツリー表示          |
|   h   |             help             |
|   q   |             quit             |

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

git add .
git commit -m "first commit"
git branch -M main
git remote add origin git@github.com:catatsuy/test_empty.git
git push -u origin main
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

## Go

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

### Goでインメモリキャッシュ・簡易ロック

https://github.com/catatsuy/cache

https://pkg.go.dev/github.com/catatsuy/cache

### Goでインメモリキャッシュのデータを永続化して、起動時に読み込む

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/catatsuy/cache"
)

const cacheFileName = "cache_data.json"

var mCache = cache.NewWriteHeavyCache[int, string]()

func main() {
	if _, err := os.Stat(cacheFileName); err == nil {
		fmt.Println("Cache file found. Loading data...")
		if err := loadCacheFromFile(cacheFileName); err != nil {
			fmt.Println("Failed to load cache:", err)
			return
		}
	} else {
		fmt.Println("No cache file found. Starting with an empty cache.")
	}

	mCache.Set(1, "apple")
	mCache.Set(2, "banana")

	sigs := make(chan os.Signal, 1)
	done := make(chan struct{})

	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigs
		fmt.Println("\nReceived signal:", sig)

		if err := saveCacheToFile(cacheFileName); err != nil {
			fmt.Println("Failed to save cache:", err)
			return
		}

		done <- struct{}{}
	}()

	<-done

	fmt.Println("Cache successfully saved to file.")
}

// saveCacheToFile serializes the cache data and writes it to a file
func saveCacheToFile(fileName string) error {
	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	items := mCache.GetItems()
	if err := json.NewEncoder(file).Encode(items); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}

// loadCacheFromFile reads the cache data from a file and deserializes it
func loadCacheFromFile(fileName string) error {
	file, err := os.Open(fileName)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	items := make(map[int]string)
	if err := json.NewDecoder(file).Decode(&items); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	mCache.SetItems(items)

	return nil
}
```

### Goで更新をまとめつつ、インメモリキャッシュを使う

```go
package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/catatsuy/cache"
)

var (
	sf     = cache.NewSingleflightGroup[string]()
	mCache = cache.NewWriteHeavyCache[int, string]()
)

func main() {
	mCache.Set(1, "apple")
	value, found := mCache.Get(1)
	if found {
		fmt.Println("Found:", value)
	} else {
		fmt.Println("Not found")
	}

	var wg sync.WaitGroup

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			result, err := GetWithSingleFlight(i%2 + 2)
			if err != nil {
				fmt.Println("Error:", err)
			}
			fmt.Println("Result:", result)
		}(i)
	}

	wg.Wait()
}

func GetWithSingleFlight(key int) (string, error) {
	value, found := mCache.Get(key)
	if found {
		return value, nil
	}

	vv, err := sf.Do(fmt.Sprintf("cacheGet_%d", key), func() (string, error) {
		value, err := HeavyGet(key)
		if err != nil {
			return "", err
		}
		mCache.Set(key, value)
		return value, nil
	})

	if err != nil {
		return "", err
	}

	return vv, nil
}

func HeavyGet(key int) (string, error) {
	fmt.Println("HeavyGet for key:", key)
	time.Sleep(time.Millisecond)
	return fmt.Sprintf("heavy_result_for_%d", key), nil
}
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

### Goで新旧のデータを比較して差分をlogに出す

```go
package main

import (
	"log"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type User struct {
	ID        int
	Name      string
	Score     int
	Timestamp time.Time
}

func main() {
	oldData := User{
		ID:    1,
		Name:  "Alice",
		Score: 100,
	}

	newData := User{
		ID:    1,
		Name:  "Alice",
		Score: 200,
	}

	diff := cmp.Diff(oldData, newData)

	if diff != "" {
		log.Printf("Data changed:\n%s", diff)
	} else {
		log.Println("No changes detected.")
	}

	oldData = User{
		ID:        1,
		Name:      "Alice",
		Score:     100,
		Timestamp: time.Now().Add(-1 * time.Hour),
	}

	newData = User{
		ID:        1,
		Name:      "Alice",
		Score:     200,
		Timestamp: time.Now(),
	}

	diff = cmp.Diff(oldData, newData, cmpopts.IgnoreFields(User{}, "ID", "Timestamp"))

	if diff != "" {
		log.Printf("Filtered Diff:\n%s", diff)
	} else {
		log.Println("No significant changes detected.")
	}
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

### Goでbulk insertする

sqlxを使うと楽

```go
places := []*Place{&place1, &place2}
db.NamedExec("INSERT INTO place (country, telcode) VALUES (:country, :telcode)", places)
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
db.SetConnMaxLifetime(3 * time.Minute)
// db.SetConnMaxIdleTime(2 * time.Minute)

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
    * （ISUCONではあまりないと思うが）`res.Body`をReadせずにCloseするとコネクションが切断されるので、`io.ReadAll`などを使って読み切る
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
_, err = io.ReadAll(res.Body)
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

initializeの最適化は特に意味がないので、initializeの後に呼び出している。別にmainから呼び出して、専用エンドポイントでstopしてもよい。

```go
import "runtime/pprof"

func startCPUProfile(filePath string) error {
	var err error
	profileFile, err = os.Create(filePath)
	if err != nil {
		return err
	}

	pprof.StartCPUProfile(profileFile)
	return nil
}

func stopCPUProfile() {
	pprof.StopCPUProfile()
	profileFile.Close()
}

func isProfilingEnabled() bool {
	return os.Getenv("PPROF") == "1"
}

func postInitialize(w http.ResponseWriter, r *http.Request) {
	// ...

	if isProfilingEnabled() {
		if err := startCPUProfile("/home/isucon/cpu.pprof"); err != nil {
			return
		}
		go func() {
			<-time.After(65 * time.Second)
			stopCPUProfile()
		}()
	}

	// ...
}
```

`apt install graphviz`してから`go tool pprof --pdf /home/isucon/cpu.pprof > cpu.pdf`するとPDFになる。LinuxのpprofファイルをMacで処理することもできる。

#### pgo

本番環境で作成したcpu.pprofを手元に持ってくる。

```sh
go build -pgo=cpu.pprof -o app
```

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
// メモリコピーをなくせる（nsレベルの最適化になる）
r = unsafe.String(&b[0], len(b))
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

### ログ無効化

```go
// echo
e.Debug = false
e.Logger.SetLevel(log.ERROR) // log.OFF

// アクセスログ
// e.Use(middleware.Logger())


// slog
devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
if err != nil {
	panic(err)
}
defer devNull.Close()
logger := slog.New(slog.NewTextHandler(devNull, &slog.HandlerOptions{}))
slog.SetDefault(logger)
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

// for echo
e.GET("/debug/pprof/", echo.WrapHandler(http.HandlerFunc(pprof.Index)))
e.GET("/debug/pprof/cmdline", echo.WrapHandler(http.HandlerFunc(pprof.Cmdline)))
e.GET("/debug/pprof/profile", echo.WrapHandler(http.HandlerFunc(pprof.Profile)))
e.GET("/debug/pprof/symbol", echo.WrapHandler(http.HandlerFunc(pprof.Symbol)))
e.GET("/debug/pprof/trace", echo.WrapHandler(http.HandlerFunc(pprof.Trace)))

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

https://github.com/goccy/echo-tools/tree/main/json

### GOGC

* defaultは100で、大きくするとGCの回数が減る
* メモリが余っていたら200とかにしてみるとよさそう

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

## etckeeper

```
sudo apt install etckeeper

sudo etckeeper init
sudo etckeeper commit "Initial commit of /etc"

sudo etckeeper vcs diff
sudo etckeeper commit "Updated hostname"
```

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

### tar cvf

```
tar cvf backup.tar /home/isucon/webapp/sql/
```

### 参考 URL

  * [にひりずむ::しんぷる - ngrep 便利！](http://blog.livedoor.jp/xaicron/archives/54419469.html)
  * [dstatの便利なオプションまとめ - Qiita](https://qiita.com/harukasan/items/b18e484662943d834901)
  * [Linux - rsync したいときの秘伝のタレ - Qiita](https://qiita.com/catatsuy/items/66aa402cbb4c9cffe66b)
