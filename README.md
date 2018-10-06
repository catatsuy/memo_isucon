ISUCON
==================================

ISUCONのめも

    curl -L https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash
    # not installed curl
    wget -O - https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash

`screen -S catatsuy -c ~/.screenrc_catatsuy`


## MySQL

```
create database isubata;
CREATE USER 'isucon'@'localhost' IDENTIFIED BY 'isucon';
GRANT ALL PRIVILEGES ON isubata.* TO 'isucon'@'localhost';
```

MySQL8以降で簡単なパスワードを設定できなくなった。my.cnfで以下のようにする。

```my.cnf
validate_password.length = 0
validate_password.policy = LOW
```

### mysqldump

    mysqldump -uroot データベース名 > dump.sql
    mysql -uroot データベース名 < dump.sql

スキーマだけを得たい場合

```
mysqldump -u root --compact --no-data database | grep -v "^SET" | grep -v "^/\*\!" | perl -ple 's@CREATE TABLE @\nCREATE TABLE @g'
```

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

```
# RedHat
yum install percona-toolkit

# Debian
apt install percona-toolkit
```

（依存も入るけど`sudo yum install -y perl-DBI perl-DBD-MySQL perl-Time-HiRes`で自前で入れることもできる）


#### innodb buffer poolを温める

  * [お手軽InnoDBウォームアップを実現するMySQL::Warmerの話をGotanda.pm #2でしてきました | おそらくはそれさえも平凡な日々](http://www.songmu.jp/riji/entry/2014-09-22-gotandapm-mysql-warmer.html)
  * [Kazuho@Cybozu Labs: MySQL のウォームアップ (InnoDB編)](http://labs.cybozu.co.jp/blog/kazuho/archives/2007/10/innodb_warmup.php)
  * [日々の覚書: InnoDB buffer pool dumpで遊ぶ](http://yoku0825.blogspot.jp/2012/08/innodb-buffer-pool-dump.html)
  * [InnoDBのウォームアップに別サーバでdumpしたib_buffer_poolを使ってみる - mikedaの日記](http://mikeda.hatenablog.com/entry/2015/09/21/142746)

```
cpanm MySQL::Warmer
cpanm DBD::mysql
mysql-warmup mydatabase -h db.example.com -u dbuser -p --dry-run
```

`--dry-run`で実行すべきクエリを取得できる。`--dry-run`を付けなければ実行してくれるが、自分の環境では実行できないクエリを実行しようとした。

また時間制限もあるのでどれを実行するかは人間が決めるべき。


## tmpfs

`/etc/fstab`

```
tmpfs  /mnt/tmpfs  tmpfs  defaults,size=8G  0  0
```

`sudo mount -a`で適用

## sysctl.conf

`sysctl -p` で適用

  * cannot assign requested はローカルポート
  * ip_conntrack: table full, dropping packet (`dmesg`)
    * 有効でない場合は `modprobe ip_conntrack`

## nginx

[Ruby - ltsv access log summary tool - Qiita](https://qiita.com/edvakf@github/items/3bdd46b53d65cf407fa2)

`parse.rb`を使う

```
cat access.log | ruby parse.rb --before=300 > result.txt
notify_slack result.txt
```

66行目の `path = line[:path]` を `gsub` で適当に縮める
（例：`line[:path].gsub(/memo\/(\d+)/, 'memo/:id').gsub(/recent\/(\d+)/, 'recent/:id')`）

`nginx -V` で configure オプション確認

キャッシュがHITしているか確認したい場合はログに `"\tcache_status:$upstream_cache_status` を追加

`/home/isucon` の権限を 755 にすること

### OpenResty

```
sudo apt install libreadline-dev libncurses5-dev libpcre3-dev libssl-dev perl make build-essential
./configure --with-pcre-jit --with-luajit --with-http_gzip_static_module

# you need to have ldconfig in your PATH env when enabling luajit. と言われたら
PATH=$PATH:/sbin ./configure --with-pcre-jit --with-luajit --with-http_gzip_static_module

sudo apt install build-essential
PATH=$PATH:/sbin ./nginx-build -d work -openresty -openssl -pcre -zlib
```

`nginx -V`

```
# nginx-full(Debian stretch)
# nginx version: nginx/1.10.3
./configure \
 --with-cc-opt='-g -O2 -fdebug-prefix-map=/build/nginx-2tpxfc/nginx-1.10.3=. -fstack-protector-strong -Wformat -Werror=format-security -Wdate-time -D_FORTIFY_SOURCE=2' \
 --with-ld-opt='-Wl,-z,relro -Wl,-z,now' \
 --prefix=/usr/share/nginx \
 --conf-path=/etc/nginx/nginx.conf \
 --http-log-path=/var/log/nginx/access.log \
 --error-log-path=/var/log/nginx/error.log \
 --lock-path=/var/lock/nginx.lock \
 --pid-path=/run/nginx.pid \
 --modules-path=/usr/lib/nginx/modules \
 --http-client-body-temp-path=/var/lib/nginx/body \
 --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
 --http-proxy-temp-path=/var/lib/nginx/proxy \
 --http-scgi-temp-path=/var/lib/nginx/scgi \
 --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
 --with-debug \
 --with-pcre-jit \
 --with-ipv6 \
 --with-http_ssl_module \
 --with-http_stub_status_module \
 --with-http_realip_module \
 --with-http_auth_request_module \
 --with-http_v2_module \
 --with-http_dav_module \
 --with-http_slice_module \
 --with-threads \
 --with-http_addition_module \
 --with-http_geoip_module=dynamic \
 --with-http_gunzip_module \
 --with-http_gzip_static_module \
 --with-http_image_filter_module=dynamic \
 --with-http_sub_module \
 --with-http_xslt_module=dynamic \
 --with-stream=dynamic \
 --with-stream_ssl_module \
 --with-mail=dynamic \
 --with-mail_ssl_module \
 --add-dynamic-module=/build/nginx-2tpxfc/nginx-1.10.3/debian/modules/nginx-auth-pam \
 --add-dynamic-module=/build/nginx-2tpxfc/nginx-1.10.3/debian/modules/nginx-dav-ext-module \
 --add-dynamic-module=/build/nginx-2tpxfc/nginx-1.10.3/debian/modules/nginx-echo \
 --add-dynamic-module=/build/nginx-2tpxfc/nginx-1.10.3/debian/modules/nginx-upstream-fair \
 --add-dynamic-module=/build/nginx-2tpxfc/nginx-1.10.3/debian/modules/ngx_http_substitutions_filter_module

# nginx(Debian stretch)
# nginx version: nginx/1.12.1
./configure \
 --prefix=/etc/nginx \
 --sbin-path=/usr/sbin/nginx \
 --modules-path=/usr/lib/nginx/modules \
 --conf-path=/etc/nginx/nginx.conf \
 --error-log-path=/var/log/nginx/error.log \
 --http-log-path=/var/log/nginx/access.log \
 --pid-path=/var/run/nginx.pid \
 --lock-path=/var/run/nginx.lock \
 --http-client-body-temp-path=/var/cache/nginx/client_temp \
 --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
 --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
 --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
 --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
 --user=nginx \
 --group=nginx \
 --with-compat \
 --with-file-aio \
 --with-threads \
 --with-http_addition_module \
 --with-http_auth_request_module \
 --with-http_dav_module \
 --with-http_flv_module \
 --with-http_gunzip_module \
 --with-http_gzip_static_module \
 --with-http_mp4_module \
 --with-http_random_index_module \
 --with-http_realip_module \
 --with-http_secure_link_module \
 --with-http_slice_module \
 --with-http_ssl_module \
 --with-http_stub_status_module \
 --with-http_sub_module \
 --with-http_v2_module \
 --with-mail \
 --with-mail_ssl_module \
 --with-stream \
 --with-stream_realip_module \
 --with-stream_ssl_module \
 --with-stream_ssl_preread_module \
 --with-cc-opt='-g -O2 -fdebug-prefix-map=/data/builder/debuild/nginx-1.12.1/debian/debuild-base/nginx-1.12.1=. -specs=/usr/share/dpkg/no-pie-compile.specs -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
 --with-ld-opt='-specs=/usr/share/dpkg/no-pie-link.specs -Wl,-z,relro -Wl,-z,now -Wl, --as-needed -pie'

# OpenResty 1.11.2.4
./configure
 --prefix=/usr/local/openresty/nginx \
 --with-cc-opt=-O2 \
 --add-module=../ngx_devel_kit-0.3.0 \
 --add-module=../echo-nginx-module-0.60 \
 --add-module=../xss-nginx-module-0.05 \
 --add-module=../ngx_coolkit-0.2rc3 \
 --add-module=../set-misc-nginx-module-0.31 \
 --add-module=../form-input-nginx-module-0.12 \
 --add-module=../encrypted-session-nginx-module-0.06 \
 --add-module=../srcache-nginx-module-0.31 \
 --add-module=../ngx_lua-0.10.8 \
 --add-module=../ngx_lua_upstream-0.06 \
 --add-module=../headers-more-nginx-module-0.32 \
 --add-module=../array-var-nginx-module-0.05 \
 --add-module=../memc-nginx-module-0.18 \
 --add-module=../redis2-nginx-module-0.14 \
 --add-module=../redis-nginx-module-0.3.7 \
 --add-module=../rds-json-nginx-module-0.14 \
 --add-module=../rds-csv-nginx-module-0.07 \
 --with-ld-opt=-Wl,-rpath,/usr/local/openresty/luajit/lib \
 --with-pcre=/home/vagrant/work/openresty/1.11.2.4/openresty-1.11.2.4/../pcre-8.41 \
 --with-openssl=/home/vagrant/work/openresty/1.11.2.4/openresty-1.11.2.4/../openssl-1.0.2l \
 --with-zlib=/home/vagrant/work/openresty/1.11.2.4/openresty-1.11.2.4/../zlib-1.2.11 \
 --with-http_ssl_module

# recommend
PATH=$PATH:/sbin ./nginx-build -d work -openresty -openssl -pcre -zlib \
 --sbin-path=/usr/sbin/nginx \
 --conf-path=/etc/nginx/nginx.conf \
 --http-log-path=/var/log/nginx/access.log \
 --error-log-path=/var/log/nginx/error.log \
 --pid-path=/var/run/nginx.pid \
 --lock-path=/var/lock/nginx.lock \
 --http-client-body-temp-path=/var/lib/nginx/body \
 --http-proxy-temp-path=/var/lib/nginx/proxy \
 --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
 --with-debug \
 --with-pcre-jit \
 --with-http_gunzip_module \
 --with-http_gzip_static_module \
 --with-http_v2_module
```

## ulimit

`too many open files` はファイルディスクリプタ

  * [ulimitが効かない不安を無くす設定 | 外道父の匠](http://blog.father.gedow.net/2012/08/08/ulimit-configuration/)
  * [systemd時代に困らないためのlimits設定 | 外道父の匠](http://blog.father.gedow.net/2016/03/28/limits-of-systemd/)

`ulimit -n 65536` が一番良さそう

`/etc/security/limits.conf`

```
isucon hard nofile 65535
isucon soft nofile 65535
```

systemdの方が楽。

```
[Service]
LimitNOFILE=1006500
LimitNPROC=1006500
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

## git init

``` shell
git init
git config --global user.name "isucon"
git config --global user.email "isucon@isucon"
```

## deploy

### .ssh/config

```
Host isu
  HostName xxx
  User isucon
  ServerAliveInterval 5
  ServerAliveCountMax 12
```

### deploy.sh

``` shell
## deploy.sh

#!/bin/bash -x

./deploy_body.sh | notify_slack

## deploy_body.sh
#!/bin/bash -x

echo "start deploy ${USER}"
GOOS=linux go build -v isubata
for server in isu; do
    ssh -t $server "sudo systemctl stop isubata.golang.service"
    scp ./isubata $server:/home/isucon/isubata/webapp/go/isubata
    rsync -av ./src/isubata/views/ $server:/home/isucon/isubata/webapp/go/src/isubata/views/
    ssh -t $server "sudo systemctl start isubata.golang.service"
done

echo "finish deploy ${USER}"
```

## go

### UNIX domain Socket

注：変数名が被りにくいように少し変な変数名にしてある。

```go
var hport int

func init() {
	flag.IntVar(&hport, "port", 0, "port to listen")
	flag.Parse()
}

// 以下は main() で
sigchan := make(chan os.Signal)
signal.Notify(sigchan, syscall.SIGTERM)
signal.Notify(sigchan, syscall.SIGINT)

var li net.Listener
var herr error
hsock := "/dev/shm/server.sock"
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
go func() {
	// func Serve(l net.Listener, handler Handler) error
	log.Println(http.Serve(li, nil))
}()

<-sigchan
```

### Goでインメモリキャッシュ

``` go
type cacheSlice struct {
	// Setが多いならsync.Mutex
	sync.RWMutex
	items map[int]int
}

func NewCacheSlice() *cacheSlice {
	m := make(map[int]int)
	c := &cacheSlice{
		items: m,
	}
	return c
}

func (c *cacheSlice) Set(key int, value int) {
	c.Lock()
	c.items[key] = value
	c.Unlock()
}

func (c *cacheSlice) Get(key int) (int, bool) {
	c.RLock()
	v, found := c.items[key]
	c.RUnlock()
	return v, found
}

func (c *cacheSlice) Incr(key int, n int) {
	c.Lock()
	v, found := c.items[key]
	if found {
		c.items[key] = v + n
	} else {
		c.items[key] = n
	}
	c.Unlock()
}

var mCache = NewCacheSlice()
```

### zero time cache

[DSAS開発者の部屋:ISUCON6予選をトップ通過しました](http://dsas.blog.klab.org/archives/2016-09-20/isucon5q.html)

``` go
var (
	mUpdateHeavyProcess sync.Mutex
	dataLastUpdated     time.Time
	mChangeDataControl  sync.Mutex
)

func updateHeavyProcess() {
	now := time.Now()
	mUpdateHeavyProcess.Lock()
	defer mUpdateHeavyProcess.UnLock()

	if dataLastUpdated.After(now) {
		return
	}
	dataLastUpdated := time.Now()

	// Heavy Process
}

func changeData() {
	mChangeDataControl.Lock()

	// change data

	updateHeavyProcess()
	mChangeDataControl.UnLock()
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

// unix domain socket
dsn := fmt.Sprintf(
	"%s:%s@unix(%s)/%s?charset=utf8mb4&parseTime=true&loc=Local",
	user,
	password,
	socket,
	dbname,
)
```

### GoでMySQLのコネクションを制限する

デフォルトは無限なので制限した方が良い。

``` go
maxConns := os.Getenv("DB_MAXOPENCONNS")
if maxConns != "" {
	i, err := strconv.Atoi(maxConns)
	if err != nil {
		panic(err)
	}
	db.SetMaxOpenConns(i)
	db.SetMaxIdleConns(i)
}
```

### Goでプレースホルダ置換

[DSAS開発者の部屋:go-sql-driver/mysql でプレースホルダ置換をサポートしました](http://dsas.blog.klab.org/archives/52191467.html)

`interpolateParams=true`をつける。

```go
// tcp
dsn := fmt.Sprintf(
	"%s:%s@tcp(%s:%s)/%s?interpolateParams=true&charset=utf8mb4&parseTime=true&loc=Local",
	user,
	password,
	host,
	port,
	dbname,
)
```

### Goアプリケーションの状況を見たい

  * [golang-stats-api-handler/handler.go at master · fukata/golang-stats-api-handler](https://github.com/fukata/golang-stats-api-handler/blob/master/handler.go)

### Goアプリケーションのプロファイリング

```go
import "github.com/pkg/profile"

// cf: https://godoc.org/github.com/pkg/profile
// main()の中で
defer profile.Start().Stop()
// ファイル名を指定したい
defer profile.Start(profile.ProfilePath("/home/isucon/profile")).Stop()
// memory
defer profile.Start(profile.MemProfile).Stop()
```

`/tmp/profile/cpu.pprof`ファイルとかができる。空ファイルができた場合はdeferが呼ばれていないので何とかする。

`apt install graphviz`してから`go tool pprof --pdf /tmp/profile/cpu.pprof > tmp.pdf`するとPDFになる。（Go1.8以下の場合バイナリを指定する必要がある `go tool pprof --pdf app /tmp/profile/cpu.pprof > tmp.pdf`）。

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

#### net/http/pprof

``` go
import _ "net/http/pprof"

// blocking profiler
// cf: http://blog.livedoor.jp/sonots/archives/39879160.html
runtime.SetBlockProfileRate(1)
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


### egoを使う

https://github.com/benbjohnson/ego

`go get github.com/benbjohnson/ego/cmd/ego`

```go
//go:generate ego
func main() {
}
```

`go generate`すれば`*.ego.go`が出力される。


### jsonが遅い場合

https://github.com/json-iterator/go

``` go
import (
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary
```

### Martini でログを吐かない

`MARTINI_ENV=production` ではログは消えない

[DSAS開発者の部屋:ISUCON4 予選で workload=5 で 88000点出す方法 (lily white 参戦記)](http://dsas.blog.klab.org/archives/52171878.html)

テンプレートのパース回数が減るらしいので有効にはすべき

```go
m := martini.Classic()
devnull, err := os.Open(os.DevNull)
if err != nil {
	log.Fatal(err)
}
m.Map(log.New(devnull, "", 0))
```

本当に消したいなら martini のソースコードをいじるしかない


### Goの書き方

  * [The Go Programming Language Specification - The Go Programming Language](https://golang.org/ref/spec)
  * [SliceTricks · golang/go Wiki](https://github.com/golang/go/wiki/SliceTricks)

### Redis

#### redigo

``` go
package main

import (
	"fmt"
	"time"

	"github.com/garyburd/redigo/redis"
)

var (
	conn redis.Conn
	pool *redis.Pool
)

func init() {
	pool = newPool(":6379")
	conn = pool.Get()
}

// https://godoc.org/github.com/garyburd/redigo/redis
// https://redis.io/commands
func main() {
	defer conn.Close()

	flush()
	getSet()
	uniqueKey()
	list()
	hash()
}

func newPool(addr string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 240 * time.Second,
		Dial:        func() (redis.Conn, error) { return redis.Dial("tcp", addr) },
	}
}

// func serveHome(w http.ResponseWriter, r *http.Request) {
// 	conn := pool.Get()
// 	defer conn.Close()
// 	// ...
// }

func flush() {
	_, err := conn.Do("FLUSHALL")
	if err != nil {
		panic(err)
	}
}

func getSet() {
	_, err := conn.Do("SET", "key", "value")
	if err != nil {
		panic(err)
	}

	s, err := redis.String(conn.Do("GET", "key"))
	if err != nil {
		panic(err)
	}
	fmt.Println(s)

	s2, err := redis.String(conn.Do("GET", "key2"))

	if err == redis.ErrNil {
		fmt.Println("key2 does not exist")
	} else if err != nil {
		panic(err)
	} else {
		fmt.Println("key2", s2)
	}
}

func uniqueKey() {
	id, _ := conn.Do("Incr", "pk")
	fmt.Println("id", id)

	id, _ = conn.Do("Incr", "pk")
	fmt.Println("id", id)

	id, _ = conn.Do("Incr", "pk")
	fmt.Println("id", id)
}

func list() {
	_, err := conn.Do("RPUSH", "mylist", "one")
	if err != nil {
		panic(err)
	}

	_, err = conn.Do("RPUSH", "mylist", "two")
	if err != nil {
		panic(err)
	}

	_, err = conn.Do("RPUSH", "mylist", "three")
	if err != nil {
		panic(err)
	}

	_, err = conn.Do("RPUSH", "mylist", "four")
	if err != nil {
		panic(err)
	}

	_, err = conn.Do("RPUSH", "otherlist", "five")
	if err != nil {
		panic(err)
	}

	res, err := redis.String(conn.Do("RPOPLPUSH", "mylist", "otherlist"))
	if err != nil {
		panic(err)
	}
	fmt.Println(res)

	res, err = redis.String(conn.Do("LPOP", "otherlist"))
	if err != nil {
		panic(err)
	}
	fmt.Println(res)

	res, err = redis.String(conn.Do("LPOP", "otherlist"))
	if err != nil {
		panic(err)
	}
	fmt.Println(res)

	fmt.Println("LRANGE")

	ss, err := redis.Strings(conn.Do("LRANGE", "mylist", 1, 10))
	if err != nil {
		panic(err)
	}

	for _, s := range ss {
		fmt.Println(s)
	}
}

func hash() {
	res, err := redis.Int(conn.Do("HSET", "myhash", "key1", "value1"))
	if err != nil {
		panic(err)
	}
	// 1
	fmt.Println(res)

	res, err = redis.Int(conn.Do("HSET", "myhash", "key1", "value2"))
	if err != nil {
		panic(err)
	}
	// 0
	fmt.Println(res)

	_, err = redis.Int(conn.Do("HSET", "myhash", "key2", "valueee"))
	if err != nil {
		panic(err)
	}

	s, err := redis.String(conn.Do("HGET", "myhash", "key1"))
	if err != nil {
		panic(err)
	}
	fmt.Println(s)

	m, err := redis.StringMap(conn.Do("HGETALL", "myhash"))
	if err != nil {
		panic(err)
	}

	for k, v := range m {
		fmt.Printf("key: %s; val: %s\n", k, v)
	}
}
```


## lua

### luaのデバッグ

```
resty -e 'ngx.say("Hello, World!")'
```

### cjson

```lua
local res = {
  test = "hello",
}

local cjson = require "cjson"
ngx.say(cjson.encode(res))
```

### example

```
content_by_lua_block {
  local res = ngx.location.capture("/some_other_location")
  if res then
    ngx.say("status: ", res.status)
    ngx.say("body:")
    ngx.print(res.body)
  end
}

access_by_lua_block {
  -- check the client IP address is in our black list
  if ngx.var.remote_addr == "132.5.72.3" then
    ngx.exit(ngx.HTTP_FORBIDDEN)
  end

  -- check if the URI contains bad words
  if ngx.var.uri and string.match(ngx.var.request_body, "evil") then
    return ngx.redirect("/terms_of_use.html")
  end
}

access_by_lua_file /path/to/access.lua;
ontent_by_lua_file /path/to/content.lua;
```

### error log

``` lua
ngx.log(ngx.STDERR, err)
```

### ライブラリ

  * [openresty/lua-resty-mysql: Nonblocking Lua MySQL driver library for ngx_lua or OpenResty](https://github.com/openresty/lua-resty-mysql)
  * [openresty/lua-resty-redis: Lua redis client driver for the ngx_lua based on the cosocket API](https://github.com/openresty/lua-resty-redis)
  * [openresty/lua-resty-memcached: Lua memcached client driver for the ngx_lua based on the cosocket API](https://github.com/openresty/lua-resty-memcached)

### ドキュメント

  * [Directives - OpenResty Reference](https://openresty-reference.readthedocs.io/en/latest/Directives/)
  * [openresty/lua-nginx-module: Embed the Power of Lua into NGINX HTTP servers](https://github.com/openresty/lua-nginx-module)
  * [lua-nginx-module を使いこなす - Qiita](https://qiita.com/kz_takatsu/items/e94805a8e3cc285f9b33)

### luaの書き方

  * [Lua Cheat Sheet](https://gist.github.com/doches/2219649)
  * [catatsuy/demo_test_nginx_mysql](https://github.com/catatsuy/demo_test_nginx_mysql)

## Gitでpatchファイルを生成する

    git diff --no-prefix HEAD > ~/thisis.patch
    patch --dry-run -p0 < thisis.patch
    patch -p0 < thisis.patch

## おまじない集

### dstat

    dstat -tlamp

これに cpu の状況を確認したいなら `--top-cpu-adv`，IO を確認したいなら `--top-io-adv` でブロッキング IO を確認したいなら `--top-bio-adv` を付ける

### rsync

    rsync -vau /hoge/fuga/ catatsuy.org:/hoge/fuga/

ディレクトリの最後には必ず `/` を付ける

### netstat

    netstat -tlnp

tcp の通信だけ見れる

### 参考 URL

  * [にひりずむ::しんぷる - ngrep 便利！](http://blog.livedoor.jp/xaicron/archives/54419469.html)
  * [dstatの便利なオプションまとめ - Qiita](https://qiita.com/harukasan/items/b18e484662943d834901)
  * [Linux - rsync したいときの秘伝のタレ - Qiita](https://qiita.com/catatsuy/items/66aa402cbb4c9cffe66b)
