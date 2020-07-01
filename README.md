ISUCON
==================================

ISUCONのめも

```
curl -L https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash
# not installed curl
wget -O - https://raw.githubusercontent.com/catatsuy/memo_isucon/master/quick.sh | bash
```

## MySQL

```
create database isucari;
CREATE USER 'isucon'@'localhost' IDENTIFIED BY 'isucon';
GRANT ALL PRIVILEGES ON isucari.* TO 'isucon'@'localhost';
```

MySQL8以降で簡単なパスワードを設定できなくなった。my.cnfで以下のようにする。

```my.cnf
validate_password.length = 0
validate_password.policy = LOW
```

### mysqldump

```
mysqldump -uroot データベース名 > dump.sql
mysql -uroot データベース名 < dump.sql
```

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

```
pt-query-digest --since="2020-05-02 09:00:00" /tmp/mysql-slow.log
```

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

```
cat /var/log/nginx/access.log | alp ltsv -m "^/items/\d+\.json","^/new_items/\d+\.json","/users/\d+\.json","/transactions/\d+.png","/upload/[0-9a-f]+\.jpg" --sort=sum --reverse --filters 'Time > TimeAgo("5m")'
```

https://github.com/tkuchiki/alp/blob/master/docs/usage_samples.md

キャッシュがHITしているか確認したい場合はログに `"\tcache_status:$upstream_cache_status"` を追加


## ulimit

systemdの方が楽。

```
[Service]
LimitNOFILE=1006500
LimitNPROC=1006500
```

`too many open files` はファイルディスクリプタ

## gzip

```
gzip -r js css
gzip -k index.html
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
Host isu01
  HostName xxx
  User isucon
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
GOOS=linux go build -v isucari
for server in isu01 isu02; do
  ssh -t $server "sudo systemctl stop isucari.golang.service"
  scp ./isucari $server:/home/isucon/isucari/webapp/go/isucari
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

### Goでexpire付きのインメモリキャッシュ

```go
type configValue struct {
	value  string
	expire time.Time
}

type configCache struct {
	sync.RWMutex
	items map[string]configValue
}

func NewConfigCache() *configCache {
	m := make(map[string]configValue)
	c := &configCache{
		items: m,
	}
	return c
}

func (c *configCache) Set(key string, value string) {
	val := configValue{
		value:  value,
		expire: time.Now().Add(80 * time.Second),
	}
	c.Lock()
	defer c.Unlock()
	c.items[key] = val
}

func (c *configCache) Get(key string) (string, bool) {
	c.RLock()
	defer c.RUnlock()
	v, found := c.items[key]
	if !found {
		return "", false
	}
	if time.Now().After(v.expire) {
		return "", false
	}
	return v.value, found
}

var CacheConfig = NewConfigCache()
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

[DSAS開発者の部屋:Re: Configuring sql.DB for Better Performance](http://dsas.blog.klab.org/archives/2018-02/configure-sql-db.html)

デフォルトは無限なので制限した方が良い。ISUCONだと30くらいから調整するのがよいかも。

``` go
maxConns := os.Getenv("DB_MAXOPENCONNS")
maxConnsInt := 30
if maxConns != "" {
	maxConnsInt, err = strconv.Atoi(maxConns)
	if err != nil {
		panic(err)
	}
}
dbx.SetMaxOpenConns(maxConnsInt)
dbx.SetMaxIdleConns(maxConnsInt)
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

### INクエリ

  * IN句などで大量にプレースホルダを作ると、クエリの実行にかなり時間がかかるので避ける必要がある
    * このケースだとスロークエリにならないのに、アプリケーション側からクエリを実行するのに時間がかかるという状況になるので注意
    * 適切にエスケープした値を`strings.Join`で結合してSQLに渡すべき
    * エスケープするよりも`[0-9a-zA-Z]`に限定する方を個人的には推奨

```go
idsStr := make([]string, 0, len(items))
for _, i := range items {
	idsStr = append(idsStr, strconv.FormatInt(i.ID, 10))
}
transactionEvidences := make([]TransactionEvidence, 0, len(items))
err = dbx.Select(&transactionEvidences, "SELECT * FROM `transaction_evidences` WHERE `item_id` IN ("+strings.Join(idsStr, ",")+")")
if err != nil {
	log.Print(err)
	outputErrorMsg(w, http.StatusInternalServerError, "db error")
	return
}
transactionEvidenceMap := make(map[int64]TransactionEvidence)
for _, t := range transactionEvidences {
	transactionEvidenceMap[t.ItemID] = t
}
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

### Goアプリケーションの状況を見たい

  * [golang-stats-api-handler/handler.go at master · fukata/golang-stats-api-handler](https://github.com/fukata/golang-stats-api-handler/blob/master/handler.go)

### Goアプリケーションのプロファイリング

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
func getReportMeasure(w http.ResponseWriter, r *http.Request) {
	stats := measure.GetStats()
	stats.SortDesc("sum")

	fmt.Fprintf(w, "key\tcount\tsum\tmin\tmax\tavg\trate\tp95\n")

	// print stats in TSV format
	for _, s := range stats {
		fmt.Fprintf(w, "%s\t%d\t%f\t%f\t%f\t%f\t%f\t%f\n",
			s.Key, s.Count, s.Sum, s.Min, s.Max, s.Avg, s.Rate, s.P95)
	}
}
```

一度コピーしてエディタに貼り付けてからGoogle Spreadsheetに貼り付けるといい感じになる。curlとpbcopyでも可。

```
curl http://localhost/report_measure | pbcopy
```

して貼り付け。Google Spreadsheetは複数行を選択すると複数行を一気に上に挿入できる。

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

https://github.com/json-iterator/go

``` go
import (
	jsoniter "github.com/json-iterator/go"
)

var json = jsoniter.ConfigCompatibleWithStandardLibrary
```

互換性はないが https://github.com/buger/jsonparser はもっと早い。

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

### netstat

```
netstat -tlnp
```

tcp の通信だけ見れる

### 参考 URL

  * [にひりずむ::しんぷる - ngrep 便利！](http://blog.livedoor.jp/xaicron/archives/54419469.html)
  * [dstatの便利なオプションまとめ - Qiita](https://qiita.com/harukasan/items/b18e484662943d834901)
  * [Linux - rsync したいときの秘伝のタレ - Qiita](https://qiita.com/catatsuy/items/66aa402cbb4c9cffe66b)
