# Obsoleted

たまにすごく古い構成で出ることがある（辞めて欲しい）ので残しておく。

## ulimit

  * [ulimitが効かない不安を無くす設定 | 外道父の匠](http://blog.father.gedow.net/2012/08/08/ulimit-configuration/)
  * [systemd時代に困らないためのlimits設定 | 外道父の匠](http://blog.father.gedow.net/2016/03/28/limits-of-systemd/)

`ulimit -n 65536` が一番良さそう

`/etc/security/limits.conf`

```
isucon hard nofile 65535
isucon soft nofile 65535
```

## supervisord

    sudo supervisorctl status
    sudo supervisorctl reload

環境変数を渡したいとき

```
environment=MARTINI_ENV="production",PORT="8080"
```

## Martini でログを吐かない

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

## egoを使う

https://github.com/benbjohnson/ego

`go get github.com/benbjohnson/ego/cmd/ego`

```go
//go:generate ego
func main() {
}
```

`go generate`すれば`*.ego.go`が出力される。

## INクエリ

  * 以前はIN句などで大量にプレースホルダを作ると、クエリの実行にかなり時間がかかる問題があったが、現在のGoのライブラリにはない
    * このケースだとスロークエリにならないのに、アプリケーション側からクエリを実行するのに時間がかかるという状況になるので注意
    * 古いバージョンを使う場合や、PHPなど他言語を使う場合は注意

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

## sysctl.conf

`sysctl -p` で適用。もしくは `sudo service procps reload`。

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

// cacheInteger with manual type constraints instead of using external interfaces.
type cacheInteger[K comparable, V interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}] struct {
	sync.RWMutex
	items map[K]V
}

// NewCacheInteger constructor for creating a new cache.
func NewCacheInteger[K comparable, V interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}]() *cacheInteger[K, V] {
	return &cacheInteger[K, V]{
		items: make(map[K]V),
	}
}

// Set a value in the cache.
func (c *cacheInteger[K, V]) Set(key K, value V) {
	c.Lock()
	c.items[key] = value
	c.Unlock()
}

// Get a value from the cache.
func (c *cacheInteger[K, V]) Get(key K) (V, bool) {
	c.RLock()
	v, found := c.items[key]
	c.RUnlock()
	return v, found
}

// Incr increments the value in the cache by the given value.
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

### Goで簡易ロック

```go
package main

import (
	"sync"
)

type LockManager[T comparable] struct {
	mu    sync.Mutex
	locks map[T]*sync.Mutex
}

func NewLockManager[T comparable]() *LockManager[T] {
	return &LockManager[T]{
		locks: make(map[T]*sync.Mutex),
	}
}

func (lm *LockManager[T]) getLock(id T) *sync.Mutex {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if lock, exists := lm.locks[id]; exists {
		return lock
	}

	lock := &sync.Mutex{}
	lm.locks[id] = lock
	return lock
}

func (lm *LockManager[T]) Lock(id T) func() {
	lock := lm.getLock(id)
	lock.Lock()

	return func() {
		lock.Unlock()
	}
}

func main() {
	var lmInt64 = NewLockManager[int64]()
	unlock := lmInt64.Lock(123)
	defer unlock()

	var lmString = NewLockManager[string]()
	unlockStr := lmString.Lock("myLock")
	defer unlockStr()
}
```
