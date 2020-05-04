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
