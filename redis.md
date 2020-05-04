# Redis

## redigo

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
