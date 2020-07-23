# lua

## OpenResty

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
# Ubuntu 20.04
$ nginx -V
--with-cc-opt='-g -O2 -fdebug-prefix-map=/build/nginx-5J5hor/nginx-1.18.0=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2'
--with-ld-opt='-Wl,-Bsymbolic-functions -Wl,-z,relro -Wl,-z,now -fPIC'
--prefix=/usr/share/nginx
--conf-path=/etc/nginx/nginx.conf
--http-log-path=/var/log/nginx/access.log
--error-log-path=/var/log/nginx/error.log
--lock-path=/var/lock/nginx.lock
--pid-path=/run/nginx.pid
--modules-path=/usr/lib/nginx/modules
--http-client-body-temp-path=/var/lib/nginx/body
--http-fastcgi-temp-path=/var/lib/nginx/fastcgi
--http-proxy-temp-path=/var/lib/nginx/proxy
--http-scgi-temp-path=/var/lib/nginx/scgi
--http-uwsgi-temp-path=/var/lib/nginx/uwsgi
--with-debug
--with-compat
--with-pcre-jit
--with-http_ssl_module
--with-http_stub_status_module
--with-http_realip_module
--with-http_auth_request_module
--with-http_v2_module
--with-http_dav_module
--with-http_slice_module
--with-threads
--with-http_addition_module
--with-http_gunzip_module
--with-http_gzip_static_module
--with-http_image_filter_module=dynamic
--with-http_sub_module
--with-http_xslt_module=dynamic
--with-stream=dynamic
--with-stream_ssl_module
--with-mail=dynamic
--with-mail_ssl_module

# recommend
PATH=$PATH:/sbin ./nginx-build -d work -openresty -openssl -pcre -zlib \
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

