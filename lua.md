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

