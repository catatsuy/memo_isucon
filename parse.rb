#!/usr/bin/env ruby

# cat access.log | ruby parse.rb
# if --since is given, logs before the specified time are ignored
#  (by string comparison)
# eg. --since='2013-11-05T02:23'

# supported accesslog format : http://i2bskn.hateblo.jp/entry/2013/05/14/003726 style
#
#  log_format ltsv "time:$time_iso8601"
#                  "\thost:$remote_addr"
#                  "\txff:$http_x_forwarded_for"
#                  "\tmethod:$request_method"
#                  "\tpath:$request_uri"
#                  "\tstatus:$status"
#                  "\tua:$http_user_agent"
#                  "\treq_size:$request_length"
#                  "\treq_time:$request_time"
#                  "\tres_size:$bytes_sent"
#                  "\tbody_size:$body_bytes_sent"
#                  "\tapp_time:$upstream_response_time";
#
# time:2013-11-05T02:23:14+09:00  host:202.232.134.129    xff:-   method:GET      path:/  status:200      ua:Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36  req_size:599    req_time:0.005  res_size:2951   body_size:2711  app_time:0.005

since = nil
if ARGV.length
  m = /--since=(.*)/.match(ARGV[0])
  since = m[1] if m
end

logs = []
while l = STDIN.gets
  l.strip!
  log = {}
  l.split("\t").each{|kv|
    k,v = kv.split(":", 2)
    k = k.to_sym
    if k == :req_time || k == :app_time
      log[k] = v.to_f
    else
      log[k] = v
    end
  }
  if !since.nil? && log[:time] < since
    next
  end
  logs.push(log)
end

template = {
  :path => '',
  :mathod => '',
  :total_time => 0,
  :total_count => 0,
  :avg_time => 0,
}
tmp = {}

logs.each {|log|
  path = log[:path]
  method = log[:method]
  key = method+'::'+path
  if tmp[key].nil?
    tmp[key] = template.clone
    tmp[key][:path] = path
    tmp[key][:method] = method
  end
  tmp[key][:total_time] += log[:req_time]
  tmp[key][:total_count] += 1
}

paths = []
tmp.to_a.each {|path, detail|
  detail[:avg_time] = detail[:total_time] / detail[:total_count]
  paths.push(detail)
}

def print_paths(paths)
  puts "\tavg\ttotal\tcount\tmethod\tpath"
  paths.each {|path|
    puts "\t#{sprintf("%.2f",path[:avg_time])}\t#{sprintf("%.2f",path[:total_time])}\t#{path[:total_count]}\t#{path[:method]}\t#{path[:path]}"
  }
end

puts "==============="
puts "sort by total_count"
paths.sort! {|a, b| b[:total_count] <=> a[:total_count] }
print_paths(paths)

puts "==============="
puts "sort by avg_time"
paths.sort! {|a, b| b[:avg_time] <=> a[:avg_time] }
print_paths(paths)

puts "==============="
puts "sort by total_time"
paths.sort! {|a, b| b[:total_time] <=> a[:total_time] }
print_paths(paths)
