require 'drb'

class Responder
  def ping i
    i
  end
end

def ping uri
  seq = 0

  while seq += 1 do
    remote = DRb::DRbObject.new_with_uri uri

    begin
      start = Time.now
      remote.ping seq

      elapsed = (Time.now - start) * 1000

      puts "from %s: seq=%d time=%0.3f ms" % [uri, seq, elapsed]

      sleep 1
    rescue DRb::DRbConnError
      puts "connection failed"
    end
  end
end

DRb.start_service nil, Responder.new

uri = ARGV.shift

case uri
when 'server' then
  puts DRb.uri

  DRb.thread.join
when /^druby:/ then
  ping uri
when String then
  abort <<-ABORT
#{$0} server

or

#{$0} druby://...

or

#{$0}
  ABORT
else
  uri = DRb.uri

  pid = fork do
    DRb.stop_service

    DRb.start_service

    ping uri
  end

  trap 'INT'  do Process.kill 'INT',  pid end
  trap 'TERM' do Process.kill 'TERM', pid end

  Process.wait pid
end

