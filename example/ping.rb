require 'drb'
require 'optparse'

module Statistics
  refine Array do
    def sum
      inject :+
    end

    def average
      sum / length.to_f
    end

    def sample_variance
      avg = average
      sum = inject { |sum, i| sum + (i - avg) ** 2 }
      1 / length.to_f * sum
    end

    def σ
      Math.sqrt sample_variance
    end
  end
end

using Statistics

class Ping

  class Responder
    def ping i, data
      return i, data
    end
  end

  def self.process_args argv
    options = {
      client:    nil,
      count:     nil,
      flood:     false,
      interval:  1,
      reconnect: false,
      server:    false,
      size:      0,
    }

    interval_set = false

    op = OptionParser.new do |opt|
      opt.banner = <<-BANNER
Usage: ping.rb [options] [druby://...]

  With no arguments, spawns a child process and sends DRb messages to it

  To ping across multiple machines start a server with:

    ping.rb --server

  And submit the given URI to a client:

    ping.rb druby://...
      BANNER

      opt.separator nil
      opt.separator 'Options:'

      opt.on('-c', '--count COUNT', Integer,
             'Number of packets to send') do |count|
        options[:count] = count
      end

      opt.on('-f', '--flood',
             'Send packets as fast as possible',
             'Prints one . per 1000 messages') do
        options[:flood] = true
      end

      opt.on('-i', '--interval SECONDS', Float,
             'Time between non-flood packets') do |interval|
        options[:interval] = interval
        interval_set = true
      end

      opt.on('-s', '--packet-size SIZE', Integer,
             'Size of extra data to send') do |size|
        options[:size] = size
      end

      opt.on(      '--reconnect',
             'Reconnect for each ping') do
        options[:reconnect] = true
      end

      opt.on(      '--server',
             'Run only as a server') do |value|
        options[:server] = true
      end
    end

    op.parse! argv

    raise OptionParser::ParseError, '--flood with --interval is nonsense' if
      options[:flood] and interval_set

    raise OptionParser::ParseError, '--server with --flood is nonsense' if
      options[:server] and options[:flood]

    raise OptionParser::ParseError, '--server with --count is nonsense' if
      options[:server] and options[:count]

    options[:client] = argv.shift if /\Adruby:/ =~ argv.first

    raise OptionParser::ParseError, '--server with client URI is nonsense' if
      options[:server] and options[:client]

    options
  rescue OptionParser::ParseError => e
    $stderr.puts op
    $stderr.puts
    $stderr.puts e.message

    abort
  end

  def self.run argv = ARGV
    options = process_args argv

    ping = new options

    ping.run
  end

  def initialize options
    @count     = options[:count]
    @client    = options[:client]
    @flood     = options[:flood]
    @interval  = options[:interval]
    @reconnect = options[:reconnect]
    @remote    = nil
    @server    = options[:server]
    @size      = options[:size]
    @uri       = nil

    @data = ('a'..'z').cycle.first(@size).join
  end

  def delay_ping
    times = []
    seq = 0

    until (seq += 1) > @count do
      begin
        start = Time.now
        @remote.ping seq, @data
        elapsed = (Time.now - start) * 1000

        times << elapsed

        puts "from %s: seq=%d time=%0.3f ms" % [@uri, seq, elapsed]

        reconnect

        sleep @interval
      rescue DRb::DRbConnError
        puts "connection failed"
      end
    end
  ensure
    puts
    puts delay_statistics times
  end

  def delay_statistics times
    min, max = times.minmax
    avg      = times.average
    σ        = times.σ

    '%d messages, min/avg/max/stddev = %0.3f/%0.3f/%0.3f/%0.3f ms' % [
      times.length, min, avg, max, σ
    ]
  end

  def flood_ping
    start = Time.now
    seq = 0

    until (seq += 1) > @count do
      begin
        @remote.ping seq, @data

        reconnect

        print '.' if seq % 1000 == 0
      rescue DRb::DRbConnError
        puts "connection failed"
      end
    end
  ensure
    elapsed = Time.now - start
    puts
    puts flood_statistics(elapsed, seq - 1)
  end

  def flood_statistics elapsed, messages
    '%d messages in %0.3f seconds, %d messages/sec' % [
      messages, elapsed, messages / elapsed
    ]
  end

  def loopback
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

  def ping uri
    @uri = uri
    @remote = DRb::DRbObject.new_with_uri @uri

    if @flood then
      flood_ping
    else
      delay_ping
    end
  end

  def reconnect
    return unless @reconnect

    DRb::DRbConn.open @uri do [false, false] end
  end

  def run
    DRb.start_service nil, Responder.new

    if @server then
      puts DRb.uri

      DRb.thread.join
    elsif @client then
      ping @client
    else
      loopback
    end
  end

end

Ping.run ARGV if $0 == __FILE__

