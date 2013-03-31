require 'drb'
require 'optparse'

class Ping

  class Responder
    def ping i
      i
    end
  end

  def self.process_args argv
    options = {
      flood:  false,
      server: false,
      client: nil,
    }

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

      opt.on('--flood',
             'Send packets as fast as possible',
             'Prints one . per 1000 messages') do
        options[:flood] = true
      end

      opt.on('--server',
             'Run only as a server') do |value|
        options[:server] = true
      end
    end

    op.parse! argv

    raise OptionParser::ParseError, '--server with --flood is nonsense' if
      options[:server] and options[:flood]

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
    @client = options[:client]
    @flood  = options[:flood]
    @server = options[:server]
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
    remote = DRb::DRbObject.new_with_uri uri
    seq = 0

    while seq += 1 do
      begin
        start = Time.now
        remote.ping seq

        elapsed = (Time.now - start) * 1000

        if @flood then
          print '.' if seq % 1000 == 0
        else
          puts "from %s: seq=%d time=%0.3f ms" % [uri, seq, elapsed]

          sleep 1
        end
      rescue DRb::DRbConnError
        puts "connection failed"
      end
    end
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

