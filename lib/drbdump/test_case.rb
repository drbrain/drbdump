require 'minitest/autorun'
require 'drbdump'
require 'tempfile'

class DRbDump::TestCase < MiniTest::Unit::TestCase

  test = File.expand_path '../../../test', __FILE__

  ARG_DUMP       = File.join test, 'arg.dump'
  FIN_DUMP       = File.join test, 'drb_fin.dump'
  HTTP_DUMP      = File.join test, 'http.dump'
  PING_DUMP      = File.join test, 'ping.dump'
  RING_DUMP      = File.join test, 'ring.dump'
  TOO_LARGE_DUMP = File.join test, 'too_large_packet.pcap'

  def drbdump file = PING_DUMP
    @drbdump = DRbDump.new devices: [file]
    @drbdump.resolver = resolver

    @statistics = @drbdump.statistics

    @drbdump
  end

  def packets file
    Capp.open(file).loop
  end

  def resolver
    Tempfile.open 'hosts' do |io|
      io.puts '10.101.28.77 kault'
      io.flush

      resolver = Resolv::Hosts.new io.path
      resolver.getname '10.101.28.77' # initialize
      resolver
    end
  end

end

