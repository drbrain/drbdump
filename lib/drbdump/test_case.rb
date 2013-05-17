require 'minitest/autorun'
require 'drbdump'
require 'tempfile'

# force time zone to mine
ENV['TZ'] = 'PST8PDT'

##
# A test case for writing DRbDump tests.

class DRbDump::TestCase < MiniTest::Unit::TestCase

  test = File.expand_path '../../../test', __FILE__

  ##
  # Dump containing DRb messages with arguments

  ARG_DUMP       = File.join test, 'arg.dump'

  ##
  # Dump containing a packet with a FIN flag

  FIN_DUMP       = File.join test, 'drb_fin.dump'

  ##
  # Dump containing HTTP packets

  HTTP_DUMP      = File.join test, 'http.dump'

  ##
  # Dump containing messages from example/ping.rb

  PING_DUMP      = File.join test, 'ping.dump'

  ##
  # Dump containing Rinda::RingFinger lookups

  RING_DUMP      = File.join test, 'ring.dump'

  ##
  # Dump containing a DRb message that is too large

  TOO_LARGE_DUMP = File.join test, 'too_large_packet.pcap'

  ##
  # Creates a new drbdump for +file+ and makes it available as @drbdump.
  # Calling this again will create a brand new instance.

  def drbdump file = PING_DUMP
    @drbdump = DRbDump.new devices: [file]
    @drbdump.instance_variable_set :@running, true
    @drbdump.resolver = resolver

    @statistics = @drbdump.statistics

    @drbdump
  end

  ##
  # Returns a Capp packet Enumerator for +file+

  def packets file
    Capp.open(file).loop
  end

  ##
  # Creates a resolver for addresses in *_DUMP files

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

