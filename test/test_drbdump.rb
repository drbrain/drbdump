require 'minitest/autorun'
require 'drbdump'
require 'rinda/ring'
require 'tempfile'

class TestDRbDump < MiniTest::Unit::TestCase

  PING_DUMP = File.expand_path '../ping.dump', __FILE__
  RING_DUMP = File.expand_path '../ring.dump', __FILE__

  PING_PACKETS = Capp.open(PING_DUMP).loop.to_a

  def test_capture_drb_tcp
    drbdump PING_DUMP

    @drbdump.capture_drb_tcp.join

    refute_empty @drbdump.incoming_packets

    packet = @drbdump.incoming_packets.deq

    assert packet.tcp?
  end

  def test_capture_ring_finger
    drbdump RING_DUMP

    @drbdump.capture_ring_finger.join

    refute_empty @drbdump.incoming_packets

    packet = @drbdump.incoming_packets.deq

    assert packet.udp?

    assert_equal Rinda::Ring_PORT, packet.udp_header.destination_port
  end

  def test_display_drb_recv_msg
    send_msg = PING_PACKETS.find do |packet|
      packet.payload =~ /\x00\x03\x04\x08T/
    end

    out, = capture_io do
      drbdump.display_drb send_msg
    end

    expected = <<-EXPECTED
20:01:45.927677 kault.53714 > kault.53717: success: true result: 1
    EXPECTED

    assert_equal expected, out
  end

  def test_display_drb_send_msg
    send_msg = PING_PACKETS.find { |packet| packet.payload =~ /ping/ }

    out, = capture_io do
      drbdump.display_drb send_msg
    end

    expected = <<-EXPECTED
20:01:45.927216 kault.53717 > kault.53714: (front).ping(1)
    EXPECTED

    assert_equal expected, out
  end

  def drbdump file = nil
    @drbdump = DRbDump.new file
    @drbdump.resolver = resolver
    @drbdump
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

