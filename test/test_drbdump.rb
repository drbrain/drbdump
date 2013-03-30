require 'minitest/autorun'
require 'drbdump'
require 'tempfile'

class TestDRbDump < MiniTest::Unit::TestCase

  PING_DUMP = File.expand_path '../ping.dump', __FILE__
  RING_DUMP = File.expand_path '../ring.dump', __FILE__

  PING_PACKETS = Capp.open(PING_DUMP).loop.to_a

  def test_class_process_args_defaults
    options = DRbDump.process_args []

    assert_equal nil,  options[:device]
    assert_equal true, options[:resolve_names]
    assert_equal nil,  options[:run_as_directory]
    assert_equal nil,  options[:run_as_user]
  end

  def test_class_process_args_device
    options = DRbDump.process_args %w[--interface lo0]

    assert_equal 'lo0', options[:device]

    options = DRbDump.process_args %w[-i lo0]

    assert_equal 'lo0', options[:device]
  end

  def test_class_process_args_invalid
    e = nil
    out, err = capture_io do
      e = assert_raises SystemExit do
        DRbDump.process_args %w[--no-such-option]
      end
    end

    assert_empty out
    assert_match 'Usage', err
    assert_match 'no-such-option', err

    assert_equal 1, e.status
  end

  def test_class_process_args_resolve_names
    options = DRbDump.process_args %w[-n]

    refute options[:resolve_names]
  end

  def test_class_process_args_run_as_directory
    options = DRbDump.process_args %w[--run-as-directory /]

    assert_equal '/', options[:run_as_directory]
  end

  def test_class_process_args_run_as_user
    options = DRbDump.process_args %w[--run-as-user nobody]

    assert_equal 'nobody', options[:run_as_user]
  end

  def test_create_capp
    drbdump RING_DUMP

    packets = @drbdump.create_capp.loop.to_a

    refute_empty packets

    packet = packets.first

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

  def test_start_capture
    drbdump RING_DUMP

    capp = @drbdump.create_capp

    thread = @drbdump.start_capture capp

    thread.join

    refute_empty @drbdump.incoming_packets

    packet = @drbdump.incoming_packets.deq

    assert packet.udp?

    assert_equal Rinda::Ring_PORT, packet.udp_header.destination_port
  end

  def drbdump file = PING_DUMP
    @drbdump = DRbDump.new :device => file
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

