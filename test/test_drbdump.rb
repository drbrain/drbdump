require 'minitest/autorun'
require 'drbdump'
require 'tempfile'

class TestDRbDump < MiniTest::Unit::TestCase

  ARG_DUMP       = File.expand_path '../arg.dump',     __FILE__
  FIN_DUMP       = File.expand_path '../drb_fin.dump', __FILE__
  HTTP_DUMP      = File.expand_path '../http.dump',    __FILE__
  PING_DUMP      = File.expand_path '../ping.dump',    __FILE__
  RING_DUMP      = File.expand_path '../ring.dump',    __FILE__
  TOO_LARGE_DUMP = File.expand_path '../too_large_packet.pcap', __FILE__

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

  def test_display_drb_http
    drbdump

    assert_silent do
      packets(HTTP_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    assert_equal 0, @drbdump.drb_packet_count

    expected = {
      '17.149.160.49.80'   => false,
      '10.101.28.77.53600' => false,
    }

    assert_equal expected, @drbdump.drb_streams
  end

  def test_display_drb_incomplete
    drbdump

    out, = capture_io do
      packets(FIN_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    expected = <<-EXPECTED
22:19:38.279650 "druby://kault:56128" > ("druby://kault:56126", nil).ping(1)
22:19:38.280108 "druby://kault:56128" < "druby://kault:56126" success: 1
22:19:38.280472 "druby://kault:56128" < "druby://kault:56126" exception: #<DRb::DRbConnError: connection closed>
22:19:38.280713 "druby://kault:56129" > ("druby://kault:56126", nil).ping(2)
22:19:38.280973 "druby://kault:56129" < "druby://kault:56126" success: 2
22:19:38.281197 "druby://kault:56129" < "druby://kault:56126" exception: #<DRb::DRbConnError: connection closed>
    EXPECTED

    assert_equal expected, out

    assert_empty @drbdump.incomplete_drb

    assert_equal 4, @drbdump.drb_result_receipts
    assert_equal 2, @drbdump.drb_message_sends
  end

  def test_display_drb_recv_msg
    send_msg = packets(PING_DUMP).find do |packet|
      packet.payload =~ /\x00\x03\x04\x08T/
    end

    out, = capture_io do
      drbdump.display_drb send_msg
    end

    expected = <<-EXPECTED
20:01:45.927677 "druby://kault:53717" < "druby://kault:53714" success: 1
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @drbdump.drb_packet_count
    assert_equal 1, @drbdump.drb_result_receipts
  end

  def test_display_drb_send_msg
    send_msg = packets(ARG_DUMP).find { |packet| packet.payload =~ /ping/ }

    out, = capture_io do
      drbdump.display_drb send_msg
    end

    expected = <<-EXPECTED
23:46:20.561659 "druby://kault:57317" > ("druby://kault:57315", nil).ping(1, \"abcdefghij\")
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @drbdump.drb_packet_count
    assert_equal 1, @drbdump.drb_message_sends
  end

  def test_display_drb_too_large
    out, = capture_io do
      packets(TOO_LARGE_DUMP).each do |packet|
        drbdump.display_drb packet
      end
    end

    innards = "\x04\bI\"\x04\x00\x00\xE0\x01"
    innards << ' ' * 468

    expected = <<-EXPECTED
22:41:07.060619 "druby://kault:56430" to "druby://kault:56428" packet too large, valid: [nil, "<<", 1] too big (31457294 bytes): #{innards.dump}
    EXPECTED

    assert_equal expected, out

    assert_equal 0, @drbdump.drb_packet_count
  end

  def test_display_ring_finger
    out, = capture_io do
      drbdump.display_ring_finger packets(RING_DUMP).first
    end

    expected = <<-EXPECTED
19:39:25.877246 find ring on 255.255.255.255.7647 for druby://kault.jijo.segment7.net:53578 timeout: 5
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @drbdump.rinda_packet_count
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

    assert_equal packets(RING_DUMP).count, @drbdump.total_packet_count
  end

  def test_start_capture_rst_fin
    drbdump FIN_DUMP

    packet = packets(FIN_DUMP).first
    @drbdump.drb_streams[packet.source] = true
    @drbdump.incomplete_drb[packet.source] = ''

    capp = @drbdump.create_capp

    thread = @drbdump.start_capture capp

    thread.join

    assert_empty @drbdump.drb_streams
    assert_empty @drbdump.incomplete_drb
  end

  def test_show_statistics
    drbdump

    capture_io do
      packets(ARG_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    out, = capture_io do
      @drbdump.show_statistics
    end

    expected = <<-EXPECTED
0 total packets captured
0 Rinda packets captured
3 DRb packets captured
1 messages sent
2 results received
1 exceptions raised
    EXPECTED

    assert_equal expected, out
  end

  def drbdump file = PING_DUMP
    @drbdump = DRbDump.new device: file
    @drbdump.resolver = resolver
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

