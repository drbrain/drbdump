require 'drbdump/test_case'

class TestDRbDump < DRbDump::TestCase

  def test_class_process_args_count
    options = DRbDump.process_args %w[--count 50]

    assert_equal 50, options[:count]

    options = DRbDump.process_args %w[-c 49]

    assert_equal 49, options[:count]
  end

  def test_class_process_args_defaults
    options = DRbDump.process_args []

    assert_equal Float::INFINITY,  options[:count]
    assert_equal [],               options[:devices]
    assert_equal true,             options[:resolve_names]
    assert_equal nil,              options[:run_as_directory]
    assert_equal nil,              options[:run_as_user]
  end

  def test_class_process_args_devices
    options = DRbDump.process_args %w[--interface lo0]

    assert_equal %w[lo0], options[:devices]

    options = DRbDump.process_args %w[-i lo0]

    assert_equal %w[lo0], options[:devices]

    options = DRbDump.process_args %w[-i lo0 -i en0]

    assert_equal %w[lo0 en0], options[:devices]
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

  def test_class_process_args_quiet
    options = DRbDump.process_args %w[--quiet]

    assert options[:quiet]

    options = DRbDump.process_args %w[-q]

    assert options[:quiet]
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

  def test_close_stream
    drbdump FIN_DUMP

    packet = packets(FIN_DUMP).first
    @drbdump.drb_streams[packet.source] = true
    @drbdump.incomplete_streams[packet.source] = ''
    @drbdump.incomplete_timestamps[packet.source] = Time.now

    capp = @drbdump.close_stream packet.source

    assert_empty @drbdump.drb_streams
    assert_empty @drbdump.incomplete_streams
    assert_empty @drbdump.incomplete_timestamps
  end

  def test_create_capp
    drbdump RING_DUMP

    packets = @drbdump.create_capp(RING_DUMP).loop.to_a

    refute_empty packets

    packet = packets.first

    assert packet.udp?

    assert_equal Rinda::Ring_PORT, packet.udp_header.destination_port
  end

  def test_display_drb_count
    send_msg = packets(ARG_DUMP).find { |packet| packet.payload =~ /ping/ }

    drbdump

    @drbdump.count = 1

    capture_io do
      @drbdump.display_drb send_msg
      @drbdump.display_drb send_msg
    end

    assert_equal 1, @statistics.drb_packet_count
    assert_equal 1, @statistics.drb_message_sends

    source, destination = @drbdump.resolve_addresses send_msg

    assert_equal send_msg.timestamp,
                 @statistics.last_peer_send[source][destination]
  end

  def test_display_drb_http
    drbdump

    assert_silent do
      packets(HTTP_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    assert_equal 0, @statistics.drb_packet_count

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
22:19:38.279650 "druby://kault:56128" \u21d2 ("druby://kault:56126", nil).ping(1)
22:19:38.280108 "druby://kault:56128" \u21d0 "druby://kault:56126" success: 1
22:19:38.280472 "druby://kault:56128" \u2902 "druby://kault:56126" exception: #<DRb::DRbConnError: connection closed>
22:19:38.280713 "druby://kault:56129" \u21d2 ("druby://kault:56126", nil).ping(2)
22:19:38.280973 "druby://kault:56129" \u21d0 "druby://kault:56126" success: 2
22:19:38.281197 "druby://kault:56129" \u2902 "druby://kault:56126" exception: #<DRb::DRbConnError: connection closed>
    EXPECTED

    assert_equal expected, out

    assert_empty @drbdump.incomplete_streams
    assert_empty @drbdump.incomplete_timestamps

    assert_equal 4, @statistics.drb_result_receipts
    assert_equal 2, @statistics.drb_message_sends
  end

  def test_display_drb_recv_msg
    drbdump

    send_msg = packets(PING_DUMP).find do |packet| packet.payload =~ /ping/ end
    source, destination = @drbdump.resolve_addresses send_msg
    @statistics.add_send_timestamp source, destination, send_msg.timestamp

    recv_msg = packets(PING_DUMP).find do |packet|
      packet.payload =~ /\x00\x03\x04\x08T/
    end

    out, = capture_io do
      @drbdump.display_drb recv_msg
    end

    expected = <<-EXPECTED
20:01:45.927677 "druby://kault:53717" \u21d0 "druby://kault:53714" success: 1
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @statistics.drb_packet_count
    assert_equal 1, @statistics.drb_result_receipts

    source, destination = @drbdump.resolve_addresses recv_msg

    assert_equal 1, @statistics.peer_latencies[destination][source].count
  end

  def test_display_drb_recv_msg_quiet
    send_msg = packets(PING_DUMP).find do |packet|
      packet.payload =~ /\x00\x03\x04\x08T/
    end

    drbdump
    @drbdump.quiet = true

    assert_silent do
      @drbdump.display_drb send_msg
    end

    assert_equal 1, @statistics.drb_packet_count
    assert_equal 1, @statistics.drb_result_receipts
  end

  def test_display_drb_send_msg
    send_msg = packets(ARG_DUMP).find { |packet| packet.payload =~ /ping/ }

    out, = capture_io do
      drbdump.display_drb send_msg
    end

    expected = <<-EXPECTED
23:46:20.561659 "druby://kault:57317" \u21d2 ("druby://kault:57315", nil).ping(1, \"abcdefghij\")
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @statistics.drb_packet_count
    assert_equal 1, @statistics.drb_message_sends
  end

  def test_display_drb_send_msg_quiet
    send_msg = packets(ARG_DUMP).find { |packet| packet.payload =~ /ping/ }

    drbdump
    @drbdump.quiet = true

    assert_silent do
      @drbdump.display_drb send_msg
    end

    assert_equal 1, @statistics.drb_packet_count
    assert_equal 1, @statistics.drb_message_sends
    refute_empty @statistics.last_peer_send
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

    assert_equal 0, @statistics.drb_packet_count
  end

  def test_display_drb_too_large_quiet
    drbdump
    @drbdump.quiet = true

    assert_silent do
      packets(TOO_LARGE_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end
  end

  def test_display_ring_finger
    out, = capture_io do
      drbdump.display_ring_finger packets(RING_DUMP).first
    end

    expected = <<-EXPECTED
19:39:25.877246 find ring on 255.255.255.255.7647 for druby://kault.jijo.segment7.net:53578 timeout: 5
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @statistics.rinda_packet_count
  end

  def test_display_ring_finger_quiet
    drbdump
    @drbdump.quiet = true

    assert_silent do
      @drbdump.display_ring_finger packets(RING_DUMP).first
    end

    assert_equal 1, @statistics.rinda_packet_count
  end

  def test_load_marshal_data
    drbdump

    marshal_structure = Marshal::Structure.new "\x04\x08i\x06"

    assert_equal 1, @drbdump.load_marshal_data(marshal_structure)

    marshal_structure = Marshal::Structure.new "\x04\x08o:\x06C\x00"

    loaded = @drbdump.load_marshal_data marshal_structure

    assert_kind_of DRb::DRbUnknown, loaded
  end

  def test_start_capture
    drbdump RING_DUMP

    capp = @drbdump.create_capp RING_DUMP

    thread, = @drbdump.start_capture [capp]

    thread.join

    refute_empty @drbdump.incoming_packets

    packet = @drbdump.incoming_packets.deq

    assert packet.udp?

    assert_equal Rinda::Ring_PORT, packet.udp_header.destination_port

    assert_equal packets(RING_DUMP).count, @statistics.total_packet_count
  end

  def test_start_capture_rst_fin
    drbdump FIN_DUMP

    packet = packets(FIN_DUMP).first
    @drbdump.drb_streams[packet.source] = true

    capp = @drbdump.create_capp FIN_DUMP

    thread, = @drbdump.start_capture [capp]

    thread.join

    assert_empty @drbdump.drb_streams
  end

end

