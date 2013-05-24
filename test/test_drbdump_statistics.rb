require 'drbdump/test_case'

class TestDRbDumpStatistics < DRbDump::TestCase

  def setup
    super

    @MS = Marshal::Structure

    drbdump

    @statistics = @drbdump.statistics
    @packet = packets(ARG_DUMP).first
    @random = Random.new 2
  end

  def test_add_message_send
    receiver = @MS.new "\x04\x080"
    msg = "\x00\x00\x00\x0b\x04\x08\"\x0cmessage"
    argc = "\x00\x00\x00\x04\x04\x08i\x08"
    argv = [
      "\x00\x00\x00\x07\x04\x08[\x06\"\x06a",
      "\x00\x00\x00\x0a\x04\x08[\x07\"\x06a\"\x06b",
      "\x00\x00\x00\x0d\x04\x08[\x08\"\x06a\"\x06b\"\x06c",
    ]
    block = "\x00\x00\x00\x03\x04\x080"

    stream = StringIO.new msg + argc + argv.join + block

    message = DRbDump::MessageSend.new @drbdump, @packet, receiver, stream

    @statistics.add_message_send message

    assert_equal 1, @statistics.drb_message_sends

    stat = @statistics.message_allocations['message'][3]

    assert_equal  1,    stat.count
    assert_equal 10.0,  stat.mean
    assert_equal  0.0, stat.standard_deviation

    assert_equal @packet.timestamp,
                 @statistics.last_peer_send[message.source][message.destination]
  end

  def test_add_result_receipt_exception
    result = @MS.new "\x04\x08\"\x09FAIL" # not an exception

    @statistics.add_result_receipt false, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 1, @statistics.drb_exceptions_raised

    stat = @statistics.result_receipts[false]

    assert_equal 1,   stat.count
    assert_equal 1.0, stat.mean
    assert_equal 0.0, stat.standard_deviation
  end

  def test_add_result_receipt_success
    result = @MS.new "\x04\x08\[\x06\"\x07OK"

    @statistics.add_result_receipt true, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 0, @statistics.drb_exceptions_raised

    stat = @statistics.result_receipts[true]

    assert_equal 1,   stat.count
    assert_equal 2.0, stat.mean
    assert_equal 0.0, stat.standard_deviation
  end

  def test_add_result_timestamp
    packet = packets(ARG_DUMP).first

    source      = packet.source      resolver
    destination = packet.destination resolver
    @statistics.last_peer_send[destination][source] = packet.timestamp
    @statistics.last_sent_message[destination][source] = 'message', 3

    @statistics.add_result_timestamp source, destination, packet.timestamp

    refute @statistics.last_peer_send[destination][source]
    assert_equal 1, @statistics.peer_latencies[destination][source].count

    stat = @statistics.message_latencies['message'][3]

    assert_equal 1,   stat.count
    assert_equal 0.0, stat.mean
    assert_equal 0.0, stat.standard_deviation
  end

  def test_adjust_units
    adjusted = @statistics.adjust_units [0.051, 0.2], 's'

    assert_in_epsilon 0.051, adjusted.shift
    assert_in_epsilon 0.2,   adjusted.shift
    assert_equal      's',   adjusted.shift
    assert_empty adjusted

    adjusted = @statistics.adjust_units [0.049, 0.2], 's'

    assert_in_epsilon  49.0, adjusted.shift
    assert_in_epsilon 200.0, adjusted.shift
    assert_equal       'ms', adjusted.shift
    assert_empty adjusted

  end

  def test_merge_results
    @statistics.message_allocations['one'][2]   = statistic
    @statistics.message_allocations['one'][3]   = statistic
    @statistics.message_allocations['three'][1] = statistic
    @statistics.message_latencies['one'][2]     = statistic
    @statistics.message_latencies['one'][3]     = statistic
    @statistics.message_latencies['three'][1]   = statistic

    _, _, _, allocation_rows =
      @statistics.extract_and_size @statistics.message_allocations
    _, _, _, latency_rows =
      @statistics.extract_and_size @statistics.message_latencies

    results = @statistics.merge_results allocation_rows, latency_rows

    expecteds = [
      ['one',   2, 9, 2.200, 5.809, 10.477, 3.199, 2.272, 4.166,  6.967, 2.476],
      ['one',   3, 6, 3.585, 6.488,  8.198, 1.646, 2.195, 6.282, 10.933, 2.901],
      ['three', 1, 4, 1.653, 3.696,  6.052, 2.298, 1.272, 5.401, 10.537, 2.954],
    ]

    assert_equal expecteds.size, results.size

    result   = results.shift
    expected = expecteds.shift

    assert_equal expected.shift, result.shift, 'message name'
    assert_equal expected.shift, result.shift, 'argument count'
    assert_equal expected.shift, result.shift, 'send count'

    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift
    assert_in_epsilon expected.shift, result.shift

    assert_empty result
    assert_empty expected
  end

  def test_show_basic
    @statistics.total_packet_count    = 5
    @statistics.rinda_packet_count    = 1
    @statistics.drb_packet_count      = 3
    @statistics.drb_message_sends     = 1
    @statistics.drb_result_receipts   = 2
    @statistics.drb_exceptions_raised = 1

    out, = capture_io do
      @statistics.show_basic
    end

    expected = <<-EXPECTED
5 total packets captured
1 Rinda packets captured
3 DRb packets captured
1 messages sent
2 results received
1 exceptions raised
    EXPECTED

    assert_equal expected, out
  end

  def test_show_peers
    @statistics.peer_latencies['a.example.50100']['b.example.51000'] = statistic
    @statistics.peer_latencies['b.example.51000']['a.example.50100'] = statistic
    @statistics.peer_latencies['c.example.52000']['a.example.50100'] = statistic

    out, = capture_io do
      @statistics.show_peers
    end

    expected = <<-EXPECTED
Peers min, avg, max, stddev:
9 messages from a.example.50100 to b.example.51000 2.200, 5.809, 10.477, 3.199 s
6 messages from b.example.51000 to a.example.50100 3.585, 6.488, 8.198, 1.646 s
4 messages from c.example.52000 to a.example.50100 1.653, 3.696, 6.052, 2.298 s
    EXPECTED

    assert_equal expected, out
  end

  def test_show_peers_collapse_singles
    s = DRbDump::Statistic.new
    s.add rand 2.0
    @statistics.peer_latencies['a.example.50100']['b.example.51000'] = s
    s = DRbDump::Statistic.new
    s.add rand 2.0
    @statistics.peer_latencies['b.example.51000']['a.example.50100'] = s
    s = DRbDump::Statistic.new
    s.add rand 2.0
    @statistics.peer_latencies['c.example.52000']['a.example.50100'] = s

    out, = capture_io do
      @statistics.show_peers
    end

    expected = <<-EXPECTED
Peers min, avg, max, stddev:
3 single-message peers 0.052, 0.674, 1.099, 0.551 s
    EXPECTED

    assert_equal expected, out
  end

  def test_show_per_message
    @statistics.message_allocations['one'][2]   = statistic
    @statistics.message_allocations['one'][3]   = statistic
    @statistics.message_allocations['three'][1] = statistic
    @statistics.message_latencies['one'][2]     = statistic
    @statistics.message_latencies['one'][3]     = statistic
    @statistics.message_latencies['three'][1]   = statistic

    out, = capture_io do
      @statistics.show_per_message
    end

    expected = <<-EXPECTED
Messages sent min, avg, max, stddev:
one   (2 args) 9 sent; 2.2, 5.8, 10.5, 3.2 allocations; 2.272, 4.166, 6.967, 2.476 s
one   (3 args) 6 sent; 3.6, 6.5, 8.2, 1.6 allocations; 2.195, 6.282, 10.933, 2.901 s
three (1 args) 4 sent; 1.7, 3.7, 6.1, 2.3 allocations; 1.272, 5.401, 10.537, 2.954 s
    EXPECTED

    assert_equal expected, out
  end

  def test_show_per_result
    @statistics.result_receipts[true]  = statistic
    @statistics.result_receipts[false] = statistic

    out, = capture_io do
      @statistics.show_per_result
    end

    expected = <<-EXPECTED
Results received min, avg, max, stddev:
success:   9 received; 2.2, 5.8, 10.5, 3.2 allocations
exception: 6 received; 3.6, 6.5, 8.2, 1.6 allocations
    EXPECTED

    assert_equal expected, out
  end

  def test_show_per_result_no_messages
    @statistics.result_receipts[true]  = DRbDump::Statistic.new
    @statistics.result_receipts[false] = DRbDump::Statistic.new

    assert_silent do
      @statistics.show_per_result
    end
  end

  def rand *args
    @random.rand(*args)
  end

  def statistic
    s = DRbDump::Statistic.new
    rand(1..20).times do
      s.add rand 1..11.0
    end
    s
  end

end

