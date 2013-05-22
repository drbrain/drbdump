require 'drbdump/test_case'

class TestDRbDumpStatistics < DRbDump::TestCase

  def setup
    super

    @MS = Marshal::Structure

    @statistics = DRbDump::Statistics.new
    @random = Random.new 2
  end

  def test_add_message_send
    receiver = @MS.new "\x04\x080"
    message  = @MS.new "\x04\x08\"\x0cmessage"
    argv = [
      @MS.new("\x04\x08[\x06\"\x06a"),
      @MS.new("\x04\x08[\x07\"\x06a\"\x06b"),
      @MS.new("\x04\x08[\x08\"\x06a\"\x06b\"\x06c"),
    ]
    block = @MS.new "\x04\x080"

    @statistics.add_message_send receiver, message, argv, block

    assert_equal 1, @statistics.drb_message_sends

    stat = @statistics.message_sends['message'][3]

    assert_equal  1,    stat.count
    assert_equal 10.0,  stat.mean
    assert_equal 'NaN', stat.standard_deviation.to_s
  end

  def test_add_result_receipt_exception
    result = @MS.new "\x04\x08\"\x09FAIL" # not an exception

    @statistics.add_result_receipt false, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 1, @statistics.drb_exceptions_raised

    stat = @statistics.result_receipts[false]

    assert_equal  1,    stat.count
    assert_equal 1.0,   stat.mean
    assert_equal 'NaN', stat.standard_deviation.to_s
  end

  def test_add_result_receipt_success
    result = @MS.new "\x04\x08\[\x06\"\x07OK"

    @statistics.add_result_receipt true, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 0, @statistics.drb_exceptions_raised

    stat = @statistics.result_receipts[true]

    assert_equal  1,    stat.count
    assert_equal 2.0,   stat.mean
    assert_equal 'NaN', stat.standard_deviation.to_s
  end

  def test_add_result_timestamp
    packet = packets(ARG_DUMP).first

    source      = packet.source      resolver
    destination = packet.destination resolver
    @statistics.add_send_timestamp destination, source, packet.timestamp

    @statistics.add_result_timestamp source, destination, packet.timestamp

    refute @statistics.last_peer_send[destination][source]
    assert_equal 1, @statistics.peer_latencies[destination][source].count
  end

  def test_add_send_timestamp
    packet = packets(ARG_DUMP).first

    source      = packet.source      resolver
    destination = packet.destination resolver

    @statistics.add_send_timestamp source, destination, packet.timestamp

    assert_equal packet.timestamp,
                 @statistics.last_peer_send[source][destination]
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
Peers:
8 messages from a.example.50100 to b.example.51000 average 5.804 s, 3.420 std. dev.
5 messages from b.example.51000 to a.example.50100 average 6.493 s, 1.840 std. dev.
1 messages from c.example.52000 to a.example.50100 average 5.942 s, NaN std. dev.
    EXPECTED

    assert_equal expected, out
  end

  def test_show_per_message
    @statistics.message_sends['one'][2]   = statistic
    @statistics.message_sends['one'][3]   = statistic
    @statistics.message_sends['three'][1] = statistic

    out, = capture_io do
      @statistics.show_per_message
    end

    expected = <<-EXPECTED
Messages sent:
one   (2 args) 8 sent, average of   5.8 allocations,   3.420 std. dev.
one   (3 args) 5 sent, average of   6.5 allocations,   1.840 std. dev.
three (1 args) 1 sent, average of   5.9 allocations,     NaN std. dev.
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
Results received:
success:   8 received, average of   5.8 allocations,   3.420 std. dev.
exception: 5 received, average of   6.5 allocations,   1.840 std. dev.
    EXPECTED

    assert_equal expected, out
  end

  def statistic
    s = DRbDump::Statistic.new
    @random.rand(19 + 1).times do
      s.add @random.rand(10.0) + 1
    end
    s
  end

end

