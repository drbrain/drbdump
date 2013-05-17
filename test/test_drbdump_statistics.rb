require 'drbdump/test_case'

class TestDRbDumpStatistics < DRbDump::TestCase

  def setup
    super

    @MS = Marshal::Structure

    @statistics = DRbDump::Statistics.new
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

    expected = {
      M_2:    0.0,
      mean:  10.0,
      count:  1,
    }

    assert_equal expected, @statistics.message_sends['message'][3]
  end

  def test_add_result_receipt_exception
    result = @MS.new "\x04\x08\"\x09FAIL" # not an exception

    @statistics.add_result_receipt false, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 1, @statistics.drb_exceptions_raised

    expected = {
      M_2:   0.0,
      mean:  1.0,
      count: 1,
    }

    assert_equal expected, @statistics.result_receipts[false]
  end

  def test_add_result_receipt_success
    result = @MS.new "\x04\x08\[\x06\"\x07OK"

    @statistics.add_result_receipt true, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 0, @statistics.drb_exceptions_raised

    expected = {
      M_2:   0.0,
      mean:  2.0,
      count: 1,
    }

    assert_equal expected, @statistics.result_receipts[true]
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

  def test_show_per_message
    @statistics.message_sends['one'][2] = {
      M_2:   0.25,
      mean:  8.0,
      count: 4,
    }
    @statistics.message_sends['one'][3] = {
      M_2:    0.5,
      mean:  12.0,
      count:  2,
    }
    @statistics.message_sends['three'][1] = {
      M_2:    0.0,
      mean:   2.0,
      count: 20,
    }

    out, = capture_io do
      @statistics.show_per_message
    end

    expected = <<-EXPECTED
Messages sent:
one   (2 args)  4 sent, average of   8.0 allocations,   0.289 std. dev.
one   (3 args)  2 sent, average of  12.0 allocations,   0.707 std. dev.
three (1 args) 20 sent, average of   2.0 allocations,   0.000 std. dev.
    EXPECTED

    assert_equal expected, out
  end

  def test_show_per_result
    @statistics.result_receipts[true] = {
      M_2:    0.1,
      mean:   9.5,
      count: 20,
    }
    @statistics.result_receipts[false] = {
      M_2:    0.25,
      mean:  20.0,
      count:  4,
    }

    out, = capture_io do
      @statistics.show_per_result
    end

    expected = <<-EXPECTED
Results received:
success:   20 received, average of   9.5 allocations,   0.073 std. dev.
exception:  4 received, average of  20.0 allocations,   0.289 std. dev.
    EXPECTED

    assert_equal expected, out
  end

end

