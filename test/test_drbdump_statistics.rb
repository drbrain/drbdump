require 'drbdump/test_case'

class TestDRbDumpStatistics < DRbDump::TestCase

  def setup
    super

    @MS = Marshal::Structure

    @statistics = DRbDump::Statistics.new
  end

  def test_add_message_send
    receiver = @MS.new "\x04\x080"
    message  = @MS.new "\x04\x08\"\x0emessage"
    argv = [
      @MS.new("\x04\x08i\x00"),
      @MS.new("\x04\x08i\x05"),
      @MS.new("\x04\x08i\x06"),
    ]
    block = @MS.new "\x04\x080"

    @statistics.add_message_send receiver, message, argv, block

    assert_equal 1, @statistics.drb_message_sends
  end

  def test_add_result_receipt_exception
    result = @MS.new "\x04\x08\"\x08FAIL" # not an exception

    @statistics.add_result_receipt false, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 1, @statistics.drb_exceptions_raised
  end

  def test_add_result_receipt_success
    result = @MS.new "\x04\x08\"\x06OK"

    @statistics.add_result_receipt true, result

    assert_equal 1, @statistics.drb_result_receipts
    assert_equal 0, @statistics.drb_exceptions_raised
  end

  def test_show_basic
    drbdump

    capture_io do
      packets(ARG_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    out, = capture_io do
      @statistics.show_basic
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

end

