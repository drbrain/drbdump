require 'drbdump/test_case'

class TestDRbDumpMessageResult < DRbDump::TestCase

  def setup
    super

    drbdump

    @packet = packets(ARG_DUMP).first

    status = Marshal::Structure.new "\x04\x08T"
    value  = StringIO.new "\x00\x00\x00\x08\x04\x08\[\x06\"\x07OK"

    @mr = DRbDump::MessageResult.new @drbdump, @packet, status, value
  end

  def test_allocations
    assert_equal 2, @mr.allocations
  end

  def test_display
    out, = capture_io do
      @mr.display
    end

    expected = <<-EXPECTED
23:46:20.561298 "druby://kault:57315" \u21d0 "druby://kault:57317" success: ["OK"]
    EXPECTED

    assert_equal expected, out

    assert_equal 1, @statistics.drb_results_received
  end

  def test_display_quiet
    @drbdump.quiet = true

    assert_silent do
      @mr.display
    end

    assert_equal 1, @statistics.drb_results_received
  end

  def test_result
    assert_equal '["OK"]', @mr.result
  end

  def test_status
    assert_equal true, @mr.status
  end

  def test_timestamp
    first, _, last = packets(FIN_DUMP).first 3

    ms = DRbDump::MessageSend.new @drbdump, last, nil, nil

    assert_equal last.timestamp, ms.timestamp

    @drbdump.incomplete_timestamps[first.source] = first.timestamp

    assert_equal first.timestamp, ms.timestamp
  end

  def test_update_statistics
    @mr.update_statistics

    assert_equal 1, @statistics.drb_results_received
  end

end

