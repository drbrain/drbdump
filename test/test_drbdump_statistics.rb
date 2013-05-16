require 'drbdump/test_case'

class TestDRbDumpStatistics < DRbDump::TestCase

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

