require 'minitest/autorun'
require 'drbdump'

class TestDRbDumpStatistics < MiniTest::Unit::TestCase

  ARG_DUMP       = File.expand_path '../arg.dump',     __FILE__
  FIN_DUMP       = File.expand_path '../drb_fin.dump', __FILE__
  HTTP_DUMP      = File.expand_path '../http.dump',    __FILE__
  PING_DUMP      = File.expand_path '../ping.dump',    __FILE__
  RING_DUMP      = File.expand_path '../ring.dump',    __FILE__
  TOO_LARGE_DUMP = File.expand_path '../too_large_packet.pcap', __FILE__

  def test_show
    drbdump

    capture_io do
      packets(ARG_DUMP).each do |packet|
        @drbdump.display_drb packet
      end
    end

    out, = capture_io do
      @statistics.show
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
    @drbdump = DRbDump.new devices: [file]

    @statistics = @drbdump.statistics

    @drbdump
  end

  def packets file
    Capp.open(file).loop
  end

end

