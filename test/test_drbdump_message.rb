require 'drbdump/test_case'

class TestDRbDumpMessage < DRbDump::TestCase

  def setup
    super

    drbdump

    @packet = packets(ARG_DUMP).first

    @m = DRbDump::Message.new @drbdump, @packet
  end

  def test_destination
    assert_equal '"druby://kault:57315"', @m.destination
  end

  def test_resolve_addresses
    @m.resolve_addresses

    assert_equal '"druby://kault:57317"', @m.source
    assert_equal '"druby://kault:57315"', @m.destination
  end

  def test_source
    assert_equal '"druby://kault:57317"', @m.source
  end

end

