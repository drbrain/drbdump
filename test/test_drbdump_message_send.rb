require 'drbdump/test_case'

class TestDRbDumpMessageSend < DRbDump::TestCase

  def setup
    super

    drbdump

    @packet = packets(ARG_DUMP).first

    receiver = Marshal::Structure.new "\x04\x080"
    msg = "\x00\x00\x00\x0b\x04\x08\"\x0cmessage"
    argc = "\x00\x00\x00\x04\x04\x08i\x08"
    argv = [
      "\x00\x00\x00\x05\x04\x08\"\x06a",
      "\x00\x00\x00\x05\x04\x08\"\x06b",
      "\x00\x00\x00\x05\x04\x08\"\x06c",
    ]
    block = "\x00\x00\x00\x03\x04\x080"

    stream = StringIO.new msg + argc + argv.join + block

    @ms = DRbDump::MessageSend.new @drbdump, @packet, receiver, stream
  end

  def test_allocations
    assert_equal 4, @ms.allocations
  end

  def test_arguments
    assert_equal '"a", "b", "c"', @ms.arguments
  end

  def test_argument_count
    assert_equal 3, @ms.argument_count
  end

  def test_argv
    assert_equal %w[a b c], @ms.argv
  end

  def test_block
    assert_nil @ms.block
  end

  def test_load_message
    assert_equal 'message', @ms.raw_message.load
    assert_equal 3,         @ms.argc
    assert_equal %w[a b c], @ms.raw_argv.map { |obj| obj.load }
    assert_nil              @ms.raw_block.load
  end

  def test_message
    assert_equal 'message', @ms.message
  end

  def test_receiver
    assert_nil @ms.receiver
  end

  def test_timestamp
    first, _, last = packets(FIN_DUMP).first 3

    ms = DRbDump::MessageSend.new @drbdump, last, nil, nil

    assert_equal last.timestamp, ms.timestamp

    @drbdump.incomplete_timestamps[first.source] = first.timestamp

    assert_equal first.timestamp, ms.timestamp
  end

  def test_to_a
    expected = [
      '23:46:20.561298',
      '"druby://kault:57317"',
      '"druby://kault:57315"',
      nil,
      'message',
      '"a", "b", "c"',
    ]

    assert_equal expected, @ms.to_a
  end

  def test_update_statistics
    @ms.update_statistics

    assert_equal 1, @statistics.drb_messages_sent
  end

end

