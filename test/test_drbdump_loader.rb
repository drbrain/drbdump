require 'drbdump/test_case'

class TestDRbDumpLoader < DRbDump::TestCase

  def setup
    super

    @loader = DRbDump::Loader.new load_limit: 40
  end

  def test_load
    ms = load "\x00\x00\x00\x05\x04\x08[\x06T"

    assert_equal "\x04\x08[\x06T", ms.stream
  end

  def test_load_marshal_read_error
    stream = Object.new
    stream.instance_variable_set :@read, false
    def stream.read(size)
      raise if @read

      @read = true

      "\x00\x00\x00\x05"
    end

    assert_raises DRbDump::Loader::DataError do
      @loader.load stream
    end
  end

  def test_load_marshal_too_short
    assert_raises DRbDump::Loader::Premature do
      load "\x00\x00\x00\x05\x04\x08[\x06"
    end
  end

  def test_load_no_marshal
    stream = Object.new
    stream.instance_variable_set :@read, false
    def stream.read(size)
      return nil if @read

      @read = true

      "\x00\x00\x00\x05"
    end

    assert_raises DRbDump::Loader::DataError do
      @loader.load stream
    end
  end

  def test_load_no_size
    assert_raises DRbDump::Loader::SizeError do
      load ''
    end
  end

  def test_load_size_read_error
    stream = Object.new
    def stream.read() end # ArgumentError

    assert_raises DRbDump::Loader::SizeError do
      @loader.load stream
    end
  end

  def test_load_size_too_short
    assert_raises DRbDump::Loader::Premature do
      load "\x00\x00\x00"
    end
  end

  def test_load_size_too_long
    assert_raises DRbDump::Loader::TooLarge do
      load [41].pack 'N'
    end
  end

  def load stream
    stream = StringIO.new stream
    @loader.load stream
  end

end

