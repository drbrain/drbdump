require 'marshal/structure'

##
# A DRb protocol message chunk loader.
#
# Based on DRb::DRbMessage

class DRbDump::Loader

  ##
  # Base Loader error class

  class Error < DRbDump::Error; end

  ##
  # Raised when the message content is missing or too short

  class DataError < Error; end

  ##
  # Raised when the packet is too large

  class TooLarge < Error; end

  ##
  # Raised when the packet is not large enough to complete a message

  class Premature < Error; end

  ##
  # Raised when the message size is incorrect or missing

  class SizeError < Error; end

  ##
  # Creates a new loader with the given +config+ Hash.  The loader uses only
  # the :load_limit key to limit the maximum message size.

  def initialize config
    @load_limit = config[:load_limit]
  end

  ##
  # Returns the next component from a DRb message +stream+ as a
  # Marshal::Structure object.

  def load stream
    begin
      size = stream.read 4
    rescue => e
      raise SizeError, e.message, e.backtrace
    end

    raise SizeError, 'connection closed' unless size
    raise Premature, 'header' if size.size < 4

    size, = size.unpack 'N'

    raise TooLarge, "#{size} bytes (#{@load_limit} allowed)" if
      size >= @load_limit

    begin
      data = stream.read size
    rescue => e
      raise DataError, e.message, e.backtrace
    end

    raise DataError, 'connection closed' unless data
    raise Premature, 'Marshal' if data.bytesize < size

    Marshal::Structure.new data
  end

end

