##
# Wraps a DRb message-result after consuming it from a stream.

class DRbDump::MessageResult < DRbDump::Message

  ##
  # Creates a new MessageResult for the creating +drbdump+ instance.  The last
  # packet in the message is +packet+ and the Marshal::Structure for the
  # result type is +status+.  The rest of the message will be loaded from
  # +stream+.

  def initialize drbdump, packet, status, stream
    super drbdump, packet

    @result     = nil
    @status     = nil
    @stream     = stream

    @raw_result = @loader.load stream
    @raw_status = status
  end

  ##
  # The number of allocations required to load the result.

  def allocations
    @raw_status.count_allocations + @raw_result.count_allocations
  end

  ##
  # Prints the message information to standard output

  def display
    update_statistics

    return if @drbdump.quiet

    message   = status ? 'success' : 'exception'
    arrow     = status ? "\u21d0"  : "\u2902"
    timestamp = self.timestamp.strftime DRbDump::TIMESTAMP_FORMAT

    puts "%s %s %s %s %s: %s" % [
      timestamp, destination, arrow, source, message, result
    ]
  end

  ##
  # The loaded result object

  def result
    return @result if @result

    result = @drbdump.load_marshal_data @raw_result

    @result = if DRb::DRbObject === result then
               "(\"druby://#{result.__drburi}\", #{result.__drbref})"
             else
               result.inspect
             end
  end

  ##
  # The loaded status object

  def status
    @status ||= @raw_status.load
  end

  ##
  # The timestamp of the last packet in the result

  def timestamp
    @packet.timestamp
  end

  ##
  # Updates the drbdump's statistics with information from this result.

  def update_statistics # :nodoc:
    @statistics.add_result self
  end

end

