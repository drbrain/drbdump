##
# Wraps a DRb message-result after consuming it from a stream.

class DRbDump::MessageResult

  def initialize drbdump, packet, status, stream
    @drbdump    = drbdump
    @loader     = drbdump.loader
    @packet     = packet
    @result     = nil
    @statistics = drbdump.statistics
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
  # The resolved destination for the result.

  def destination
    return @destination if @destination

    resolve_addresses

    @destination
  end

  ##
  # Resolves source and destination addresses

  def resolve_addresses # :nodoc:
    resolver = @drbdump.resolver

    source = @packet.source resolver
    @source = "\"druby://#{source.sub(/\.(\d+)$/, ':\1')}\""

    destination = @packet.destination resolver
    @destination = "\"druby://#{destination.sub(/\.(\d+)$/, ':\1')}\""
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
  # The resolved source of the message

  def source
    return @source if @source

    resolve_addresses

    @source
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
  # The message as an Array usable by sprintf

  def to_a
    message   = status ? 'success' : 'exception'
    arrow     = status ? "\u21d0"  : "\u2902"
    timestamp = @packet.timestamp.strftime DRbDump::TIMESTAMP_FORMAT

    [timestamp, destination, arrow, source, message, result]
  end

  ##
  # Updates the drbdump's statistics with information from this result.

  def update_statistics # :nodoc:
    @statistics.add_result self
  end

end

