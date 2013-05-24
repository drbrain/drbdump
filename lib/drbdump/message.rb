##
# Contains common parts of MessageSend and MessageResult

class DRbDump::Message

  ##
  # Creates the appropriate message instance from the next +packet+ which was
  # captured by +drbdump+ on the given +stream+.

  def self.from_stream drbdump, packet, stream
    loader = drbdump.loader

    first_chunk = loader.load stream

    case first_chunk.load
    when nil, Integer then
      DRbDump::MessageSend.new drbdump, packet, first_chunk, stream
    when true, false then
      DRbDump::MessageResult.new drbdump, packet, first_chunk, stream
    end
  end

  ##
  # Initializes a message from +packet+ captured by a +drbdump+

  def initialize drbdump, packet
    @drbdump     = drbdump
    @loader      = drbdump.loader
    @packet      = packet
    @statistics  = drbdump.statistics

    @source      = nil
    @destination = nil
  end

  ##
  # The resolved destination for the message.

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
  # The resolved source of the message

  def source
    return @source if @source

    resolve_addresses

    @source
  end

end

