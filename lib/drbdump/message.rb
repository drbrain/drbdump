##
# Contains common parts of MessageSend and MessageResult

class DRbDump::Message

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

