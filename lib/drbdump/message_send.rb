##
# Wraps a DRb message-send after consuming it from a stream.

class DRbDump::MessageSend < DRbDump::Message

  ##
  # The number of arguments, not including the block

  attr_reader :argc

  ##
  # The arguments, each as a Marshal::Structure

  attr_reader :raw_argv

  ##
  # The block as a Marshal::Structure

  attr_reader :raw_block

  ##
  # The message sent as a Marshal::Structure

  attr_reader :raw_message

  ##
  # Creates a new MessageSend for the creating +drbdump+ instance.  The last
  # packet in the message is +packet+ and the Marshal::Structure for the first
  # argument is +receiver+.  The rest of the message will be loaded from
  # +stream+.

  def initialize drbdump, packet, receiver, stream
    super drbdump, packet

    @argc         = nil
    @argv         = nil
    @block        = nil
    @message      = nil
    @raw_receiver = receiver
    @stream       = stream

    load_message if stream
  end

  ##
  # The number of allocations required to load the message.

  def allocations
    allocations = 0

    allocations += @raw_receiver.count_allocations
    allocations += @raw_message.count_allocations
    @raw_argv.each { |arg| allocations += arg.count_allocations }
    allocations += @raw_block.count_allocations

    allocations
  end

  ##
  # A string containing all loaded arguments including the block.

  def arguments
    arguments = argv.map { |obj| obj.inspect }
    (arguments << '&block') if block
    arguments.join ', '
  end

  ##
  # Number of arguments including the block

  def argument_count
    @argc + (block ? 1 : 0)
  end

  ##
  # The loaded arguments

  def argv
    @argv ||= @raw_argv.map { |obj| @drbdump.load_marshal_data obj }
  end

  ##
  # The loaded block

  def block
    @block ||= @raw_block.load
  end

  ##
  # Prints the message information to standard output

  def display
    update_statistics

    return if @drbdump.quiet

    timestamp = self.timestamp.strftime DRbDump::TIMESTAMP_FORMAT

    puts "%s %s \u21d2 (%s, %p).%s(%s)" % [
      timestamp, source, destination, receiver, message, arguments
    ]
  end

  ##
  # Returns the message, arguments and block for the DRb message-send in
  # +stream+.

  def load_message # :nodoc:
    @raw_message = @loader.load @stream
    @argc        = @loader.load(@stream).load
    @raw_argv    = @argc.times.map { @loader.load @stream }
    @raw_block   = @loader.load @stream
  end

  ##
  # The loaded message

  def message
    @message ||= @raw_message.load
  end

  ##
  # The loaded receiver for the message

  def receiver
    @receiver ||= @raw_receiver.load
  end

  ##
  # Returns the timestamp for the first packet in the incomplete stream for
  # +packet+ or the packet's timestamp if this is the only packet in the
  # stream.

  def timestamp
    @drbdump.incomplete_timestamps.delete(@packet.source) || @packet.timestamp
  end

  ##
  # Updates the drbdump's statistics with information from this message.

  def update_statistics # :nodoc:
    @statistics.add_message_send self
  end

end

