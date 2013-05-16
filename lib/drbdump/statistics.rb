##
# Collects and displays statistics on captured packets.

class DRbDump::Statistics

  ##
  # Number of DRb exceptions raised

  attr_accessor :drb_exceptions_raised

  ##
  # Number of DRb results received

  attr_accessor :drb_result_receipts

  ##
  # Number of DRb messages sent

  attr_accessor :drb_message_sends

  ##
  # Number of DRb packets seen

  attr_accessor :drb_packet_count

  ##
  # Number of Rinda packets seen

  attr_accessor :rinda_packet_count

  ##
  # Number of packets seen, including non-DRb traffic

  attr_accessor :total_packet_count

  def initialize # :nodoc:
    @drb_exceptions_raised = 0
    @drb_result_receipts   = 0
    @drb_message_sends     = 0
    @drb_packet_count      = 0
    @rinda_packet_count    = 0
    @total_packet_count    = 0
  end

  ##
  # Writes statistics on packets and messages processed to $stdout

  def show
    puts "#{@total_packet_count} total packets captured"
    puts "#{@rinda_packet_count} Rinda packets captured"
    puts "#{@drb_packet_count} DRb packets captured"
    puts "#{@drb_message_sends} messages sent"
    puts "#{@drb_result_receipts} results received"
    puts "#{@drb_exceptions_raised} exceptions raised"
  end

end

