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
  # Records statistics about message sends.  The outer key is the message name
  # while the inner key is the argument count (including block).

  attr_accessor :message_sends

  ##
  # Counts message sent between peers.

  attr_accessor :peer_counts

  ##
  # Records statistics about result receipts.  +true+ is used for successful
  # messages while +false+ is used for exceptions.

  attr_accessor :result_receipts

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

    @message_sends = Hash.new do |message_sends, message|
      message_sends[message] = Hash.new do |arg_counts, argc|
        arg_counts[argc] = {
          M_2:   0.0,
          mean:  0.0,
          count: 0,
        }
      end
    end

    @peer_counts = Hash.new do |counts, source|
      counts[source] = Hash.new 0
    end

    @result_receipts = Hash.new do |result_receipts, success|
      result_receipts[success] = {
        M_2:   0.0,
        mean:  0.0,
        count: 0,
      }
    end
  end

  ##
  # Adds a message-send to the counters

  def add_message_send receiver, message, argv, block
    @drb_message_sends += 1

    argc = argv.length
    argc += 1 if block.load

    allocations = 0

    allocations += receiver.count_allocations
    allocations += message.count_allocations
    argv.each { |arg| allocations += arg.count_allocations }
    allocations += block.count_allocations

    stats = @message_sends[message.load][argc]

    update_statistics stats, allocations
  end

  ##
  # Adds one extra peer contact between +source+ and +destination+

  def add_peer source, destination
    @peer_counts[source][destination] += 1
  end

  ##
  # Adds a result-receipt to the counter

  def add_result_receipt success, result
    @drb_result_receipts += 1
    @drb_exceptions_raised += 1 unless success

    stats = @result_receipts[success]

    update_statistics stats, result.count_allocations
  end

  def row_statistics stats # :nodoc:
    count, m_2, mean = stats.values_at :count, :M_2, :mean

    std_dev = Math.sqrt m_2 / (count - 1)

    [count, mean, std_dev]
  end

  ##
  # Writes all statistics on packets and messages processesed to $stdout

  def show
    show_basic
    puts
    show_per_message
    puts
    show_per_result
    puts
    show_peers
  end

  ##
  # Writes basic statistics on packets and messages processed to $stdout

  def show_basic
    puts "#{@total_packet_count} total packets captured"
    puts "#{@rinda_packet_count} Rinda packets captured"
    puts "#{@drb_packet_count} DRb packets captured"
    puts "#{@drb_message_sends} messages sent"
    puts "#{@drb_result_receipts} results received"
    puts "#{@drb_exceptions_raised} exceptions raised"
  end

  ##
  # Shows peer statistics

  def show_peers
    rows = []

    max_count         = 0
    destination_width = 0
    source_width      = 0

    @peer_counts.each do |source, destinations|
      source_width = [source_width, source.length].max

      destinations.each do |destination, count|
        destination_width = [destination_width, destination.length].max
        max_count         = [max_count, count].max

        rows << [count, source, destination]
      end
    end

    count_width = max_count.to_s.length

    rows = rows.sort_by { |count,| -count }

    output = rows.map do |count, source, destination|
      '%2$*1$s messages from %4$*3$s to %6$*5$s' % [
        count_width, count, source_width, source,
        destination_width, destination
      ]
    end

    puts 'Peers:'
    puts output
  end

  ##
  # Shows per-message-send statistics including arguments per calls, count of
  # calls and average and standard deviation of allocations.

  def show_per_message
    max_name_size = 0
    max_argc      = 0
    max_sends     = 0

    rows = []

    @message_sends.each do |message, argc_counts|
      max_name_size = [max_name_size, message.length].max

      argc_counts.each do |argc, stats|
        count, m_2, mean = stats.values_at :count, :M_2, :mean

        std_dev = Math.sqrt m_2 / (count - 1)

        rows << [message, argc, count, mean, std_dev]

        max_argc  = [max_argc, argc].max
        max_sends = [max_sends, stats[:count]].max
      end
    end

    rows.sort_by { |message, argc,| [message, argc] }

    sends_width = max_sends.to_s.length
    argc_width  = max_argc.to_s.length

    output = rows.map do |message, argc, count, mean, std_dev|
      '%-2$*1$s (%4$*3$s args) %6$*5$d sent, ' % [
          max_name_size, message, argc_width, argc, sends_width, count,
      ] + 
      'average of %5.1f allocations, %7.3f std. dev.' % [mean, std_dev]
    end  

    puts 'Messages sent:'
    puts output
  end

  ##
  # Shows per-result statistics including amount of normal and exception
  # results, average allocations per result and standard deviation of
  # allocations.

  def show_per_result
    success_count,   *success_stats   = row_statistics @result_receipts[true]
    exception_count, *exception_stats = row_statistics @result_receipts[false]

    count_width = [success_count.to_s.length, exception_count.to_s.length].max

    puts 'Results received:'
    print 'success:   %2$*1$s received, ' % [count_width, success_count]
    puts 'average of %5.1f allocations, %7.3f std. dev.' % success_stats
    print 'exception: %2$*1$s received, ' % [count_width, exception_count]
    puts 'average of %5.1f allocations, %7.3f std. dev.' % exception_stats
  end

  ##
  # Updates +m_2+ (used to calculate the standard deviation) and the +mean+
  # for the +index+th item of +value+.
  #
  # Returns the updated +m_2+ and +mean+

  def update_statistics stats, value # :nodoc:
    m_2   = stats[:M_2]
    mean  = stats[:mean]
    index = stats[:count] + 1

    delta = value - mean
    mean += delta / index
    m_2 += delta * (value - mean)

    stats[:M_2]  = m_2
    stats[:mean] = mean
    stats[:count]            = index
  end

end

