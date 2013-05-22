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
  # Records the last timestamp for a message sent between peers

  attr_accessor :last_peer_send

  ##
  # Records statistics about latencies for messages sent between peers

  attr_accessor :peer_latencies

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
        arg_counts[argc] = DRbDump::Statistic.new
      end
    end

    # [message][argc]
    @message_sends = two_level_statistic_hash

    # [source][destination]
    @peer_latencies = two_level_statistic_hash

    @last_peer_send = Hash.new do |sources, source|
      sources[source] = Hash.new
    end

    @result_receipts = Hash.new do |result_receipts, success|
      result_receipts[success] = DRbDump::Statistic.new
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

    @message_sends[message.load][argc].add allocations
  end

  ##
  # Adds a result-receipt to the counter

  def add_result_receipt success, result
    @drb_result_receipts += 1
    @drb_exceptions_raised += 1 unless success

    @result_receipts[success].add result.count_allocations
  end

  ##
  # Adds a result +timestamp+ for a message between +source+ and +destination+

  def add_result_timestamp source, destination, timestamp
    sent_timestamp = @last_peer_send[destination].delete source

    return unless sent_timestamp

    latency = timestamp - sent_timestamp

    @peer_latencies[destination][source].add latency

    latency
  end

  ##
  # Adds one extra peer contact between +source+ and +destination+ that
  # finished sending at +timestamp+

  def add_send_timestamp source, destination, timestamp
    @last_peer_send[source][destination] = timestamp
  end

  def extract_and_size data # :nodoc:
    max_outer_size = 0
    max_inner_size = 0
    max_count      = 0

    rows = []

    data.each do |outer_key, inner|
      max_outer_size = [max_outer_size, outer_key.to_s.size].max

      inner.each do |inner_key, stat|
        count, mean, std_dev = stat.to_a

        rows << [outer_key, inner_key, count, mean, std_dev]

        max_inner_size = [max_inner_size, inner_key.to_s.size].max
        max_count      = [max_count, count].max
      end
    end

    max_count_size = max_count.to_s.size

    return max_outer_size, max_inner_size, max_count_size, rows
  end

  def two_level_statistic_hash # :nodoc:
    Hash.new do |outer, outer_key|
      outer[outer_key] = Hash.new do |inner, inner_key|
        inner[inner_key] = DRbDump::Statistic.new
      end
    end
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
    source_size, destination_size, count_size, rows =
      extract_and_size @peer_latencies

    rows = rows.sort_by { |_, _, count| -count }

    output = rows.map do |source, destination, count, mean, std_dev|
      unit = 's'

      if mean < 1 then
        mean    *= 1000
        std_dev *= 1000
        unit = 'ms'
      end

      '%2$*1$s messages from %4$*3$s to %6$*5$s ' % [
        count_size, count, source_size, source, destination_size, destination
      ] +
      'average %0.3f %s, %0.3f std. dev.' % [
        mean, unit, std_dev
      ]
    end

    puts 'Peers:'
    puts output
  end

  ##
  # Shows per-message-send statistics including arguments per calls, count of
  # calls and average and standard deviation of allocations.

  def show_per_message
    name_size, argc_size, sends_size, rows = extract_and_size @message_sends

    rows.sort_by { |message, argc,| [message, argc] }

    output = rows.map do |message, argc, count, mean, std_dev|
      '%-2$*1$s (%4$*3$s args) %6$*5$d sent, ' % [
          name_size, message, argc_size, argc, sends_size, count,
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
    success_count,   *success_stats   = @result_receipts[true].to_a
    exception_count, *exception_stats = @result_receipts[false].to_a

    count_width = [success_count.to_s.length, exception_count.to_s.length].max

    puts 'Results received:'
    print 'success:   %2$*1$s received, ' % [count_width, success_count]
    puts 'average of %5.1f allocations, %7.3f std. dev.' % success_stats
    print 'exception: %2$*1$s received, ' % [count_width, exception_count]
    puts 'average of %5.1f allocations, %7.3f std. dev.' % exception_stats
  end

end

