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
  # Records the last timestamp for a message sent between peers

  attr_accessor :last_peer_send

  ##
  # Records the last message sent between peers

  attr_accessor :last_sent_message

  ##
  # Records statistics about allocations required to send a message.  The
  # outer key is the message name while the inner key is the argument count
  # (including block).

  attr_accessor :message_allocations

  ##
  # Records statistics about latencies for sent messages.  The outer key is
  # the message name while the inner key is the argument count (including
  # block).
  #
  # The recorded latency is from the first packet in the message-send to the
  # last packet in the message result.

  attr_accessor :message_latencies

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

    # [message][argc]
    @message_allocations = two_level_statistic_hash
    @message_latencies   = two_level_statistic_hash

    # [source][destination]
    @peer_latencies = two_level_statistic_hash

    @last_peer_send = Hash.new do |sources, source|
      sources[source] = Hash.new
    end

    @last_sent_message = Hash.new do |sources, source|
      sources[source] = Hash.new
    end

    @result_receipts = Hash.new do |result_receipts, success|
      result_receipts[success] = DRbDump::Statistic.new
    end
  end

  ##
  # Adds information from +message+

  def add_message_send message
    @drb_message_sends += 1

    msg  = message.message
    argc = message.argument_count

    source      = message.source
    destination = message.destination

    @message_allocations[msg][argc].add message.allocations
    @last_peer_send[source][destination] = message.timestamp
    @last_sent_message[source][destination] = msg, argc
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
    message, argc = @last_sent_message[destination].delete source

    return unless sent_timestamp

    latency = timestamp - sent_timestamp

    @peer_latencies[destination][source].add latency
    @message_latencies[message][argc].add latency

    latency
  end

  def adjust_units stats, unit # :nodoc:
    if stats.first > 0.05 then
      stats << unit
      return stats
    end

    unit.replace "m#{unit}"

    stats = stats.map { |stat| stat * 1000 }

    stats << unit
  end

  def extract_and_size data # :nodoc:
    max_outer_size = 0
    max_inner_size = 0
    max_count      = 0

    rows = []

    data.each do |outer_key, inner|
      max_outer_size = [max_outer_size, outer_key.to_s.size].max

      inner.each do |inner_key, stat|
        count, *rest = stat.to_a

        rows << [outer_key, inner_key, count, *rest]

        max_inner_size = [max_inner_size, inner_key.to_s.size].max
        max_count      = [max_count, count].max
      end
    end

    max_count_size = max_count.to_s.size

    return max_outer_size, max_inner_size, max_count_size, rows
  end

  def merge_results allocation_rows, latency_rows
    allocations = allocation_rows.group_by { |message, argc,| [message, argc] }
    latencies   = latency_rows.group_by { |message, argc,| [message, argc] }

    allocations.map do |group, (row, _)|
      latency_row, = latencies.delete(group)

      if latency_row then
        row.concat latency_row.last 4
      else
        row.concat [0, 0, 0, 0]
      end
    end
  end

  def multiple_peers count_size, source_size, destination_size, rows # :nodoc:
    rows = rows.sort_by { |_, _, count| -count }

    rows.map do |source, destination, count, *stats|
      stats = adjust_units stats, 's'

      '%2$*1$d messages from %4$*3$s to %6$*5$s ' % [
        count_size, count, source_size, source, destination_size, destination
      ] +
      '%0.3f, %0.3f, %0.3f, %0.3f %s' % stats
    end
  end

  def per_message_results
    name_size, argc_size, sends_size, allocation_rows =
      extract_and_size @message_allocations

    _, _, _, latency_rows = extract_and_size @message_latencies

    rows = merge_results allocation_rows, latency_rows

    rows.sort_by { |message, argc, count,| [-count, message, argc] }

    return name_size, argc_size, sends_size, rows
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

    multiple, single = rows.partition { |_, _, count| count > 1 }

    multiple << single.pop if single.length == 1

    count_size = [count_size, single.length.to_s.size].max

    puts 'Peers min, avg, max, stddev:'
    puts multiple_peers count_size, source_size, destination_size, multiple
    puts single_peers count_size, single unless single.empty?
  end

  ##
  # Shows per-message-send statistics including arguments per calls, count of
  # calls and average and standard deviation of allocations.

  def show_per_message # :nodoc:
    name_size, argc_size, sends_size, rows = per_message_results

    output = rows.map do |message, argc, count, *stats|
      allocation_stats = stats.first 4
      latency_stats   = adjust_units stats.last(4), 's'

      '%-2$*1$s (%4$*3$s args) %6$*5$d sent; ' % [
          name_size, message, argc_size, argc, sends_size, count,
      ] +
      '%0.1f, %0.1f, %0.1f, %0.1f allocations; ' % allocation_stats +
      '%0.3f, %0.3f, %0.3f, %0.3f %s' % latency_stats
    end

    puts 'Messages sent min, avg, max, stddev:'
    puts output
  end

  ##
  # Shows per-result statistics including amount of normal and exception
  # results, average allocations per result and standard deviation of
  # allocations.

  def show_per_result
    success_count,   *success_stats   = @result_receipts[true].to_a
    exception_count, *exception_stats = @result_receipts[false].to_a

    return if success_count.zero? and exception_count.zero?

    count_width = [success_count.to_s.length, exception_count.to_s.length].max

    puts 'Results received min, avg, max, stddev:'
    unless success_count.zero? then
      print 'success:   %2$*1$s received; ' % [count_width, success_count]
      puts '%0.1f, %0.1f, %0.1f, %0.1f allocations' % success_stats
    end

    unless exception_count.zero? then
      print 'exception: %2$*1$s received; ' % [count_width, exception_count]
      puts '%0.1f, %0.1f, %0.1f, %0.1f allocations' % exception_stats
    end
  end

  def single_peers count_size, rows # :nodoc:
    return if rows.empty?

    statistic = DRbDump::Statistic.new

    rows.each do |_, _, _, value|
      statistic.add value
    end

    count, *stats = statistic.to_a

    stats = adjust_units stats, 's'

    '%2$*1$d single-message peers ' % [count_size, count] +
    '%0.3f, %0.3f, %0.3f, %0.3f %s' % stats
  end

end

