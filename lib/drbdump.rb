# coding: BINARY
require 'capp'
require 'drb'
require 'optparse'
require 'resolv'
require 'rinda/ring'
require 'stringio'
require 'thread'

##
# tcpdump for DRb
#
# == Usage
#
# The +drbdump+ command-line utility works similarly to tcpdump.  Here's the
# easiest way to get started:
#
#   sudo drbdump
#
# This captures DRb messages on your loopback and public interface.  You can
# disable name resolution with <code>-n</code>.  You can also drop root
# privileges with the -Z option if you don't want drbdump to run as root after
# it creates the capture device.
#
# == Output
#
# +drbdump+ reassembles TCP streams to create a complete message-send or
# message result and displays it to you when complete.  Here is an object in a
# Rinda::TupleSpace being renewed (checked if it is still alive), but broken
# into two lines:
#
#   17:46:27.818412 "druby://kault.local:65172" \u21d2
#                     ("druby://kault.local:63874", 70093484759080).renew()
#   17:46:27.818709 "druby://kault.local:65172" \u21d0
#                     "druby://kault.local:63874" success: 180
#
# The first two lines are the message-send.  The first field is the timestamp
# of the packet.  The second is the DRb peer the messages was sent from.
# The greater-than sign indicates this is a message-send.  The remainder is
# the DRb peer and object reference (7009...) the message is being sent to
# along with the message (+renew+).  If any arguments were present they would
# appear in the argument list.
#
# The URIs are quoted to make it easy to copy part of the message into irb if
# you want to perform further debugging.  For example, you can attach to the
# peer sending the message with:
#
#   >> sender = DRb::DRbObject.new_with_uri "druby://kault.local:65172"
#
# You can re-send the message by copying the message from the first
# open parenthesis to the end of the line:
#
#   >> DRb::DRbObject.new_with("druby://kault.local:63874", 70093484759080).
#        renew()
#
# For the second two lines are the return value from the message-send.  Here
# they are again:
#
#   17:46:27.818709 "druby://kault.local:65172" \u21d0
#                     "druby://kault.local:63874" success: 180
#
# The fields are the timestamp, the DRb peer that sent the message and is
# receiving the result, the DRb peer that received the message, "success" for
# a non-exception result and the response value.
#
# Unlike +tcpdump+ drbdump always shows the peer that send the message on the
# left and uses the arrow to indicate the direction of the message.
#
# Note that the message-send and its result may be separated by other messages
# and results, so you will need to check the port values to connect a message
# send to its result.
#
# == Statistics
#
# To run drbdump in a to only display statistical information, run:
#
#   drbdump -n -q -c 10000
#
# This disables name resolution and per-message output, collects 10,000
# messages then prints statistics at exit.  Depending on the diversity of
# messages in your application you may need to capture a different amount of
# packets.
#
# On supporting operating systems (OS X, BSD) you can send a SIGINFO
# (control-t) to display current statistics for the basic counters at any
# time:
#
#   load: 0.91  cmd: ruby 31579 running 2.48u 8.64s
#   29664 total packets captured
#   71 Rinda packets received
#   892 DRb packets received
#   446 messages sent
#   446 results received
#   0 exceptions raised
#
# These statistics are also printed when you quit drbdump.
#
# At exit, per-message statistics are displayed including message name, the
# number of argument count (to help distinguish between messages with the same
# name and different receivers), a statistical summary of allocations required
# to load the message's objects and a statistical summary of total latency
# (from first packet of the message-send to last packet of the message result:
#
#   Messages sent min, avg, max, stddev:
#   call         (1 args) 12 sent; 3.0, 3.0, 3.0, 0.0 allocations;
#                                  0.214, 1.335, 6.754, 2.008 ms
#   each         (1 args)  6 sent; 5.0, 5.0, 5.0, 0.0 allocations;
#                                  0.744, 1.902, 4.771, 1.918 ms
#   []           (1 args)  3 sent; 3.0, 3.0, 3.0, 0.0 allocations;
#                                  0.607, 1.663, 3.518, 1.612 ms
#   []=          (2 args)  3 sent; 5.0, 5.0, 5.0, 0.0 allocations;
#                                  0.737, 0.791, 0.839, 0.051 ms
#   add          (1 args)  2 sent; 3.0, 3.0, 3.0, 0.0 allocations;
#                                  0.609, 0.651, 0.694, 0.060 ms
#   update       (1 args)  2 sent; 3.0, 3.0, 3.0, 0.0 allocations;
#                                  0.246, 0.272, 0.298, 0.037 ms
#   add_observer (1 args)  1 sent; 5.0, 5.0, 5.0, 0.0 allocations;
#                                  1.689, 1.689, 1.689, 0.000 ms
#   respond_to?  (2 args)  1 sent; 4.0, 4.0, 4.0, 0.0 allocations;
#                                  0.597, 0.597, 0.597, 0.000 ms
#
# (The above has been line-wrapped, display output is one line per.)
#
# This helps you determine which message-sends are causing more network
# traffic or are less performant overall.  Some message-sends may be naturally
# long running so a high result latency may not be indicative of a
# poorly-performing method.
#
# Messages with higher numbers of allocations typically take longer to send
# and load and create more pressure on the garbage collector.  You can change
# locations that call these messages to use DRb::DRbObject references to help
# reduce the size of the messages sent.
#
# Switching entirely to sending references may increase latency as the remote
# end needs to continually ask the sender to invoke methods on its behalf.
#
# A summary of results is also shown:
#
#   Results received min, avg, max, stddev:
#   success:   24 received; 0.0, 0.6, 2.0, 0.9 allocations
#   exception:  2 received; 16.0, 16.0, 16.0, 0.0 allocations
#
# To help determine if changes you make are causing too many messages drbdump
# shows the number of messages sent between peers along with the message
# latency:
#
#   Peers min, avg, max, stddev:
#   6 messages from "druby://a.example:54167" to "druby://a.example:54157"
#              0.609, 1.485, 4.771, 1.621 ms
#   4 messages from "druby://a.example:54166" to "druby://a.example:54163"
#              1.095, 2.848, 6.754, 2.645 ms
#   3 messages from "druby://a.example:54162" to "druby://a.example:54159"
#              0.246, 0.380, 0.597, 0.189 ms
#   3 messages from "druby://a.example:54169" to "druby://a.example:54163"
#              0.214, 0.254, 0.278, 0.035 ms
#   2 messages from "druby://a.example:54168" to "druby://a.example:54163"
#              0.324, 0.366, 0.407, 0.059 ms
#   2 messages from "druby://a.example:54164" to "druby://a.example:54154"
#              0.607, 0.735, 0.863, 0.181 ms
#   2 messages from "druby://a.example:54160" to "druby://a.example:54154"
#              0.798, 2.158, 3.518, 1.923 ms
#   4 single-message peers 0.225, 0.668, 1.259, 0.435 ms
#
# (The above has been line-wrapped, display output is one line per.)
#
# To save terminal lines (the peers report can be long when many messages are
# captured) any single-peer results are wrapped up into a single line
# aggregate.
#
# An efficient API between peers would send the fewest messages with the
# fewest allocations.
#
# == Replaying packet logs
#
# You can capture and record packets with tcpdump then replay the captured
# file with drbdump.  To record captured packets use <code>tcpdump -w
# dump_file</code>:
#
#   $ tcpdump -i lo0 -w drb.pcap [filter]
#
# To replay the capture with drbdump give the path to the dump file to
# <code>drbdump -i</code>:
#
#   $ drbdump -i drb.pcap

class DRbDump

  ##
  # DRbDump error class

  class Error < RuntimeError
  end

  ##
  # The version of DRbDump you are using

  VERSION = '1.0'

  TIMESTAMP_FORMAT = '%H:%M:%S.%6N' # :nodoc:

  ##
  # Number of messages to process before stopping

  attr_accessor :count

  ##
  # Tracks if TCP packets contain DRb content or not

  attr_reader :drb_streams # :nodoc:

  ##
  # Queue of all incoming packets from Capp.

  attr_reader :incoming_packets # :nodoc:

  ##
  # Storage for incomplete DRb messages

  attr_reader :incomplete_streams # :nodoc:

  ##
  # The timestamp for the first packet added to an incomplete stream

  attr_reader :incomplete_timestamps # :nodoc:

  ##
  # The DRb protocol loader

  attr_reader :loader # :nodoc:

  ##
  # A Resolv-compatible DNS resolver for looking up host names

  attr_accessor :resolver

  ##
  # If true no per-packet information will be shown

  attr_accessor :quiet

  ##
  # Directory to chroot to after starting packet capture devices (which
  # require root privileges)
  #
  # Note that you will need to either set up a custom resolver that excludes
  # Resolv::Hosts or provide /etc/hosts in the chroot directory when setting
  # the run_as_directory.

  attr_accessor :run_as_directory

  ##
  # User to run as after starting packet capture devices (which require root
  # privileges)

  attr_accessor :run_as_user

  ##
  # Collects statistics on packets and messages.  See DRbDump::Statistics.

  attr_reader :statistics

  ##
  # Converts command-line arguments +argv+ into an options Hash

  def self.process_args argv
    options = {
      count:            Float::INFINITY,
      devices:          [],
      quiet:            false,
      resolve_names:    true,
      run_as_directory: nil,
      run_as_user:      nil,
    }

    op = OptionParser.new do |opt|
      opt.program_name = File.basename $0
      opt.version = VERSION
      opt.release = nil
      opt.banner = <<-BANNER
Usage: #{opt.program_name} [options]

  drbdump dumps DRb traffic from your local network.

  drbdump understands TCP traffic and Rinda broadcast queries.

  For information on drbdump output and usage see `ri DRbDump`.
      BANNER

      opt.separator nil

      opt.on('-c', '--count MESSAGES', Integer,
             'Capture the given number of message sends',
             'and exit, printing statistics.',
             "\n",
             'Use with -q to analyze a sample of traffic') do |count|
        options[:count] = count
      end

      opt.separator nil

      opt.on('-i', '--interface INTERFACE',
             'The interface to listen on or a tcpdump',
             'packet capture file.  Multiple interfaces',
             'can be specified.',
             "\n",
             'The tcpdump default interface and the',
             'loopback interface are the drbdump',
             'defaults') do |interface|
        options[:devices] << interface
      end

      opt.separator nil

      opt.on('-n', 'Disable name resolution') do |do_not_resolve_names|
        options[:resolve_names] = !do_not_resolve_names
      end

      opt.separator nil

      opt.on('-q', '--quiet',
             'Do not print per-message information.') do |quiet|
        options[:quiet] = quiet
      end

      opt.separator nil

      opt.on(      '--run-as-directory DIRECTORY',
             'chroot to the given directory after',
             'starting packet capture',
             "\n",
             'Note that you must disable name resolution',
             'or provide /etc/hosts in the chroot',
             'directory') do |directory|
        options[:run_as_directory] = directory
      end

      opt.separator nil

      opt.on('-Z', '--run-as-user USER',
             'Drop root privileges and run as the',
             'given user') do |user|
        options[:run_as_user] = user
      end
    end

    op.parse! argv

    options
  rescue OptionParser::ParseError => e
    $stderr.puts op
    $stderr.puts
    $stderr.puts e.message

    abort
  end

  ##
  # Starts dumping DRb traffic.

  def self.run argv = ARGV
    options = process_args argv

    new(options).run
  end

  ##
  # Creates a new DRbDump for +options+.  The following options are allowed:
  #
  # :devices::
  #   An Array of devices to listen on.  If the Array is empty then the
  #   default device (see Capp::default_device_name) and the loopback device
  #   are used.
  # :resolve_names::
  #   When true drbdump will look up address names.
  # :run_as_user::
  #   When set, drop privileges from root to this user after starting packet
  #   capture.
  # :run_as_directory::
  #   When set, chroot() to this directory after starting packet capture.
  #   Only useful with :run_as_user

  def initialize options
    @count                 = options[:count] || Float::INFINITY
    @drb_config            = DRb::DRbServer.make_config
    @incoming_packets      = Queue.new
    @incomplete_streams    = {}
    @incomplete_timestamps = {}
    @loader                = DRbDump::Loader.new @drb_config
    @quiet                 = options[:quiet]
    @resolver              = Resolv if options[:resolve_names]
    @run_as_directory      = options[:run_as_directory]
    @run_as_user           = options[:run_as_user]

    initialize_devices options[:devices]

    @capps       = []
    @drb_streams = {}
    @running     = false
    @statistics  = DRbDump::Statistics.new
  end

  def initialize_devices devices # :nodoc:
    @devices = devices

    if @devices.empty? then
      devices = Capp.devices

      abort "you must run #{$0} with root permissions, try sudo" if
        devices.empty?

      loopback = devices.find do |device|
        device.addresses.any? do |address|
          %w[127.0.0.1 ::1].include? address.address
        end
      end

      @devices = [
        Capp.default_device_name,
        (loopback.name rescue nil),
      ].compact
    end

    @devices.uniq!
  end

  ##
  # Loop that processes captured packets.

  def capture_loop capp # :nodoc:
    fin_or_rst = Capp::TCP_FIN | Capp::TCP_RST

    capp.loop do |packet|
      @statistics.total_packet_count += 1

      if packet.tcp? and 0 != packet.tcp_header.flags & fin_or_rst then
        close_stream packet.source

        next
      end

      next if @drb_streams[packet.source] == false

      @incoming_packets.enq packet
    end
  end

  ##
  # Removes tracking data for the stream from +source+

  def close_stream source # :nodoc:
    @drb_streams.delete source
    @incomplete_streams.delete source
    @incomplete_timestamps.delete source
  end

  ##
  # Creates a new Capp instance that listens on +device+ for DRb and Rinda
  # packets

  def create_capp device # :nodoc:
    capp = Capp.open device

    capp.filter = <<-FILTER
      (tcp and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)) or
      (tcp[tcpflags] & (tcp-fin|tcp-rst) != 0) or
      (udp port #{Rinda::Ring_PORT})
    FILTER

    capp
  end

  ##
  # Displays information from Rinda::RingFinger packet +packet+
  #
  # Currently only understands RingFinger broadcast packets.

  def display_ring_finger packet
    @statistics.rinda_packet_count += 1

    return if @quiet

    obj = Marshal.load packet.payload

    (_, tell), timeout = obj

    puts '%s find ring on %s for %s timeout: %d' % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      packet.destination(@resolver), tell.__drburi,
      timeout
    ]
  rescue
  end

  ##
  # Displays information from the possible DRb packet +packet+

  def display_drb packet
    return unless @running
    return unless stream = packet_stream(packet)

    source = packet.source

    first_chunk = @loader.load stream

    case first_chunk.load
    when nil, Integer then
      message = DRbDump::MessageSend.new self, packet, first_chunk, stream

      display_drb_send message

      stop if @statistics.drb_messages_sent >= count
    when true, false then
      result = DRbDump::MessageResult.new self, packet, first_chunk, stream

      display_drb_recv result
    end

    @statistics.drb_packet_count += 1
    @drb_streams[source] = true
    @incomplete_timestamps.delete source
  rescue DRbDump::Loader::TooLarge
    display_drb_too_large packet
  rescue DRbDump::Loader::Premature, DRbDump::Loader::DataError
    @incomplete_streams[source] = stream.string
    @incomplete_timestamps[source] ||= packet.timestamp
  rescue DRbDump::Loader::Error
    @drb_streams[source] = false
  end

  ##
  # Writes a DRb packet for a message recv to standard output.

  def display_drb_recv result
    result.update_statistics

    return if @quiet

    puts "%s %s %s %s %s: %s" % result.to_a
  end

  ##
  # Writes a DRb packet for a message-send to standard output.

  def display_drb_send message # :nodoc:
    message.update_statistics

    return if @quiet

    puts "%s %s \u21d2 (%s, %p).%s(%s)" % message.to_a
  end

  ##
  # Writes the start of a DRb stream from a packet that was too large to
  # transmit.

  def display_drb_too_large packet
    return if @quiet

    rest = packet.payload

    source, destination = resolve_addresses packet

    valid, size, rest = valid_in_payload rest

    puts '%s %s to %s packet too large, valid: [%s] too big (%d bytes): %s' % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      source, destination,
      valid.join(', '), size, rest.dump
    ]
  end

  ##
  # Displays each captured packet.

  def display_packets
    @running = true

    @display_thread = Thread.new do
      while @running and packet = @incoming_packets.deq do
        if packet.udp? then
          display_ring_finger packet
        else
          display_drb packet
        end
      end
    end
  end

  ##
  # Loads Marshal data in +object+ if possible, or returns a DRb::DRbUnknown
  # if there was some error

  def load_marshal_data object
    object.load
  rescue NameError, ArgumentError => e
    DRb::DRbUnknown.new e, object.stream
  end

  ##
  # Returns a StringIO created from packets that are part of the TCP
  # connection in +stream+.
  #
  # Returns nil if the stream is not a DRb message stream or the packet is
  # empty.

  def packet_stream packet # :nodoc:
    payload = packet.payload

    return if payload.empty?

    source = packet.source

    if previous = @incomplete_streams.delete(source) then
      payload = previous << payload
    elsif /\A....\x04\x08/m !~ payload then
      @drb_streams[source] = false
      return
    end

    stream = StringIO.new payload
    stream.set_encoding Encoding::BINARY, Encoding::BINARY
    stream
  end

  ##
  # Resolves source and destination addresses in +packet+ for use in DRb URIs

  def resolve_addresses packet
    source = packet.source @resolver
    source = "\"druby://#{source.sub(/\.(\d+)$/, ':\1')}\""

    destination = packet.destination @resolver
    destination = "\"druby://#{destination.sub(/\.(\d+)$/, ':\1')}\""

    return source, destination
  end

  ##
  # Captures packets and displays them on the screen.

  def run
    capps = @devices.map { |device| create_capp device }

    Capp.drop_privileges @run_as_user, @run_as_directory

    start_capture capps

    trap_info

    display_packets.join
  rescue Interrupt
    untrap_info

    stop

    @display_thread.join

    puts # clear ^C

    exit
  ensure
    @statistics.show
  end

  ##
  # Captures DRb packets and feeds them to the incoming_packets queue

  def start_capture capps
    @capps.concat capps

    capps.map do |capp|
      Thread.new do
        capture_loop capp
      end
    end
  end

  ##
  # Stops the message capture and packet display.  If root privileges were
  # dropped message capture cannot be restarted.

  def stop
    @running = false

    @capps.each do |capp|
      capp.stop
    end

    @incoming_packets.enq nil
  end

  ##
  # Adds a SIGINFO handler if the OS supports it

  def trap_info
    return unless Signal.list['INFO']

    trap 'INFO' do
      @statistics.show_basic
    end
  end

  ##
  # Sets the SIGINFO handler to the DEFAULT handler

  def untrap_info
    return unless Signal.list['INFO']

    trap 'INFO', 'DEFAULT'
  end

  ##
  # Returns the valid parts, the size and content of the invalid part in
  # +large_packet+

  def valid_in_payload too_large
    load_limit = @drb_config[:load_limit]

    size  = nil
    valid = []

    loop do
      size, too_large = too_large.unpack 'Na*'

      break if load_limit < size

      valid << Marshal.load(too_large.slice!(0, size)).inspect
    end

    return valid, size, too_large
  end

end

require 'drbdump/loader'
require 'drbdump/message_send'
require 'drbdump/message_result'
require 'drbdump/statistic'
require 'drbdump/statistics'
