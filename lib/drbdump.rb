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
# On supported operating systems you can send a SIGINFO (control-t) to display
# current statistics for the basic counters:
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
# drbdump also displays per-message statistics at which include the number of
# messages sent per argument count (to help distinguish between messages with
# the same name but on different receivers) along with the average number of
# allocations and the standard deviation of allocations required to load the
# object:
#
#   Messages sent:
#   ping (2 args) 1003 sent, average of   8.405 allocations,   2.972 std. dev.
#
#   Results received:
#   success:   1003 received, average of   7.405 allocations,   2.972 std. dev.
#   exception:    1 received, average of      15 allocations,     NaN std. dev.
#
# This helps you determine which message-sends are causing more network
# traffic.  Messages with higher numbers of allocations take longer to send
# and load and create more pressure on the garbage collector.  You can change
# locations that call these messages to use DRb::DRbObject references to help
# reduce the size of the messages sent.
#
# Switching entirely to sending references may increase latency as the remote
# end needs to continually ask the sender to invoke methods on its behalf.  To
# help determine if changes you make are causing too many messages drbdump
# shows the number of messages sent between peers:
#
#   Peers:
#   30 messages from "druby://a.example:54430" to "druby://b.example:54428"
#   10 messages from "druby://b.example:54427" to "druby://a.example:54425"
#    5 messages from "druby://a.example:54433" to "druby://c.example:54431"
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

  attr_reader :incomplete_drb # :nodoc:

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
    @count            = options[:count] || Float::INFINITY
    @devices          = options[:devices]
    @drb_config       = DRb::DRbServer.make_config
    @incoming_packets = Queue.new
    @incomplete_drb   = {}
    @loader           = DRbDump::Loader.new @drb_config
    @quiet            = options[:quiet]
    @resolver         = Resolv if options[:resolve_names]
    @run_as_directory = options[:run_as_directory]
    @run_as_user      = options[:run_as_user]

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

    @capps       = []
    @drb_streams = {}
    @running     = false
    @statistics  = DRbDump::Statistics.new
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
    payload = packet.payload

    return unless @running
    return if payload.empty?

    source = packet.source

    if previous = @incomplete_drb.delete(source) then
      payload = previous << payload
    elsif /\A....\x04\x08/m !~ payload then
      @drb_streams[source] = false
      return
    end

    stream = StringIO.new payload
    stream.set_encoding Encoding::BINARY, Encoding::BINARY

    first_chunk = @loader.load stream

    case first_chunk.load
    when nil, Integer then
      display_drb_send packet, first_chunk, stream

      stop if @statistics.drb_message_sends >= count
    when true, false then
      display_drb_recv packet, first_chunk, stream
    else
      return # ignore
    end

    @statistics.drb_packet_count += 1
    @drb_streams[source] = true
  rescue DRbDump::Loader::TooLarge
    display_drb_too_large packet
  rescue DRbDump::Loader::Premature, DRbDump::Loader::DataError
    @incomplete_drb[source] = payload
  rescue DRbDump::Loader::Error
    @drb_streams[source] = false
  end

  ##
  # Writes a DRb packet for a message recv to standard output.

  def display_drb_recv packet, success, stream
    success = success.load
    result  = @loader.load stream

    @statistics.add_result_receipt success, result

    return if @quiet

    result = load_marshal_data result

    result = if DRb::DRbObject === result then
               "(\"druby://#{result.__drburi}\", #{result.__drbref})"
             else
               result.inspect
             end

    message = success ? 'success' : 'exception'
    arrow   = success ? "\u21d0"  : "\u2902"

    source, destination = resolve_addresses packet

    puts "%s %s %s %s %s: %s" % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      destination, arrow, source,
      message, result
    ]
  end

  ##
  # Writes a DRb packet for a message-send to standard output.

  def display_drb_send packet, ref, stream # :nodoc:
    msg   = @loader.load stream
    argc  = @loader.load(stream).load
    argv  = argc.times.map do @loader.load stream end
    block = @loader.load stream

    @statistics.add_message_send ref, msg, argv, block

    source, destination = resolve_addresses packet

    @statistics.add_peer source, destination

    return if @quiet

    ref = ref.load

    argv.map! { |obj| load_marshal_data(obj).inspect }
    (argv << '&block') if block.load
    argv = argv.join ', '

    puts "%s %s \u21d2 (%s, %p).%s(%s)" % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      source, destination,
      ref, msg.load, argv
    ]
  end

  ##
  # Writes the start of a DRb stream from a packet that was too large to
  # transmit.

  def display_drb_too_large packet
    return if @quiet

    load_limit = @drb_config[:load_limit]
    rest = packet.payload

    source, destination = resolve_addresses packet

    size  = nil
    valid = []

    loop do
      size, rest = rest.unpack 'Na*'

      break if load_limit < size

      valid << Marshal.load(rest.slice!(0, size)).inspect
    end

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
        fin_or_rst = Capp::TCP_FIN | Capp::TCP_RST

        capp.loop do |packet|
          @statistics.total_packet_count += 1

          if packet.tcp? and 0 != packet.tcp_header.flags & fin_or_rst then
            @drb_streams.delete packet.source
            @incomplete_drb.delete packet.source
            next
          end

          next if @drb_streams[packet.source] == false

          @incoming_packets.enq packet
        end
      end
    end
  end

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

end

require 'drbdump/loader'
require 'drbdump/statistics'
