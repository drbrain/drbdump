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
#   drbdump
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
# current statistics:
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
  # Number of DRb exceptions raised

  attr_reader :drb_exceptions_raised

  ##
  # Number of DRb results received

  attr_reader :drb_result_receipts

  ##
  # Number of DRb messages sent

  attr_reader :drb_message_sends

  ##
  # Number of DRb packets seen

  attr_reader :drb_packet_count

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
  # Number of Rinda packets seen

  attr_reader :rinda_packet_count

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
  # Number of packets seen, including non-DRb traffic

  attr_reader :total_packet_count

  ##
  # Converts command-line arguments +argv+ into an options Hash

  def self.process_args argv
    options = {
      devices:          [],
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

      opt.on('-i', '--interface INTERFACE',
             'The interface to listen on or a tcpdump',
             'packet capture file.  Multiple interfaces',
             'can be specified.',
             "\n",
             'The tcpdump default interface is also the',
             'drbdump default') do |interface|
        options[:devices] << interface
      end

      opt.separator nil

      opt.on('-n', 'Disable name resolution') do |do_not_resolve_names|
        options[:resolve_names] = !do_not_resolve_names
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
    @devices          = options[:devices]
    @drb_config       = DRb::DRbServer.make_config
    @incoming_packets = Queue.new
    @incomplete_drb   = {}
    @loader           = DRb::DRbMessage.new @drb_config
    @resolver         = Resolv if options[:resolve_names]
    @run_as_directory = options[:run_as_directory]
    @run_as_user      = options[:run_as_user]

    if @devices.empty? then
      loopback = Capp.devices.find do |device|
        device.addresses.any? do |address|
          %w[127.0.0.1 ::1].include? address.address
        end
      end.name

      @devices = [
        Capp.default_device_name,
        loopback,
      ]
    end

    @drb_exceptions_raised = 0
    @drb_result_receipts   = 0
    @drb_message_sends     = 0
    @drb_packet_count      = 0
    @drb_streams           = {}
    @rinda_packet_count    = 0
    @total_packet_count    = 0
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
    obj = Marshal.load packet.payload

    time = packet.timestamp.strftime TIMESTAMP_FORMAT
    (_, tell), timeout = obj

    puts '%s find ring on %s for %s timeout: %d' % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      packet.destination(@resolver), tell.__drburi,
      timeout
    ]

    @rinda_packet_count += 1
  rescue
  end

  ##
  # Displays information from the possible DRb packet +packet+

  def display_drb packet
    payload = packet.payload

    return if payload.empty?

    source = packet.source

    if previous = @incomplete_drb.delete(source) then
      payload = previous << payload
    elsif /\A....\x04\x08/m !~ payload then
      @drb_streams[source] = false
      return
    end

    stream = StringIO.new payload

    first_chunk = @loader.load stream

    case first_chunk
    when nil, Integer then
      display_drb_send packet, first_chunk, stream
    when true, false then
      display_drb_recv packet, first_chunk, stream
    else
      return # ignore
    end

    @drb_packet_count += 1
    @drb_streams[source] = true
  rescue DRb::DRbConnError => e
    case e.message
    when "premature marshal format(can't read)" then
      @incomplete_drb[source] = payload
    when /^too large packet / then
      display_drb_too_large packet
    else
      @drb_streams[source] = false
    end
  end

  ##
  # Writes a DRb packet for a message recv to standard output.

  def display_drb_recv packet, success, stream
    result = @loader.load stream

    @drb_result_receipts += 1
    @drb_exceptions_raised += 1 unless success

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
    ref   = 'nil' unless ref
    msg   = @loader.load stream
    argc  = @loader.load stream
    argv  = argc.times.map do @loader.load stream end
    block = @loader.load stream

    @drb_message_sends += 1

    argv << '&block' if block

    source, destination = resolve_addresses packet

    puts "%s %s \u21d2 (%s, %s).%s(%s)" % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      source, destination,
      ref, msg, argv.map { |obj| obj.inspect }.join(', ')
    ]
  end

  ##
  # Writes the start of a DRb stream from a packet that was too large to
  # transmit.

  def display_drb_too_large packet
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
    @display_thread = Thread.new do
      while packet = @incoming_packets.deq do
        if packet.udp? then
          display_ring_finger packet
        else
          display_drb packet
        end
      end
    end
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

    capp.stop

    @incoming_packets.enq nil

    @display_thread.join

    puts # clear ^C
    show_statistics

    exit
  end

  ##
  # Writes statistics on packets and messages processed to $stdout

  def show_statistics
    puts "#{@total_packet_count} total packets captured"
    puts "#{@rinda_packet_count} Rinda packets captured"
    puts "#{@drb_packet_count} DRb packets captured"
    puts "#{@drb_message_sends} messages sent"
    puts "#{@drb_result_receipts} results received"
    puts "#{@drb_exceptions_raised} exceptions raised"
  end

  ##
  # Captures DRb packets and feeds them to the incoming_packets queue

  def start_capture capps
    capps.map do |capp|
      Thread.new do
        fin_or_rst = Capp::TCP_FIN | Capp::TCP_RST

        capp.loop do |packet|
          @total_packet_count += 1

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

  ##
  # Adds a SIGINFO handler if the OS supports it

  def trap_info
    return unless Signal.list['INFO']

    trap 'INFO' do
      show_statistics
    end
  end

  ##
  # Sets the SIGINFO handler to the DEFAULT handler

  def untrap_info
    return unless Signal.list['INFO']

    trap 'INFO', 'DEFAULT'
  end

end

