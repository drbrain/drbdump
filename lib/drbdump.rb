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
      device:           nil,
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
      BANNER

      opt.separator nil

      opt.on('-i', '--interface INTERFACE',
             'The interface to listen on or a tcpdump',
             'packet capture file',
             "\n",
             'The tcpdump default interface is also the',
             'drbdump default') do |interface|
        options[:device] = interface
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
  # Creates a new DRbDump that listens on +device+.  If no device is given the
  # default device is used.
  #
  # See also Capp::default_device_name.

  def initialize options
    @device           = options[:device] || Capp.default_device_name
    @drb_config       = DRb::DRbServer.make_config
    @incoming_packets = Queue.new
    @incomplete_drb   = {}
    @loader           = DRb::DRbMessage.new @drb_config
    @resolver         = Resolv if options[:resolve_names]
    @run_as_directory = options[:run_as_directory]
    @run_as_user      = options[:run_as_user]

    @drb_exceptions_raised = 0
    @drb_result_receipts   = 0
    @drb_message_sends     = 0
    @drb_packet_count      = 0
    @drb_streams           = {}
    @rinda_packet_count    = 0
    @total_packet_count    = 0
  end

  ##
  # Creates a new Capp instance that packets DRb and Rinda packets

  def create_capp # :nodoc:
    capp = Capp.open @device

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
    puts "#{time} find ring for #{tell.__drburi} timeout #{timeout}"

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

    source, destination = resolve_addresses packet

    puts '%s %s < %s %s: %s' % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      destination, source,
      message, result
    ]
  end

  ##
  # Writes a DRb packet for a message send to standard output.

  def display_drb_send packet, ref, stream # :nodoc:
    ref   = 'nil' unless ref
    msg   = @loader.load stream
    argc  = @loader.load stream
    argv  = argc.times.map do @loader.load stream end
    block = @loader.load stream

    @drb_message_sends += 1

    argv << '&block' if block

    source, destination = resolve_addresses packet

    puts '%s %s > (%s, %s).%s(%s)' % [
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
    capp = create_capp

    Capp.drop_privileges @run_as_user, @run_as_directory

    start_capture capp

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

  def start_capture capp
    @capture_thread = Thread.new do
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

