# coding: BINARY

require 'capp'
require 'drb'
require 'resolv'
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
  # Queue of all incoming packets from Capp.

  attr_reader :incoming_packets

  ##
  # A Resolv-compatible DNS resolver for looking up host names

  attr_accessor :resolver

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
  # Starts dumping DRb traffic.

  def self.run argv = ARGV
    device = argv.shift || Capp.default_device_name

    new(device).run
  end

  ##
  # Creates a new DRbDump that listens on +device+.  If no device is given the
  # default device is used.
  #
  # See also Capp::default_device_name.

  def initialize device = Capp.default_device_name
    @device = device

    @drb_config       = DRb::DRbServer.make_config
    @incoming_packets = Queue.new
    @loader           = DRb::DRbMessage.new @drb_config
    @resolver         = Resolv
    @run_as_directory = nil
    @run_as_user      = nil
  end

  ##
  # Captures DRb TCP packets

  def capture_drb_tcp
    Thread.new do
      capp = Capp.open @device
      capp.filter = 'tcp'

      capp.loop do |packet|
        @incoming_packets.enq packet
      end
    end
  end

  ##
  # Captures RingFinger broadcasts

  def capture_ring_finger
    Thread.new do
      capp = Capp.open @device
      capp.filter = 'udp port 7647'

      capp.loop do |packet|
        @incoming_packets.enq packet
      end
    end
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
  rescue
  end

  ##
  # Displays information from the possible DRb packet +packet+

  def display_drb packet
    payload = packet.payload

    return if payload.empty?
    return unless payload =~ /\A....\x04\x08/m

    stream = StringIO.new payload

    first_chunk = @loader.load stream

    case first_chunk
    when nil, String then
      display_drb_send packet, first_chunk, stream
    when true, false then
      display_drb_recv packet, first_chunk, stream
    else
      # ignore
    end
  rescue DRb::DRbConnError
    # ignore
  end

  ##
  # Writes a DRb packet for a message recv to standard output.

  def display_drb_recv packet, success, stream
    result = @loader.load stream

    puts "%s %s > %s: success: %s result: %s" % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      packet.source(@resolver), packet.destination(@resolver),
      success, result
    ]
  end

  ##
  # Writes a DRb packet for a message send to standard output.

  def display_drb_send packet, ref, stream # :nodoc:
    ref ||= '(front)'
    msg = @loader.load stream
    argc = @loader.load stream
    argv = Array.new argc do
      @loader.load stream
    end
    block = @loader.load stream

    argv << '&block' if block

    puts '%s %s > %s: %s.%s(%s)' % [
      packet.timestamp.strftime(TIMESTAMP_FORMAT),
      packet.source(@resolver), packet.destination(@resolver),
      ref, msg, argv.join(', ')
    ]
  end

  ##
  # Displays each captured packet.

  def display_packets
    Thread.new do
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
  # Drop privileges

  def drop_privileges
    return unless Process.uid.zero? and Process.euid.zero?
    return unless @run_as_user or @run_as_directory

    raise DRbDump::Error, 'chroot without dropping root is insecure' if
      @run_as_directory and not @run_as_user

    require 'etc'

    begin
      pw = Etc.getpwnam @run_as_user
    rescue ArgumentError
      raise DRbDump::Error, "could not find user #{@run_as_user}"
    end

    if @run_as_directory then
      begin
        Dir.chroot @run_as_directory
        Dir.chdir '/'
      rescue Errno::ENOENT
        raise DRbDump::Error,
          "could not chroot or chdir to #{@run_as_directory}"
      end
    end

    begin
      Process.gid = pw.gid
      Process.uid = pw.uid
    rescue Errno::EPERM
      raise DRbDump::Error, "unable to drop privileges to #{@run_as_user}"
    end

    true
  end

  ##
  # Captures packets and displays them on the screen.

  def run
    capture_ring_finger

    capture_drb_tcp

    drop_privileges

    display_packets.join
  end

end

