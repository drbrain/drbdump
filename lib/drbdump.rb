# coding: BINARY

require 'capp'
require 'drb'
require 'stringio'
require 'thread'

##
# tcpdump for DRb

class DRbDump

  ##
  # The version of DRbDump you are using

  VERSION = '1.0'

  attr_reader :incoming_packets

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
  end

  ##
  # Captures DRb TCP packets

  def capture_drb_tcp
    Thread.new do
      capp = Capp.open @device
      capp.filter = 'ip and tcp'

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

    if Array === obj and Array === obj.first and
       obj.first.first == :lookup_ring then
      time = packet.timestamp.strftime '%H:%M:%S.%6N'
      (_, tell), timeout = obj
      puts "#{time} find ring for #{tell.__drburi} timeout #{timeout}"
    else
      p obj
    end
  rescue
    p $!
  end

  ##
  # Displays information from the possible DRb packet +packet+

  def display_drb packet
    payload = packet.payload

    return if payload.empty?
    return unless payload =~ /\A....\x04\x08/m

    time = packet.timestamp.strftime '%H:%M:%S.%6N'

    stream = StringIO.new payload

    ref = @loader.load stream

    case ref
    when nil, String then
      ref ||= '(front)'
      msg = @loader.load stream
      argc = @loader.load stream
      argv = Array.new argc do
        @loader.load stream
      end
      block = @loader.load stream

      puts "%s %s:%d > %s:%d: %s.%s(%s)" % [
        time,
        packet.ipv4_header.source,      packet.tcp_header.source_port,
        packet.ipv4_header.destination, packet.tcp_header.destination_port,
        ref, msg, argv.join(', ')
      ]
    when true, false then
      result = @loader.load stream

      puts "%s %s:%d > %s:%d: success: %s result: %s" % [
        time,
        packet.ipv4_header.source,      packet.tcp_header.source_port,
        packet.ipv4_header.destination, packet.tcp_header.destination_port,
        ref, result
      ]
    else
      # ignore
    end
  rescue DRb::DRbConnError
    # ignore
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
  # Captures packets and displays them on the screen.

  def run
    display = display_packets

    capture_ring_finger

    capture_drb_tcp

    display.join
  end

end

