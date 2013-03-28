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

    @drb_config = DRb::DRbServer.make_config

    @udp_incoming = Queue.new
    @tcp_incoming = Queue.new
  end

  ##
  # Captures DRb TCP packets

  def capture_drb_tcp
    Thread.new do
      capp = Capp.live @device
      capp.filter = 'ip and tcp'

      capp.loop do |packet|
        @tcp_incoming.enq packet
      end
    end
  end

  ##
  # Captures RingFinger broadcasts

  def capture_ring_finger
    Thread.new do
      capp = Capp.live @device
      capp.filter = 'udp port 7647'

      capp.loop do |packet|
        @udp_incoming.enq packet
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

    message = DRb::DRbMessage.new @drb_config

    ref = message.load(stream) || '(front)'
    msg = message.load stream
    argc = message.load stream
    argv = Array.new argc do
      message.load stream
    end
    block = message.load stream

    puts "%s %s:%d > %s:%d: %s.%s(%s)" % [
      time,
      packet.ipv4_header.source,      packet.tcp_header.source_port,
      packet.ipv4_header.destination, packet.tcp_header.destination_port,
      ref, msg, argv.join(', ')
    ]
  rescue DRb::DRbConnError
    return unless ref && msg

    puts "%s %s:%d > %s:%d: success: %s result: %s" % [
      time,
      packet.ipv4_header.source,      packet.tcp_header.source_port,
      packet.ipv4_header.destination, packet.tcp_header.destination_port,
      ref, msg
    ]
  end

  ##
  # Displays each captured packet.

  def display_packets
    Thread.new do
      while packet = @udp_incoming.deq do
        display_ring_finger packet
      end
    end

    Thread.new do
      while packet = @tcp_incoming.deq do
        display_drb packet
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

