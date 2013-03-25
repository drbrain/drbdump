require 'drb'
require 'capp'
require 'thread'

##
# tcpdump for DRb

class DRbDump

  ##
  # The version of DRbDump you are using

  VERSION = '1.0'

  ##
  # Creates a new DRbDump that listens on +device+.  If no device is given the
  # default device is used.
  #
  # See also Capp::default_device_name.

  def initialize device = Capp.default_device_name
    @device = device

    @packet_queue = Queue.new
  end

  ##
  # Captures RingFinger broadcasts

  def capture_ring_finger
    Thread.new do
      capp = Capp.live @device
      capp.filter = 'udp port 7647'

      capp.loop do |packet|
        @packet_queue.enq packet
      end
    end
  end

  ##
  # Displays information from +packet+
  #
  # Currently only understands RingFinger broadcast packets.

  def display packet
    payload = packet.ip_payload[8, packet.capture_length]
    obj = Marshal.load payload

    if obj.first.first == :lookup_ring then
      time = packet.timestamp.strftime '%H:%M:%S.%6N'
      (_, tell), timeout = obj
      puts "#{time} find ring for #{tell.__drburi} timeout #{timeout}"
    else
      puts payload.dump
    end
  end

  ##
  # Displays each captured packet.

  def display_packets
    Thread.new do
      while packet = @packet_queue.deq do
        display packet
      end
    end
  end

  ##
  # Captures packets and displays them on the screen.

  def run
    display = display_packets

    capture_ring_finger

    display.join
  end

end

