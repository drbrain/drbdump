require 'drb'
require 'rinda/rinda'
require 'rinda/tuplespace'

##
# A multiprocess primes generator using DRb and Rinda::TupleSpace.
#
# A distributed program using a TupleSpace has very regular message patterns,
# so it is easy to see how the program is working using drbdump.  On the
# downside, this example isn't great at showing off the higher-level analysis
# of drbdump as the messages sent are of a small set with a consistent
# argument size.
#
# == Implementation Notes
#
# This program uses two TupleSpace streams and one TupleSpace counter.
#
# The first stream is the primes stream which contains the index of each found
# prime.
#
# The second stream contains checked values and is used to order insertion
# into the primes stream (so that 5 doesn't appear before 3).
#
# The counter is used to determine the next candidate value.
#
# See the book How to Write Parallel Programs: A First Course by Carriero and
# Gelernter at http://www.lindaspaces.com/book/ for a complete discussion of
# TupleSpaces.

class Primes

  ##
  # Setup for the process hosting the TupleSpace.

  def initialize
    @children    = []
    @tuple_space = Rinda::TupleSpace.new

    DRb.start_service nil, @tuple_space

    @uri = DRb.uri
  end

  ##
  # Retrieves prime +index+ from the primes stream.  This method will block if
  # the given prime is being checked in another process.

  def get_prime index
    _, _, value = @tuple_space.read [:primes, index, nil]

    value
  end

  ##
  # Finds the next prime by dividing the next candidate value against other
  # found primes

  def find_prime
    index = 0
    candidate = next_candidate
    max       = Math.sqrt(candidate).ceil

    prime = loop do
      test = get_prime index
      index += 1

      break true if test >= max

      _, remainder = candidate.divmod test

      break false if remainder.zero?
    end

    mark_checked candidate, prime
  end

  ##
  # Forks a worker child

  def fork_child
    Thread.start do
      pid = fork do
        DRb.stop_service

        DRb.start_service

        processor
      end

      Process.wait pid
    end
  end

  ##
  # Determines the next index where a value can be added to the +stream+.

  def head_index stream
    head = :"#{stream}_head"
    _, index = @tuple_space.take [head, nil]

    index
  ensure
    @tuple_space.write [head, index + 1]
  end

  ##
  # Marks +value+ as checked.  If the value is +prime+ it will be added as a
  # prime in the proper spot.

  def mark_checked value, prime
    checked_index = head_index :checked

    @last_checked.upto checked_index do
      @tuple_space.read [:checked, nil, nil]
    end

    @last_checked = checked_index

    if prime then
      primes_index = head_index :primes

      @tuple_space.write [:primes, primes_index, value]
    end

    @tuple_space.write [:checked, checked_index, value]
  end

  ##
  # Retrieves the next candidate value to work on.

  def next_candidate
    _, candidate = @tuple_space.take [:next_candidate, nil]

    candidate
  ensure
    @tuple_space.write [:next_candidate, candidate + 1] if candidate
  end

  ##
  # Initializes a prime-finding child.

  def processor
    @last_checked = 0
    @tuple_space = Rinda::TupleSpaceProxy.new DRb::DRbObject.new_with_uri @uri

    loop do
      find_prime
    end
  end

  ##
  # Runs +children+ prime-finding children and displays found primes.

  def run children
    seed

    children.times do
      @children << fork_child
    end

    show_primes
  end

  ##
  # Seeds the TupleSpace with base values necessary for creating the working
  # streams and candidate counter.

  def seed
    @tuple_space.write [:primes, 0, 2]
    @tuple_space.write [:primes_head, 1]

    @tuple_space.write [:next_candidate, 3]

    @tuple_space.write [:checked, 0, 2]
    @tuple_space.write [:checked_head, 1]
  end

  ##
  # Displays calculated primes.

  def show_primes
    observer = @tuple_space.notify 'write', [:primes, nil, nil]

    observer.each do |_, (_, _, prime)|
      puts prime
    end
  end

end

if $0 == __FILE__ then
  children = (ARGV.shift || 2).to_i

  Primes.new.run children
end

