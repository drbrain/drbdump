require 'drb'
require 'observer'
require 'thread'

##
# Generates primes using multiple independent services.  This prime number
# generator is purposefully ridiculous in its separation of services.
#
# == Implementation Notes
#
# ServicePrimes contains the following services:
#
# :primes::
#   NumberStore holding prime numbers and Observable for notification of newly
#   added prime numbers.
# :candidates::
#   Enumerator from 3 to infinity for candidates.
# :discover::
#   Consumes an item from the :candidates service and adds the number to the
#   :primes service if it is found to be prime.
# :show_primes::
#   Observer for the :primes NumberStore that prints added primes to standard
#   output
#
# ServicePrimes can be collapsed back to a single process by removing
# fork_child and assigning each service to the instance variable used by each
# service.
#
# == Analyzing with drbdump
#
# Setup and finding the first prime (3) occurs within the first 15 messages.
#
# Comparing short message capture (100 messages) at the beginning of prime
# generation followed by later (around 70001) shows test_prime doing more work
# as the number of +call+ messages becomes a larger fraction of the messages
# sent.
#
# Removing DrbUndumped from NumberStore and NumberShower gives an interesting
# failure where the Observer fails to register.

class ServicePrimes

  ##
  # An observer for NumberStore that prints numbers as they are added.

  class NumberShower
    include DRb::DRbUndumped

    ##
    # Prints the number to standard output

    def update number
      puts number
    end
  end

  ##
  # Stores primes and allows access to generated primes.  The NumberStore is
  # pre-primed with the first prime number (2).  The NumberStore is Observable
  # and will notify observers when a new prime is added.

  class NumberStore
    include DRb::DRbUndumped
    include Enumerable
    include Observable

    def initialize # :nodoc:
      @primes = [2]
    end

    ##
    # Adds a number +value+ and notifies observers

    def add value
      changed
      @primes << value
      notify_observers value
    end

    ##
    # Iterates through stored primes

    def each
      @primes.each do |prime|
        yield prime
      end
    end
  end

  def initialize # :nodoc:
    @services = {}

    DRb.start_service nil, @services

    @uri = DRb.uri
  end

  ##
  # Creates a candidate numbers service which is enumerator of integers from 3
  # to infinity.

  def candidates
    fork_child :candidates do
      @services[:candidates] = 3.upto Float::INFINITY

      DRb.thread.join
    end
  end

  ##
  # Creates a prime number discovery service which consumes a candidate number
  # and uses +test_prime+ to determine if the candidate number is prime.  If
  # the candidate is prime it is added to the prime number list.

  def discover
    fork_child :discover do
      candidates = @services[:candidates]
      @primes    = @services[:primes]

      candidates.each do |candidate|
        prime = test_prime candidate

        @primes.add candidate if prime
      end
    end
  end

  ##
  # Forks a worker child named +service+ and waits for its registration before
  # returning.

  def fork_child service
    Thread.start do
      pid = fork do
        DRb.stop_service

        DRb.start_service

        @services = DRb::DRbObject.new_with_uri @uri

        yield
      end

      Process.wait pid
    end

    Thread.pass until @services[service]
  end

  ##
  # Creates a prime number storage service named primes.

  def primes
    fork_child :primes do
      @services[:primes] = NumberStore.new

      DRb.thread.join
    end
  end

  ##
  # Starts the prime number generator

  def run
    candidates

    primes

    show_primes

    discover

    DRb.thread.join
  end

  ##
  # Creates a prime number display service that observes the addition of new
  # prime numbers to the primes service.

  def show_primes
    fork_child :show_primes do
      prime_shower = NumberShower.new

      @services[:primes].add_observer prime_shower

      @services[:show_primes] = prime_shower

      DRb.thread.join
    end
  end

  ##
  # Determines if +candidate+ is a prime number by dividing it by all primes
  # below the square root of the +candidate+.

  def test_prime candidate
    max = Math.sqrt(candidate).ceil

    is_prime = @primes.each do |prime|
      break true if prime > max

      _, remainder = candidate.divmod prime

      break false if remainder.zero?
    end

    is_prime
  end

end

ServicePrimes.new.run if $0 == __FILE__
