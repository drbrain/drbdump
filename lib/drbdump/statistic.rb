##
# Stores the mean, count and standard deviation for a set of values but not
# the values themselves.

class DRbDump::Statistic

  ##
  # The number of items in the set

  attr_reader :count

  ##
  # The mean of all values

  attr_reader :mean

  def initialize # :nodoc:
    @M_2   = 0.0
    @mean  = 0.0
    @count = 0
  end

  ##
  # Adds +value+ to the set of values.  Returns the number of values.

  def add value
    @count += 1

    delta  = value - @mean
    @mean += delta / @count
    @M_2  += delta * (value - @mean)

    @count
  end

  ##
  # The average of all values

  alias average mean

  ##
  # The sample variance for all values

  def sample_variance
    @M_2 / (@count - 1)
  end

  ##
  # The standard deviation of all values

  def standard_deviation
    Math.sqrt sample_variance
  end

  ##
  # An array containing the number of values in the set, the mean and the
  # standard deviation

  def to_a
    [@count, @mean, standard_deviation]
  end

end

