##
# Stores the minimum, maximum, mean, count and standard deviation for a set of
# values but not the values themselves.

class DRbDump::Statistic

  ##
  # The number of items in the set

  attr_reader :count

  ##
  # The maximum value added

  attr_reader :max

  ##
  # The mean of all values

  attr_reader :mean

  ##
  # The minimum value added

  attr_reader :min

  def initialize # :nodoc:
    @M_2   = 0.0
    @count = 0
    @max   = -Float::INFINITY
    @mean  = 0.0
    @min   = Float::INFINITY
  end

  ##
  # Adds +value+ to the set of values.  Returns the number of values.

  def add value
    @min = value if value < @min
    @max = value if value > @max
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
  # The maximum value added

  alias maximum max

  ##
  # The minimum value added

  alias minimum min

  ##
  # The sample variance for all values

  def sample_variance
    sv = @M_2 / (@count - 1)
    return 0.0 if sv.nan?
    sv
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
    [@count, @min, @mean, @max, standard_deviation]
  end

end

