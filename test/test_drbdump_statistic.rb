require 'drbdump/test_case'

class TestDRbDumpStatistic < DRbDump::TestCase

  def setup
    @s = DRbDump::Statistic.new
  end

  def test_add
    assert_equal    0,                @s.count
    assert_in_delta 0.0,              @s.mean
    assert_equal    Float::INFINITY,  @s.min
    assert_equal(   -Float::INFINITY, @s.max)

    @s.add 4

    assert_equal    1,   @s.count
    assert_in_delta 4.0, @s.mean
    assert_equal    4,   @s.min
    assert_equal    4,   @s.max

    @s.add 7

    assert_equal    2,     @s.count
    assert_in_delta 5.500, @s.mean
    assert_in_delta 4.500, @s.sample_variance
    assert_in_delta 2.121, @s.standard_deviation
    assert_equal    4,     @s.min
    assert_equal    7,     @s.max

    @s.add 13

    assert_equal     3,     @s.count
    assert_in_delta  8.000, @s.mean
    assert_in_delta 21.000, @s.sample_variance
    assert_in_delta  4.583, @s.standard_deviation
    assert_equal     4,     @s.min
    assert_equal    13,     @s.max

    @s.add 16

    assert_equal     4,     @s.count
    assert_in_delta 10.000, @s.mean
    assert_in_delta 30.000, @s.sample_variance
    assert_in_delta  5.477, @s.standard_deviation
    assert_equal     4,     @s.min
    assert_equal    16,     @s.max
  end

  def test_add_catastrophic_cancellation
    assert_equal    0,   @s.count
    assert_in_delta 0.0, @s.mean

    @s.add 4 + 10e8

    assert_equal      1,        @s.count
    assert_in_epsilon 4 + 10e8, @s.mean

    @s.add 7 + 10e8

    assert_equal      2,          @s.count
    assert_in_epsilon 5.5 + 10e8, @s.mean
    assert_in_epsilon 4.5,        @s.sample_variance

    @s.add 13 + 10e8

    assert_equal       3,        @s.count
    assert_in_epsilon  8 + 10e8, @s.mean
    assert_in_epsilon 21.0,      @s.sample_variance

    @s.add 16 + 10e8

    assert_equal         4,   @s.count
    assert_in_epsilon 10e8,   @s.mean
    assert_in_epsilon 30.0,   @s.sample_variance
  end

  def test_to_a
    @s.add 4
    @s.add 7

    ary = @s.to_a

    assert_equal      2,    ary.shift
    assert_equal      4,    ary.shift
    assert_equal      7,    ary.shift
    assert_in_epsilon 5.5,  ary.shift
    assert_in_epsilon 2.12, ary.shift

    assert_empty ary
  end

end

