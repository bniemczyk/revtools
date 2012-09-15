#!/usr/bin/env python
import math

# We inherit from tuple so that it's hashable and shit
class FuzzyRange(tuple):

    COMPARISON_CONSTANT = 0.06931471805599453
    
    def __new__(cls, a, b, name=None, low=None, high=None):
        if a == b:
            raise "Fuzzy Range must not be a point"

        self = tuple.__new__(cls,('FuzzyRange', name, a, b))

        self.name = name
        self.a = float(min(a,b))
        self.b = float(max(a,b))

        return self

    def __eq__(self, other):
        if not isinstance(self, FuzzyRange):
            return False

        return \
            self.a == other.a \
            and self.b == other.b

    def within(self, x):
        n = 0.693147 * (self.a + self.b - 2 * x) ** 2
        d = (self.a - self.b) ** 2
        return math.exp(-n / d)

    def greaterthan(self, x, sensitivity=1.0):
        try:
            result = math.exp(FuzzyRange.COMPARISON_CONSTANT/sensitivity) - 1
            result *= math.exp(0.5 * (self.b - self.a))
            result = result ** (2.0 / (self.a - self.b))
            result = result ** (self.b - x)
            result *= math.exp(self.b - x)
            result += 1
            result = 1.0 / result
            return result
        except OverflowError:
            return 1.0 if x > self.b else 0.0

    def lessthan(self, x, sensitivity=1.0):
        try:
            result = math.exp(FuzzyRange.COMPARISON_CONSTANT/sensitivity) - 1
            result *= math.exp(0.5 * (self.b - self.a))
            result = result ** (2.0 / (self.a - self.b))
            result = result ** (x - self.a)
            result *= math.exp(x - self.a)
            result += 1
            result = 1.0 / result
            return result
        except OverflowError:
            return 1.0 if x < self.a else 0.0


    def __repr__(self):
        if self.name != None:
            return "FuzzyRange(%s: %d ... %d)" % (self.name, self.a, self.b)
        else:
            return "FuzzyRange(%d ... %d)" % (self.a, self.b)

if __name__ == '__main__':
    r = FuzzyRange(100,190, "TestRange")
    print "%s: %s" % (r, type(r))
    print "8 within %s = %f" % (r, r.within(8))

    print "5 > %s = %f" % (r, r.greaterthan(5))
    print "10 > %s = %f" % (r, r.greaterthan(10))
    print "13 > %s = %f" % (r, r.greaterthan(13))
    print "15 > %s = %f" % (r, r.greaterthan(15))
    print "20 > %s = %f" % (r, r.greaterthan(20))
    print "200 > %s = %f" % (r, r.greaterthan(200))

    print "5 < %s = %f" % (r, r.lessthan(5))
    print "10 < %s = %f" % (r, r.lessthan(10))
    print "13 < %s = %f" % (r, r.lessthan(13))
    print "15 < %s = %f" % (r, r.lessthan(15))
    print "20 < %s = %f" % (r, r.lessthan(20))
    print "200 < %s = %f" % (r, r.lessthan(200))

    myhash = {}
    myhash[r] = 'Initial Range'

    q = FuzzyRange(10,15, "OtherTestRange")
    myhash[q] = 'Other Range'

    print myhash
    print "%s == %s\n\t%s" % (r, q, r == q)
