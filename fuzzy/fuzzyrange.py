#!/usr/bin/env python
import numpy 

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

    @staticmethod
    def _numpyize(x):
        if isinstance(x,list):
            if hasattr(numpy, 'float128'):
                return numpy.array(x,dtype=numpy.float128)
            elif hasattr(numpy, 'float96'):
                return numpy.array(x,dtype=numpy.float96)
            else:
                return numpy.array(x)
        else:
            return x

    def within(self, x):
        x = self._numpyize(x)

        n = -0.6931471805599453  * (self.a + self.b - 2 * x) ** 2
        d = (self.a - self.b) ** 2
        rv = numpy.exp(n / d)
        return rv

    def greaterthan(self, x, sensitivity=1.0):
        x = self._numpyize(x)

        result = numpy.exp(FuzzyRange.COMPARISON_CONSTANT/sensitivity) - 1
        result *= numpy.exp(0.5 * (self.b - self.a))
        result = result ** (2.0 / (self.a - self.b))
        bx = self.b - x
        result = result ** bx
        result *= numpy.exp(bx)
        result += 1
        result = 1.0 / result
        return result

    def lessthan(self, x, sensitivity=1.0):
        x = self._numpyize(x)

        result = numpy.exp(FuzzyRange.COMPARISON_CONSTANT/sensitivity) - 1
        result *= numpy.exp(0.5 * (self.b - self.a))
        result = result ** (2.0 / (self.a - self.b))
        xa = (x - self.a)
        result = result ** xa
        result *= numpy.exp(xa)
        result += 1
        result = 1.0 / result
        return result

    def __repr__(self):
        if self.name != None:
            return "FuzzyRange(%s: %f ... %f)" % (self.name, self.a, self.b)
        else:
            return "FuzzyRange(%f ... %f)" % (self.a, self.b)

if __name__ == '__main__':
    a = 2.0
    b = 2.5

    r = FuzzyRange(a,b, "TestRange")
    print "%s: %s" % (r, type(r))
    tests = FuzzyRange._numpyize(range(0,20)) / 2.4

    results = r.within(tests)
    for i in range(len(tests)):
        print "%f within %s = %f" % (tests[i], r, results[i])
    print ""

    results = r.greaterthan(tests)
    for i in range(len(tests)):
        print "%f > %s = %f" % (tests[i], r, results[i])
    print ""

    results = r.lessthan(tests)
    for i in range(len(tests)):
        print "%f < %s = %f" % (tests[i], r, results[i])
    print ""

    myhash = {}
    myhash[r] = 'Initial Range'

    q = FuzzyRange(a,b, "OtherTestRange")
    myhash[q] = 'Other Range'

    print myhash
    print "%s == %s\n\t%s" % (r, q, r == q)
