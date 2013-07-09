import bnrev.hashable as H
import unittest

class TestHashable(unittest.TestCase):

  def test_hashable_dict(self):
    d1 = H.HashableDict()
    d1['a'] = 'b'
    d2['b'] = 'c'

    self.assertNotEqual(None, d1.__hash__())
