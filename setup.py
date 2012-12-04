#!/usr/bin/env python

from setuptools import setup

_depends = '''
symath
distorm3
'''

setup( \
  name='bnrev', \
  version='git', \
  description='reversing tools', \
  author='Brandon Niemczyk', \
  author_email='brandon.niemczyk@gmail.com', \
  url='http://github.com/bniemczyk/revtools', \
  packages=['bnrev', 'bnrev.malware', 'bnrev.collect', 'bnrev.fuzzy'], \
  test_suite='tests', \
  license='BSD', \
  install_requires=_depends, \
  classifiers = [ \
    'Development Status :: 3 - Alpha', \
    'Intended Audience :: Developers', \
    'License :: OSI Approved :: BSD License', \
    ]
  )
