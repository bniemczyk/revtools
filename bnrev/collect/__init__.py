#!/usr/bin/env python
from onetimequeue import onetimequeue

if __name__ == '__main__':
    q = onetimequeue()
    q.append(3)
    q.append(4)
    q.append(3)
    q.append(5)

    while q:
        print q.popleft()
