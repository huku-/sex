#!/usr/bin/env python
'''sex_loader.py - Loads executable sections dumped by "sex.sh".'''


__author__ = 'huku <huku@grhack.net>'


import os


class Section(object):
    '''Holds information for an executable's section.'''

    def __init__(self, filename):

        components = filename.rsplit('.', 1)[0].split('-', 4)
        self.filename = filename
        self.name = components[0]
        self.address = int(components[1], 16)
        self.size = int(components[2])
        self.offset = int(components[3])
        self.flags = components[4] 

        with open(filename) as fp:
            self.data = fp.read()


class SexLoader(object):
    '''Loads executable sections dumped by "sex.sh".'''

    def __init__(self, dirname):

        dirname = dirname.rstrip('/')
        self.dirname = dirname

        self.sections = []
        for filename in os.listdir(dirname):
            if filename.rsplit('.', 1)[1] == 'bin':
                filename = '%s/%s' % (dirname, filename)
                self.sections.append(Section(filename))


    def read(self, address, size):
        '''Reads `size' bytes from virtual address `address'.'''

        data = None
        for section in self.sections:
            if address >= section.address and \
                    address + size <= section.address + section.size:
                offset = address - section.address
                data = section.data[offset:offset + size]
        return data

# EOF
