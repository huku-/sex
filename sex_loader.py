#!/usr/bin/env python
'''sex_loader.py - Loads executable sections dumped by "sex.sh".'''


__author__ = 'huku <huku@grhack.net>'


import os


class Section(object):
    '''Holds information for an executable's section.'''

    def __init__(self, filename):

        components = filename.rsplit('.', 1)[0].split('-', 4)
        self.filename = filename
        self.name = os.path.basename(components[0])
        self.start_address = int(components[1], 16)
        self.size = int(components[2])
        self.offset = int(components[3])
        self.flags = components[4] 

        # For convenience precompute the section's end address as well.
        self.end_address = self.start_address + self.size

        with open(filename, 'rb') as fp:
            self.data = fp.read()


class SexLoader(object):
    '''Loads executable sections dumped by "sex.sh".'''

    def __init__(self, dirname):

        dirname = dirname.rstrip(os.path.sep)
        self.dirname = dirname

        self.sections = []
        for filename in os.listdir(dirname):
            if filename.rsplit('.', 1)[1] == 'bin':
                filename = '%s%s%s' % (dirname, os.path.sep, filename)
                self.sections.append(Section(filename))

            elif filename == 'aux.txt':
                with open('%s%s%s' % (dirname, os.path.sep, filename)) as fp:
                    self.arch = fp.read().rstrip()


    def read(self, address, size):
        '''Reads `size' bytes from virtual address `address'.'''

        data = None
        for section in self.sections:
            if address >= section.start_address and \
                    address + size <= section.end_address:
                offset = address - section.start_address
                data = section.data[offset:offset + size]
        return data

# EOF
