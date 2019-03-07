#!/usr/bin/env python
'''sex_loader.py - Loads executable sections dumped by "sex.sh".'''


__author__ = 'huku <huku@grhack.net>'


import os
import ConfigParser


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

        # For convenience precompute the section's end address as well. This is
        # the address of the last byte in this section.
        self.end_address = self.start_address + self.size - 1

        with open(filename, 'rb') as fp:
            self.data = fp.read()


class SexLoader(object):
    '''Loads sections and auxiliary information dumped by "sex.sh".'''

    def __init__(self, dirname):

        dirname = dirname.rstrip(os.path.sep)
        self.dirname = dirname

        self.sections = []

        self.arch = None
        self.exit_points = set()
        self.entry_points = set()
        self.relocations = set()
        self.functions = set()

        # Map of addresses to symbolic names.
        self.labels = {}

        for filename in os.listdir(dirname):
            if filename.rpartition('.')[-1] == 'bin':
                filename = '%s%s%s' % (dirname, os.path.sep, filename)
                self.sections.append(Section(filename))

            elif filename == 'aux.ini':
                with open('%s%s%s' % (dirname, os.path.sep, filename)) as fp:
                    rcp = ConfigParser.RawConfigParser()
                    rcp.readfp(fp)

                    # Get executable's architecture.
                    self.arch = rcp.get('aux', 'arch')

                    # Get exit points (addresses of calls to dynamic symbols).
                    for _, label in rcp.items('exit_points'):
                        address, name = label.split(',')
                        address = int(address, 16)
                        self.exit_points.add(address)
                        self.labels[address] = name

                    # Get entry points (addresses of public symbols).
                    for _, label in rcp.items('entry_points'):
                        address, name = label.split(',')
                        address = int(address, 16)
                        self.entry_points.add(address)
                        self.labels[address] = name

                    # Get list of relocation entries.
                    for _, address in rcp.items('relocations'):
                        self.relocations.add(int(address, 16))

                    # Get possible metadata indicating function boundaries.
                    for _, address in rcp.items('functions'):
                        self.functions.add(int(address, 16))

        # Sort sections by starting address in ascending order. We will later
        # use binary search over this list's elements.
        self.sections.sort(key=lambda section: section.start_address)


    def __str__(self):
        return '<SexLoader "%s">' % self.dirname


    def get_section_for_address_range(self, address, length=1):
        '''
        Locate and return the section that contains the given address range.
        Returns section's `Section' instance or `None' on error.
        '''

        ret = None
        for section in self.sections:
            if section.start_address <= address <= section.end_address:
                ret = section
                break

        return ret


    def read(self, address, size):
        '''
        Reads `size' bytes from virtual address `address'. Returns the raw data
        or `None' on error.
        '''

        data = None

        section = self.get_section_for_address_range(address, size)
        if section:
            offset = address - section.start_address
            data = section.data[offset:offset + size]

        return data

# EOF
