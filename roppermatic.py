#!/usr/bin/env python

import sys
from ropper import RopperService

def setup_ropper_service(appcode: bytes):
    options = {'color' : False,     # if gadgets are printed, use colored output: default: False
                'badbytes': '',   # bad bytes which should not be in addresses or ropchains; default: ''
                'all' : False,      # Show all gadgets, this means to not remove double gadgets; default: False
                'inst_count' : 6,   # Number of instructions in a gadget; default: 6
                'type' : 'all',     # rop, jop, sys, all; default: all
                'detailed' : False} # if gadgets are printed, use detailed output; default: False

    rs = RopperService(options)
    rs.addFile(name='binary', bytes=appcode, raw=True, arch='ARMTHUMB')
    rs.setImageBaseFor(name='binary', imagebase=0x10000)
    rs.loadGadgetsFor()
    return rs

def find_postvuln_location(rs: RopperService):
    postvuln_matches = [gadget for _, gadget in rs.search('ldr r3, [r?, #0x50]%ldr r1%blx r3')]
    if not postvuln_matches:
        raise ValueError('Could not find any postvuln code locations')

    if len(postvuln_matches) > 1:
        raise ValueError('Too many postvuln locations matched - try another pattern')

    return postvuln_matches[0]

    


if __name__ == '__main__':
    if not sys.argv[1:]:
        print('Usage: python haxomatic.py <app code file>')
        sys.exit(1)

    appcode_path = sys.argv[1]
    with open(appcode_path, 'rb') as fs:
        appcode = fs.read()
    
    print('[!] Setting up and loading gadgets with ropper. Might take a moment..')
    rs = setup_ropper_service(appcode)
    print('[+] Ropper initialized')

    print('[!] Searching for postvuln location')
    postvuln = find_postvuln_location(rs)
