#!/usr/bin/python

'''
Copyright: Wavestone 2017 (c)
Author: Jean MARSAULT (@iansus)
Version: 1.0
Thanks: @gentilkiwi, @th3m4ks
Description:
    Volatility plugin to search for NotPetya AES keys in memory
    Report bugs to Jean MARSAULT (@iansus almost everywhere)
'''

import struct

import volatility.commands as commands
import volatility.debug as debug
import volatility.utils as utils
import volatility.win32.tasks as tasks

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False


try:
    import pefile
    has_pefile = True
except ImportError:
    has_pefile = False


def read_bytes(address, a, length=4):
    return a.read(address, length)


def deref(address, a, length=4):
    try:
        d = struct.unpack("<I", a.read(address, length))[0]
        return d
    except struct.error:
        return None


# MAIN CLASS
class NotPetyaKeys(commands.Command):
    """ Searches for NotPetya AES keys in memory"""

    def __init__(self, config, *args):
        commands.Command.__init__(self, config, *args)

        config.add_option('RSAENH', short_option='r', dest='dll', type=str, help='32-bit RSAENH.dll file from infected system')
        self.__keys = []


    def fetch_config(self, config_ptr):
        pass

    def readExports(self):

        try:
            exports = {}
            pe = pefile.PE(self._config.dll)

            if not pe.is_dll():
                debug.error("File does not seem to be DLL")

            if pe.PE_TYPE != pefile.OPTIONAL_HEADER_MAGIC_PE: # not 32-bits
                debug.error("DLL is not 32 bit version - search at C:\\Windows\\SysWOW64\\rasenh.dll")

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports[exp.name] = exp.address

            return exports

        except OSError, e:
            debug.error("File could not be opened: %s" % str(e))

        except pefile.PEFormatError, e:
            debug.error("An error occurred while trying to load rsaenh.dll: %s" % str(e))


    def genYaraRule(self, exports):

        # Export name order in HCRYPTKEY structure
        ORDER = ['CPGenKey', 'CPDeriveKey', 'CPDestroyKey', 'CPSetKeyParam',
                'CPGetKeyParam', 'CPExportKey', 'CPImportKey', 'CPEncrypt',
                'CPDecrypt', 'CPDuplicateKey']

        searchBytes = []
        for name in ORDER:
            if not name in exports.keys():
                debug.error("Export '%s' missing in DLL" % name)

            address = exports[name]

            searchString = '%.2x ?%.1x ?? ??' % (address & 0xFF, (address & 0x0F00) >> 8)
            searchBytes.append(searchString)

        searchBytes = ' '.join(searchBytes)
        searchBytes+= ' ?? ?? ?? ?? ?? ?? ?? ??'
        yararule = { 'HCRYPTKEY' : 'rule HCRYPTKEY { strings: $struct = { %s } condition: $struct }' % searchBytes }
        return yararule


    def getKey(self, hcryptkey, process_space):

        # Many thanks to @gentilkiwi for this section
        magic_1 = struct.unpack('<I', hcryptkey[-4:])[0]
        addr_1 = magic_1 ^ 0xe35a172c
        addr_2 = deref(addr_1, process_space)
        key_struct = [
                deref(addr_2+0, process_space), # UNK0
                deref(addr_2+4, process_space), # AlgId
                deref(addr_2+8, process_space), # Flags
                deref(addr_2+12, process_space),# dwData
                deref(addr_2+16, process_space),# data
        ]

        # Check if alg is CALG_AES_128
        if key_struct[1] != 0x660e:
            return None

        key = read_bytes(key_struct[4], process_space, key_struct[3])
        return key.encode('hex')


    def calculate(self):

        # Check imports and options
        if not has_yara:
            debug.error("You must install yara to use this plugin")

        if not has_pefile:
            debug.error("You must install pefile to use this plugin")

        if not self._config.dll:
            debug.error("No RSAENH.dll provided")

        exports = self.readExports()
        rule = self.genYaraRule(exports)

        # Load the address space
        addr_space = utils.load_as(self._config)
        # Compile yara signatures
        rules = yara.compile(sources=rule)

        # Search for RUNDLL32 task
        # On 32-bit, only one process with #1 in it
        # On 64-bit, two processes, but only one on WOW64
        selected_task = None
        for task in tasks.pslist(addr_space):
            if task.ImageFileName.lower() != 'rundll32.exe':
                continue

            if not task.Peb:
                continue

            if not "#1" in str(task.Peb.ProcessParameters.CommandLine):
                continue

            if task.IsWow64 or (selected_task is None and not task.IsWow64):
                selected_task = task

        if selected_task is None:
            debug.error("Could not find suitable process in memory, make sure system is infected")

        # iterate through all VADs
        for vad, process_space in selected_task.get_vads():
            if vad.Length > 8*1024*1024*1024:
                continue

            # read the VAD content
            data = process_space.zread(vad.Start, vad.Length)

            # match yara rules
            matches = rules.match(data=data)

            # profit !
            if matches:
                for offset, _, match in matches[0].strings:
                    key = self.getKey(match, process_space)

                    if key is not None:
                        self.__keys.append((vad.Start+offset, key))


    def render_text(self, outfd, data):

        outfd.write('\n')
        self.table_header(outfd, [
            ("Address", "[addrpad]"),
            ("AES Key", ""),
            ])

        for offset, key in self.__keys:
            self.table_row(outfd, offset, key)


