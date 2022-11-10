#!/usr/bin/env python
# Copyright 2020-present MNK Labs & Consulting, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from cmd import Cmd
import sys
import rpyc
import tftpy

class MyPrompt(Cmd):
    prompt = 'p4-ansible> '
    intro = "Welcome: MNK Labs P4-Ansible. Type ? to list commands"

    def help_compilePatch(self):
        print('compilePatch [filename.p4], Compile patch file.')

    def help_exit(self):
        print('exit the application. Shorthand: x q Ctrl-D.')
        
    def help_getNewFirmware(self):
        print('Get new data-plane firmware.')

    def help_getSparseP4Prog(self):
        print('getSparseP4Prog [program name], Get sparse P4 program')

    def help_getControlFull(self):
        print('getControlFull [control name], Get full P4 control program.')

    def help_getParserState(self):
        print('getParserState <parser state name>, Get specific parser state.')

    def help_queryVersions(self):
        print('Get switch release version and SDE version.')

    def help_useVersion(self):
        print('useVersion [version], Available versions: 1.0 and 2.0')


    def do_compilePatch(self, name):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("compilePatch" + " " + name)
        print ret        
        
    def do_exit(self, inp):
        print("Bye")
        return True

    def do_getNewFirmware(self, inp):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("getNewFirmware")
        print ret

    def do_getSparseP4Prog(self, name):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("getSparseP4Prog" " " + name)
        print ret

    def do_getControlFull(self, name):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("getControlFull" + " " + name)
        print ret

    def do_getParserState(self, name):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("getParserState" + " " + name)
        print ret

    def do_queryVersions(self, inp):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("queryVersions")
        print ret

    def do_useVersion(self, ver):
        c = rpyc.connect("localhost", 18812)
        ret = c.root.req("useVersion" + " " + ver)
        print ret

    def default(self, inp):
        if inp == 'x' or inp == 'q':
            return self.do_exit(inp)
 
        print("Default: {}".format(inp))
 
    do_EOF = do_exit
    help_EOF = help_exit
 
if __name__ == '__main__':
    RC_OK = '0'
    MyPrompt().cmdloop()
