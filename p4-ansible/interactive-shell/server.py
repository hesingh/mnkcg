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

import rpyc
from rpyc.utils.server import ThreadedServer
import os
import os.path
import subprocess
import argparse
import tftpy
    
class MyService(rpyc.Service):
# My service
#   Invoked when any cmd is issued from client
    def on_connect(self, conn):
        result = os.path.isfile('./vendor.json')
        res2 = os.path.isfile('./vendor_tna.json')
        if result == False or res2 == False:
            cmd = "p4test --std p4-16 --parse-only --toJSON ./vendor.json " + args.vpath + "/vendor_copy.p4"
            os.system(cmd)
            cmd = "p4test --std p4-16 -I " + args.vpath + "--parse-only --toJSON ./vendor_tna.json " + args.vpath + "/vendor_copy.p4"
            os.system(cmd)

    def exposed_req(self, text):
        list = text.split(" ")
        if len(list) > 1 :
            """ P4ObjName """
            print list[0], list[1]
            if (list[0] == "getControlFull") or (list[0] == "getParserState"):
                ver = getRel()
                if ver == CONST_V1_MODEL:
                    p4test = ["p4test", "--std", "p4-16", "--fromJSON", "./vendor.json", "--getP4Node", list[1]]
                else:
                    p4test = ["p4test", "--std", "p4-16", "--fromJSON", "./vendor_tna.json", "--getP4Node", list[1]]
                st = subprocess.Popen(p4test, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                res = st.communicate()
                if res[1] == '':
                    return res[0]
                else:
                    return res[1]
            if list[0] == "useVersion":
                if list[1] not in CONST_VERS:
                    return "Error: Version not valid"
                setRel(list[1])
                return list[1]
            if list[0] == "compilePatch":
                ver = getRel()
                if ver == CONST_V1_MODEL:
                    p4test = ["p4test", "--std", "p4-18", list[1]]
                else:
                    p4test = ["p4test", "--std", "p4-18", "-I " + args.vpath, list[1]]
                st = subprocess.Popen(p4test, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                res = st.communicate()
#               TODO: Compile res[0] with BF SDE and return final success/failure
                if res[1] == '':
                    return res[0]
#                    return '0'
                else:
                     return res[1]
            if list[0] == "getSparseP4Prog":
                ver = getRel()
                if ver == CONST_V1_MODEL:
                    p4test = ["p4test", "--std", "p4-18", list[1]]
                else:
                    p4test = ["p4test", "--std", "p4-18", "-I " + args.vpath, list[1]]
                st = subprocess.Popen(p4test, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                res = st.communicate()
                if res[1] == '':
                    return res[0]
#                    return '0'
                else:
                     return res[1]
        else :
            if text == "queryVersions":
                txt = '1.0 => v1model, 2.0 => TNA model'
                vers = [CONST_VERS, txt, args.sdever]
                return vers
            if text == "getNewFirmware":
#               TODO
                return "NOT_SUPPORTED"

if __name__ == "__main__":
    CONST_V1_MODEL = '1.0'
    CONST_TNA_MODEL = '2.0'
    CONST_TNA_REL_VER = '8.9.1'
    CONST_VERS = [CONST_V1_MODEL, CONST_TNA_MODEL]

    def getRel():
        return args.dpver
    def setRel(ver):
        args.dpver = ver

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dpver')
    parser.add_argument('-s', '--sdever')
    parser.add_argument('-v', '--vpath')
    args = parser.parse_args()
    if args.dpver == None and args.sdever == None:
        print "Please provide args: -d <dp_ver> -s <sde_ver> -v <vendor path>"
        exit(2)
    if args.vpath == None:
        print "Please provide vendor path: -v <vendor path>"
        exit(2)

    server = ThreadedServer(MyService, port = 18812)
    server.start()
    
