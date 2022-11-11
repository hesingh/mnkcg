# An interactive shell
  Use shell on a machine running Ubuntu 18.04 or higher. 
  Shell is written in Python to support P4-Ansible requests
  and response between client and server.  Shell supports 
  auto-completion of commands and also up-arrow to cmds 
  used in the past.

## Install dependencies

  use `pip install tftpy`
  
  use `pip install rpyc`

## Run shell
  python client.py

  Example use:

```
  hemant@ubuntu:~/interactive-shell$ python client.py 

Welcome: MNK Labs P4-Ansible. Type ? to list commands

p4-ansible> ?

Documented commands (type help <topic>):

========================================

EOF           exit            getNewFirmware  getSparseP4Prog  queryVersions

compilePatch  getControlFull  getParserState  help           
```

### Command to merge two P4 programs. 

The `vendor.p4` program must exist in the same directory as `customer.p4` program. The merged program is dumped to console and to a file `merged.p4` in the same directory where `client.py` was invoked from.

`p4-ansible> compilePatch /home/hemant/mnkcg-mex/v2_examples/new-ethtype/customer.p4`


## More example use with Client and Server

In one terminal invoke client.

```
$ python client.py

Welcome: MNK Labs P4-Ansible. Type ? to list commands

p4-ansible> help

Documented commands (type help <topic>):

========================================

EOF           exit            getNewFirmware  getSparseP4Prog  queryVersions

compilePatch  getControlFull  getParserState  help

p4-ansible> getControlFull vendor_ingress

p4-ansible> getParserState parse_ethernet

p4-ansible> getSparseP4Prog

p4-ansible>
```

In another terminal, invoke server

-d is dataplane version, 1.0 is for v1model P4 programs and 2.0 is for Tofino switching asic P4 programs.

-v is a string for path to vendor.p4 file.

If d is 2.0, use -s for BF SDE version used to compile P4 program.

```
$ python server.py -d 2.0 -s 8.9.0 -v "/home/hemant/mnkcg/merge-examples/ipv6-merge"

getControlFull(vendor_ingress)

getParserState(parse_ethernet)

getSparseP4Prog
```
