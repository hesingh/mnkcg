The tool merges two P4 programs. New code to be merged is written in P4++ described in the doc below.

https://github.com/hesingh/mnkcg/blob/master/p4-code-reuse/ansible.md

See `interactive-shell` directory for using the tool.

Example programs are included in the `merge-examples` directory

Before using the tool you must install a `p4c` on your machine using steps below. Our `p4c` is used to merge P4 programs.
Contact hemant@mnkcg.com, using a work email address, to get access to the repo. The free version of the tool uses a `p4c` from 2020 with no examples for Tofino and support by us for Barefoot/Intel SDE.

```shell
git clone --recursive <repo>
cd p4c-ansible1.01
mkdir build
cd build
cmake ..
make
sudo make install
```

 # Quick testing of Complete Functionality
 
If our `p4c` is installed on your machine, use steps below to perform a test for merging. The single `new-ethtype` merge example shows merging of struct, header, header union, enum, serialized enum, parser, parser state, and package.

1.	cd interactive-shell directory.

2.	In one xterm, run server by typing `python server.py -d 1`.

3.	In another xterm, run client by typing `python client.py`.  Inside client shell, type command such as the one below.

    `p4-ansible> compilePatch /home/hemant/merging-parsers/v2_examples/new-ethtype/customer.p4`

A `merged.p4` file is dumped to the directory where `client.py` was launched from.  Inspect `customer.p4` for its P4++ code and `vendor_copy.p4` for base code. 

