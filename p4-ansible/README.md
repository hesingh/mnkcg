The tool merges two P4 programs. New code to be merged is written in P4++ described in the doc below.

https://github.com/hesingh/mnkcg/blob/master/p4-code-reuse/ansible.md

See `interactive-shell` directory for using the tool.

Example programs are included in the `merge-examples` directory

Before using the tool you must install a p4c on your machine using steps below. Our p4c is used to merge P4 programs.
Contact hemant@mnkcg.com for a link to repo. The free version of the tool uses a p4c from 2020 and no examples for Tofino and support by us for Barefoot/Intel SDE.

```shell
git clone --recursive <repo>
cd p4c-ansible1.01
mkdir build
cd build
cmake ..
make
sudo make install
```
