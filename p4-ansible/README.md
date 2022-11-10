The tool merges two P4 programs. See 

https://github.com/hesingh/mnkcg/blob/master/p4-code-reuse/ansible.md

See `interactive-shell` directory for using the tool.

Example programs are included in the `merge-examples` directory

Before using the tool you must install a p4c on your machine using steps below.
Contact hemant@mnkcg.com for a link to repo.

```shell
git clone --recursive <repo>
cd p4c-ansible1.01
mkdir build
cd build
cmake ..
make
sudo make install
```