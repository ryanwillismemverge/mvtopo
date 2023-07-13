# mvtopo

MemVerge CXL Topology Generator

```
usage: mvtopo.py [-h] [-l LINKS] [-m] [--cxl_cmd CXL_CMD] [--dax_cmd DAX_CMD] [-d]

MemVerge Topology Generator

options:
  -h, --help            show this help message and exit
  -l LINKS, --links LINKS
                        Specify manual links between two items in the graph by name.
                        Each link should be a pair of two strings separated by a comma.
                        Separate different links by semicolon.
                        Example: --links "mem0,node2;mem1,node3"
  -m, --logical_mode    Specify that you want the graph output in logical mode
  --cxl_cmd CXL_CMD     Command for cxl, default is "cxl"
  --dax_cmd DAX_CMD     Command for daxctl, default is "daxctl"
  -d, --debug           debug prints
```

# Requirements

mvtopo requires hwloc/lstopo 3.x+ to function.

OS: Fedora 36
Kernel: 6.3.7

Requires hwloc 3.0 or later.
CXL Patches were comitted in https://github.com/open-mpi/hwloc/commit/aa26f297b5240425a970d21ecbb3a2a70fca0b95

Install Prerequsites

Ubuntu 22.04: sudo apt install numactl libnuma1 libnuma-dev libpciaccess-dev libpciaccess0 libxml2 libxml2-dev cpuid libcpuid-dev libpci-dev libpci3
Fedora 36: sudo dnf install numactl numactl-libs numactl-devel libpciaccess libpciaccess-devel libxml2 libxml2-devel cpuid libcpuid-devel
CentOS: sudo yum install numactl numactl-libs numactl-devel libpciaccess libpciaccess-devel libxml2 libxml2-devel cpuid libcpuid-devel

$ git clone https://github.com/open-mpi/hwloc
$ cd hwloc
$ ./autogen.sh
$ ./configure --prefix=/opt/hwloc
$ make -j all
$ sudo make install
$ sudo /opt/hwloc/bin/lstopo-no-graphics --version
lstopo-no-graphics 3.0.0a1-git

Optional: set this lstopo-no-graphics to this new version by default
$ update-alternatives /usr/bin/lstopo-no-graphics lstopo-no-graphics /opt/hwloc/bin/lstopo-no-graphics 0

# Platform Quirks

As of July 2013, linux kernel driver support for associating memory resources (dax devices / NUMA nodes)
and CXL memory devices (/sys/bus/cxl/devices/memN) is broken on a some platforms.

In these cases, some manual links must be provided by the user to successfully generate a sane topology.

## AMD Genoa

On Genoa machines, by default the BIOS will create mappings and numa-nodes for memory expanders.

This numa-node is created separate from any operating system driver support, meaning that the
topology will not associate the memory expander device `/sys/bus/cxl/devices/memN` with the
numa node containing its memory `/sys/bus/node/devices/nodeY`.

As a result, mvtopo requires a manual linkage provided by the user to associate these resources.

Example: mem0 is associated with numa node 2, and mem1 is associated with numa node 3.
```
./mvtopo.py --links="mem0,node2;mem1,node3"
```

## Intel Sapphire Rapids

On Sapphire rapids machines, by default, the BIOS will create a dax device associated with the
memory on a memory expander.  This dax device will not be associated with the memory device
produced by the kernel driver (similar to AMD Genoa).

If `efi=nosoftreserve` is set in the linux boot options (see `/proc/cmdline`), then a numa
node will appear instead of a dax device.  In this case, follow the directions for Genoa.


In dax mode, to set the memory as usable as general purpose system memory, you must online
the memory as a numa node manually.

Creating a numa node from dax device:
```
daxctl 
```

Then you should create links between the dax device and the memory device.

Example: dax0.0 is associated with mem0, dax1.0 is associated with mem1
```
./mvtopo.py --links="mem0,dax0.0;mem1,dax1.0"
```


## QEMU

On QEMU, mvtopo should generate the topology without manual links.
