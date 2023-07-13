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
  -s SPOOF, --spoof SPOOF
                        manually add memdev's that are not in the cxl sysfs topology.
                        Each memdev should be name,serial,size_mb - separate devices by semicolon.
  -a, --auto            Run an analyzer that attempts to auto-generate links and spoofs
  -m, --logical_mode    Specify that you want the graph output in logical mode
  --cxl_cmd CXL_CMD     Command for cxl, default is "cxl"
  --dax_cmd DAX_CMD     Command for daxctl, default is "daxctl"
  -d, --debug           debug prints
```

## mvtopo usage

Run in auto-mode using `./mvtopo.py -a > output.json`. 

If this doesn't look reasonable, then you will need to provide manual linkage (`-l`) and spoofing (`-s`), depending on your specific hardware environment.

# Requirements

mvtopo requires:
- lstopo >= 3.x // CXL Patches were committed in [aa26f2](https://github.com/open-mpi/hwloc/commit/aa26f297b5240425a970d21ecbb3a2a70fca0b95)
- daxctl
- cxl-cli (aka 'cxl')

`lstopo` must be built from source as no Linux Distro has version 3.x in their package repository yet. Follow the instructions below to build lstopo from source code.
`lstopo` and `lstopo-no-graphics` must be available in the `PATH` environment variable. i.e.: `which lstopo-no-graphics` should return the full path to the binary.

## Install the Prerequisites for lstopo

On Ubuntu, run:
```bash
sudo apt install numactl libnuma1 libnuma-dev libpciaccess-dev libpciaccess0 libxml2 libxml2-dev cpuid libcpuid-dev libpci-dev libpci3
```

On Fedora, run
```bash
sudo dnf install numactl numactl-libs numactl-devel libpciaccess libpciaccess-devel libxml2 libxml2-devel cpuid libcpuid-devel
```

On CentOS/RHEL, run
```bash
sudo yum install numactl numactl-libs numactl-devel libpciaccess libpciaccess-devel libxml2 libxml2-devel cpuid libcpuid-devel
```

## Build lstopo
```bash
$ git clone https://github.com/open-mpi/hwloc
$ cd hwloc
$ ./autogen.sh
$ ./configure --prefix=/opt/hwloc
$ make -j all
```

## Install lstopo (Optional)
lstopo can be executed from the directory with the source code. Otherwise, it can be installed to /opt/hwloc with:
```bash
$ sudo make install
```

## Check the lstopo version
Run the following to confirm the version is 3.x
```bash
$ sudo /opt/hwloc/bin/lstopo-no-graphics --version
lstopo-no-graphics 3.0.0a1-git
```

## Update the PATH environment variable
Temporarily add the full path to the `lstopo-no-graphics` binary to the PATH. Assuming the binaries were installed to `/opt/hwloc`, run:
```bash
$ export PATH=/opt/hwloc/bin:$PATH
$ export LD_LIBRARY_PATH=/opt/hwloc/lib:$LD_LIBRARY_PATH
$ which lstopo-no-graphics
/opt/hwloc/bin/lstopo-no-graphics
```

# Platform Notes

As of July 2013, Linux kernel driver support for associating memory resources (dax devices / NUMA nodes)
and CXL memory devices (/sys/bus/cxl/devices/memN) are broken on some platforms.

In these cases, some manual links must be provided by the user to generate a sane topology successfully.

## AMD Genoa

On Genoa machines, by default, the BIOS will create mappings and numa-nodes for memory expanders.

This numa-node is created separately from any operating system driver support, meaning that the
topology will not associate the memory expander device `/sys/bus/cxl/devices/memN` with the
numa node containing its memory `/sys/bus/node/devices/nodeY`.

As a result, mvtopo requires a manual linkage provided by the user to associate these resources.

Example: mem0 is associated with numa node 2, and mem1 is associated with numa node 3.
```
./mvtopo.py --links="mem0,node2;mem1,node3"
```

## Intel Sapphire Rapids

On Sapphire Rapids machines, by default, the BIOS will create a dax device associated with the
memory on a memory expander.  This dax device will not be associated with the memory device
produced by the kernel driver (similar to AMD Genoa).

If `efi=nosoftreserve` is set in the Linux boot options (see `/proc/cmdline`), then a numa
node will appear instead of a dax device.  In this case, follow the directions for Genoa.


In dax mode, to set the memory as usable as general purpose system memory, you must online
the memory as a numa node manually.

Creating a numa node from the DAX device:
```
daxctl reconfigure-device --mode=system-ram dax0.0 
```

Then you should create links between the dax device and the memory device.

Example: dax0.0 is associated with mem0, dax1.0 is associated with mem1
```
./mvtopo.py --links="mem0,dax0.0;mem1,dax1.0"
```

## QEMU

On QEMU, mvtopo should generate the topology without manual links.
