import subprocess
import os
import re
import json
import copy
from collections import defaultdict
import argparse

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

def link_type(arg):
    pairs = arg.split(";")
    links = []
    for pair in pairs:
        items = pair.split(",")
        if len(items) != 2:
            raise argparse.ArgumentTypeError("Link should be a pair of two strings separated by a comma.")
        links.append(tuple(items))
    return links

def main():
    parser = argparse.ArgumentParser(description='Process some inputs.')
    
    # Optional argument for links
    parser.add_argument('-l', '--links', type=link_type, 
                        help='Specify manual links between two items in the graph by name. Each link should be a pair of two strings separated by a comma. Separate different links by semicolon.')

    # Optional argument for logical mode
    parser.add_argument('-m', '--logical_mode', action='store_true',
                        help='Specify that you want the graph output in logical mode')

    # Optional arguments for cxl_cmd and dax_cmd
    parser.add_argument('--cxl_cmd', type=str, default='cxl', 
                        help='Command for cxl, default is "cxl"')
    
    parser.add_argument('--dax_cmd', type=str, default='daxctl', 
                        help='Command for daxctl, default is "daxctl"')

    args = parser.parse_args()
    global cxl_cmd
    global dax_cmd
    cxl_cmd = args.cxl_cmd
    dax_cmd = args.dax_cmd

    if args.logical_mode:
        print(json.dumps(generate_topology(args.links), indent=4, cls=SetEncoder))
    else:
        print(json.dumps(format_topology(args.links), indent=4, cls=SetEncoder))
    
def generate_topology(manual_links: list|None) -> dict:
    graph = {}
    try:
        generate_numa_nodes(graph)
    except Exception:
        print("Error: Couldn't generate NUMA nodes.")
    try:
        generate_dax_devices(graph)
    except Exception:
        print("Error: Couldn't generate DAX devices.")
    try:
        generate_cxl_devices(graph)
    except Exception:
        print("Error: Couldn't generate DAX devices.")
    try:
        generate_socket_devices(graph)
    except Exception:
        print("Error: Couldn't generate socket devices.")
    try:
        generate_root_devices(graph) 
    except Exception:
        print("Error: Couldn't generate root devices.")
    generate_mem_dax_links(graph)
    try:
        generate_memory_topology(graph)
    except Exception:
        print("Error: Couldn't generate DAX devices.")
    generate_manual_links(graph, manual_links)
    return graph

def format_topology(manual_links: list|None):
    manual_links = [] if manual_links is None else manual_links
    if manual_links is None:
        manual_links = []
    def recurse(nodes, node_id, link_types):
        node = nodes[node_id]
        if 'links' in node:
            for link_id in node['links']:
                link = nodes[link_id]
                link_type = link['type']
                if link_type not in node:
                    node[link_type] = {}
                node[link_type][link_id] = link
                if link_id not in link_types:
                    link_types.add(link_id)
                    recurse(nodes, link_id, link_types)
            del node['links']
            
    topology = generate_topology(manual_links)
    new_topology = {"sockets": {}}
    
    for id, properties in topology.items():
        if properties['type'] == 'socket':
            new_topology['sockets'][id] = properties
            recurse(topology, id, set())
            
    return new_topology

def generate_numa_nodes(graph: dict):
    node_dir = "/sys/devices/system/node/"
    for item in os.listdir(node_dir):
        if "node" in item:
            # Process meminfo file
            meminfo_file = os.path.join(node_dir, item, "meminfo")
            if os.path.exists(meminfo_file):
                with open(meminfo_file, 'r') as file:
                    meminfo = file.read()
                    mem_total_re = re.search(r'MemTotal:\s+(\d+)', meminfo)
                    if mem_total_re:
                        mem_total_kb = int(mem_total_re.group(1))
                        mem_total_mb = mem_total_kb // 1024

            cpuinfo_file = os.path.join(node_dir, item, "cpulist")
            cpu_list = []
            if os.path.exists(cpuinfo_file):
                with open(cpuinfo_file, 'r') as file:
                    cpu_info = file.read().strip() # remove newline at the end
                    cpu_list = parse_cpu_list(cpu_info) if len(cpu_info) > 0 else []
                         
            graph[item] = {
                'type': 'numa',
                'size_mb': mem_total_mb,
                'links': set(),
                'parent': set(),
                'cpus': cpu_list
            }
                        
def generate_dax_devices(graph: dict):
    dax_dir = "/sys/bus/dax/devices/"
    devices = {}
    for item in os.listdir(dax_dir):
        target_node_file = os.path.join(dax_dir, item, "target_node")
        numa_node_file = os.path.join(dax_dir, item, "numa_node")
        if os.path.exists(target_node_file) and os.path.exists(numa_node_file):
            with open(target_node_file, 'r') as file:
                target_node = int(file.read().strip())
            with open(numa_node_file, 'r') as file:
                numa_node = int(file.read().strip())
            graph[item] = {
                "type": "dax",
                "links": set(),
                "parent": set(),
                "target_node": target_node, 
                "numa_node": numa_node
                }
            if target_node >= 1:
                graph[item]['links'].add(f'node{target_node}')
                graph[f'node{target_node}']['parent'].add(item)
    return devices

def generate_cxl_devices(graph: dict):
    methods = [generate_cxl_devices_cxlctl, generate_cxl_devices_sysfs]
    success = False
    exceptions = []
    for func in methods:
        graph_copy = copy.deepcopy(graph)
        try:
            if func(graph_copy):
                success = True
                break
        except Exception as e:
            exceptions.append(e)
    if success:
        graph.update(graph_copy)
    else:
        raise Exception(f'Couldn\'t generate CXL devices: {str(exceptions)}')
    
def generate_cxl_devices_cxlctl(graph: dict):
    for memdev in cxl_list_memdevs():
        device_health = memdev['health'] if 'health' in memdev else None
        device = {
            'type': 'cxl',
            'serial': str(memdev['serial']),
            'links': set(),
            'parent': set(),
            'device_ram_size': memdev['ram_size'] // (1024 * 1024),
            'health': device_health
        }
        try:
            device.update(parse_lstopo_output(memdev['memdev']))
        except Exception as e:
            print('Error: Couldn\'t interpret lstopo output.')
        graph[memdev['memdev']] = device
    return True

def generate_cxl_devices_sysfs(graph: dict) -> int:
    def get_memdev_ram_size_sysfs(memdev):
        with open(f"/sys/bus/cxl/devices/{memdev}/ram/size", "r") as file:
            return int(file.read().strip(), 16) // (1024 * 1024)
    def get_memdev_serial_sysfs(memdev_name):
        file_path = f"/sys/bus/cxl/devices/{memdev_name}/serial"
        with open(file_path, "r") as file:
            serial_number = file.read().strip()
        return str(int(serial_number, 16))
        
    cxl_dir = "/sys/bus/cxl/devices/"
    for item in os.listdir(cxl_dir):
        if 'mem' in item:
            memdev = {
                'type': 'cxl',
                'serial': get_memdev_serial_sysfs(item),
                'links': set(),
                'parent': set(),
                'device_ram_size': get_memdev_ram_size_sysfs(item),
                'health': None
            }
            try:
                memdev.update(parse_lstopo_output(memdev['memdev']))
            except Exception as e:
                print('Error: Couldn\'t interpret lstopo output.')
            graph[item] =  memdev
    return True

def generate_root_devices(graph: dict) -> tuple:
    root_devices = {}
    root_links = []
    for memdev in list_cxl_devices():
        if not re.match(r'mem[0-9]+', memdev):
            continue
        node = int(subprocess.getoutput('cat /sys/bus/cxl/devices/{}/numa_node'.format(memdev)))
        node = node if node != -1 else 0
        if 'root{}'.format(node) not in root_devices:
            root_devices['root{}'.format(node)] = {
                'type': 'cxl_root_decoder',
                'links': set(),
                'parent': set()
            }
        root_links.append(('root{}'.format(node), memdev))
    
    for root_device in root_devices.keys():
        associated_numa_device_name = 'socket{}'.format(
            re.search(r'\d+', root_device).group()
        )
        root_links.append((associated_numa_device_name, root_device))
    graph.update(root_devices)
    for link in root_links:
        graph[link[0]]['links'].add(link[1])
        graph[link[1]]['parent'].add(link[0])

def generate_mem_dax_links(graph) -> list:
    try:
        new_links = set()
        decoder_dax_mapping = {
                re.findall(r'decoder[0-9]+.[0-9]+', dax_device['path'])[0]: dax_device['devices']
                for dax_device in daxctl_list_dr()
            }
        for bus in cxl_list_verbose():
            for decoder in bus['decoders:{}'.format(bus['bus'])]:
                try:
                    for region in decoder['regions:{}'.format(decoder['decoder'])]:
                        new_links.add((region['mappings'][0]['memdev'], decoder_dax_mapping[decoder['decoder']][0]['chardev']))
                except: continue
        for link in new_links:
            graph[link[0]]['links'].add(link[1])
            graph[link[1]]['parent'].add(link[0])
    except Exception:
        print("Couldn't auto-generate cxl<->dax links. Please specify links manually")
            
def generate_socket_devices(graph: dict):
    for socket_name, node_list in get_socket_nodes().items():
        socket_device = {
            'type': 'socket',
            'links': set(),
            'parent': set(),
            'cpus': [],
            'cpu_info': None,
            'dram': []
        }
        for node in node_list:
            cpus = get_node_cpus(node)
            if len(cpus) > 0:
                socket_device['links'].add(node)
                graph[node]['parent'].add(socket_name)
                socket_device['cpus'] += cpus
                if socket_device['cpu_info'] is None:
                    socket_device['cpu_info'] = get_cpu_info()
        socket_device['cpu_info']['On-line CPU(s) list'] = [
            cpu for cpu in socket_device['cpu_info']['On-line CPU(s) list'] if cpu in socket_device['cpus']
        ]
        graph[socket_name] = socket_device
        
def generate_memory_topology(graph):
    mem_info = get_memory_info()
    dualsocket_pattern = r'P\d+_Node\d+_Channel\w+_Dimm\d+'
    singlesocket_pattern = r'^P0 CHANNEL [A-Z]$'
    for handle in mem_info:
        socket = None
        if re.match(dualsocket_pattern, handle['Bank Locator']):
            pattern = r'P(\d+)_Node(\d+)'
            match = re.search(pattern, handle['Bank Locator'])
            if match:
                socket = int(match.group(1))
        elif re.match(singlesocket_pattern, handle['Bank Locator']):
            socket = 0
            
        if socket is not None:
            graph[f'socket{socket}']['dram'].append(handle)
        else:
            continue
        
def generate_manual_links(graph, manual_links):
    for (link_from, link_to) in manual_links: 
        try:
            graph[link_from]['links'].append(link_to)
            graph[link_to]['parent'].append(link_from)
        except Exception as e:
            print(f'Couldn\'t manually link {link_from} -> {link_to}')
            
def find_lstopo_parents(device):
    result = subprocess.run(['lstopo-no-graphics', '-v'], stdout=subprocess.PIPE)
    lines = result.stdout.decode('utf-8').split('\n')
    tree = {}
    level = {}
    last_node_at_level = {}
    devices = {}
    full_lines = {}
    pattern = re.compile(r'^(\s*)(.*?)( \(.*?\))?(\s*\"(.*?)\")?$')   # Matches leading spaces, trims the ending description in brackets, and extracts device name
    for line in lines:
        match = pattern.match(line)
        if match:
            depth = len(match.group(1))
            node = match.group(2).strip()
            device_name = match.group(5)
            if device_name:
                devices[device_name] = node
            if node:
                full_lines[node] = line
                parent = last_node_at_level.get(depth - 2, None)
                tree[node] = parent
                level[node] = depth
                last_node_at_level[depth] = node
    parents = []
    current_node = devices.get(device, None)
    if current_node is None:
        raise Exception(f"Device {device} not found in lstopo output.")
    while current_node is not None:
        parents.append(full_lines[current_node])
        current_node = tree[current_node]
    parents.reverse()
    return parents

def find_socket_nodes():
    output = subprocess.check_output(['numactl', '-H'], universal_newlines=True)
    node_pattern = re.compile(r'node\s+(\d+)\s+cpus:\s+([\d\s]+)')
    nodes = {}
    for match in node_pattern.finditer(output):
        node_id = match.group(1)
        cpus = [int(cpu) for cpu in match.group(2).split()]
        nodes[f'node{node_id}'] = cpus
    return nodes

def get_memory_info():
    cmd_output = subprocess.check_output("sudo dmidecode -t memory", shell=True).decode('utf-8')
    memory_info = cmd_output.split("\n")
    modules = []
    module_info = {}
    handle = None
    for line in memory_info:
        if "Handle" in line:
            handle = line.split(',')[0].split()[-1]
        if "Memory Device" in line and handle:
            module_info = {"Handle": handle}
        if "Size:" in line and "Handle" in module_info:
            size = line.split(":")[1].strip()
            module_info["Size"] = size if "No" not in size else "0GB"
        if "Bank Locator:" in line and "Handle" in module_info:
            module_info["Bank Locator"] = line.split(":", 1)[1].strip()
        if "Speed:" in line and "Handle" in module_info:
            module_info["Speed"] = line.split(":", 1)[1].strip()
        if "Manufacturer:" in line and "Handle" in module_info:
            module_info["Manufacturer"] = line.split(":", 1)[1].strip()
        if "Locator:" in line and "Bank Locator" not in line and "Handle" in module_info:
            module_info["Locator"] = line.split(":", 1)[1].strip()
        if "Size" in module_info and "Speed" in module_info and "Bank Locator" in module_info and "Manufacturer" in module_info:
            modules.append(module_info)
            module_info = {}
            handle = None
    return modules

def list_cxl_devices() -> list:
    out = subprocess.getoutput('ls /sys/bus/cxl/devices/')
    if "No such file or directory" in out:
        print('Warning: Couldn\'t access CXL directory')
        return []
    return out.split("\n")

def cxl_list_memdevs():
    return json.loads(subprocess.getoutput("{} list -MH".format(cxl_cmd)))

def cxl_list_verbose():
    return json.loads(subprocess.getoutput("{} list -vvvv".format(cxl_cmd)))

def daxctl_list_dr():
    return json.loads(subprocess.getoutput("{} list -DR".format(dax_cmd)))

def get_numa_node_size(node_name: str) -> int:
    with open(f"/sys/devices/system/node/{node_name}/meminfo", 'r') as file:
        for line in file:
            if "MemTotal" in line:
                return int(line.split()[3]) // 1024
            
def get_cpu_info():
    cpu_info_dict = {}
    lscpu_output = subprocess.check_output("lscpu", shell=True).decode('utf-8').split("\n")
    for line in lscpu_output:
        if "Architecture:" in line:
            cpu_info_dict["Architecture"] = line.split(":")[1].strip()
        if "Model name:" in line and "BIOS Model name" not in line:
            cpu_info_dict["Model name"] = line.split(":")[1].strip()
        if "Thread(s) per core:" in line:
            cpu_info_dict["Thread(s) per core"] = int(line.split(":")[1].strip())
        if "On-line CPU(s) list:" in line:
            cpu_info_dict["On-line CPU(s) list"] = parse_cpu_list(line.split(":")[1].strip())
        if "Core(s) per socket" in line:
            cpu_info_dict["Core(s) per socket"] = int(line.split(":")[1].strip())
        if line[:7] == 'CPU(s):':
            cpu_info_dict["CPU(s)"] = line.split(":")[1].strip()
    return cpu_info_dict

def parse_lstopo_output(memdev):
    try:
        lstopo_output = find_lstopo_parents(memdev)
        info_dict = {}
        host_bridge_info = []
        for line in lstopo_output:
            if "CXLMem" in line:
                slot_match = re.search(r'(PCISlot=)(\d+)', line)
                if slot_match:
                    info_dict['PCIe_slot_number'] = int(slot_match.group(2))
            if "HostBridge" in line:
                host_bridge_match = re.search(r'(HostBridge L#)(\d+)', line)
                if host_bridge_match:
                    host_bridge_info.append(int(host_bridge_match.group(2)))
            if "PCIVendor" in line:
                info_dict['vendor'] = re.search(r'PCIVendor="([^"]+)', line).group(1)   
        info_dict['host_bridge'] = host_bridge_info
        return info_dict
    except:
        return {
            'PCIe_slot_number': None,
            'host_bridge': None,
            'vendor': None
        }
        
def get_socket_nodes():
    command = 'lstopo-no-graphics'
    output = subprocess.getoutput(command)
    socket_nodes = {}
    current_socket = None
    for line in output.split('\n'):
        if 'Package L#' in line:
            current_socket = line.split('Package L#')[1].split()[0]
            socket_key = f'socket{current_socket}'
            socket_nodes[socket_key] = []
        elif 'NUMANode L#' in line:
            node_num = line.split('P#')[1].split()[0]
            socket_nodes[socket_key].append(f'node{node_num}')
    return socket_nodes

def get_node_cpus(node_name):
    node_id = int(node_name[4:])
    numactl_output = subprocess.getoutput('numactl -H')
    numactl_lines = numactl_output.split('\n')
    cpus_list = []
    for line in numactl_lines:
        if line.startswith(f"node {node_id} cpus"):
            cpus_list = line.split(':')[1].strip().split(' ')
            break
    return [int(cpu) for cpu in cpus_list] if '' not in cpus_list else []

def parse_cpu_list(online_cpu_list):
    cpus = []
    ranges = online_cpu_list.split(',')
    for cpu_range in ranges:
        if '-' in cpu_range:
            start, end = map(int, cpu_range.split('-'))
            cpus.extend(range(start, end + 1))
        else:
            cpus.append(int(cpu_range))
    return cpus
                        
if __name__ == "__main__":
    main()
