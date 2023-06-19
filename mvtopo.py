import subprocess
import os
import re
import json
import copy

cxl_cmd = '~/ndctl/build/cxl/cxl'
dax_cmd = '~/ndctl/build/daxctl/daxctl'

def generate_topology() -> dict:
    graph = {}
    generate_numa_nodes(graph)
    generate_dax_devices(graph)
    generate_cxl_devices(graph)
    generate_socket_devices(graph)
    generate_root_devices(graph) 
    generate_mem_dax_links(graph)
    generate_memory_topology(graph)
    return graph

def format_topology():
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
            
    topology = generate_topology()
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
            meminfo_file = os.path.join(node_dir, item, "meminfo")
            if os.path.exists(meminfo_file):
                with open(meminfo_file, 'r') as file:
                    meminfo = file.read()
                    mem_total_re = re.search(r'MemTotal:\s+(\d+)', meminfo)
                    if mem_total_re:
                        mem_total_kb = int(mem_total_re.group(1))
                        mem_total_mb = mem_total_kb // 1024
                        graph[item] = {
                            'type': 'numa',
                            'size_mb': mem_total_mb,
                            'links': set(),
                            'parent': set()
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
        device.update(parse_lstopo_output(memdev['memdev']))
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
            memdev.update(parse_lstopo_output(item))
            graph[item] =  memdev
    return True
            


def find_lstopo_parents(device):
    result = subprocess.run(['lstopo-no-graphics', '-v'], stdout=subprocess.PIPE)
    lines = result.stdout.decode('utf-8').split('\n')
    
    tree = {}
    level = {}
    last_node_at_level = {}
    devices = {}
    full_lines = {}
    pattern = re.compile(r'^(\s*)(.*?)( \(.*?\))?(\s*\"(.*?)\")?$')   # Matches leading spaces, trims the ending description in brackets, and extracts device names

    for line in lines:
        match = pattern.match(line)
        if match:
            depth = len(match.group(1))    # The number of leading spaces is the depth level
            node = match.group(2).strip()  # Trim any leading or trailing spaces
            device_name = match.group(5)   # Extract device name
            if device_name:                # If device name was found
                devices[device_name] = node    # Map device name to full node name
            if node:                       # Exclude empty lines
                full_lines[node] = line    # Keep track of the full line for each node
                parent = last_node_at_level.get(depth - 2, None)  # Parent is the last node at depth-2 (because each depth level represents two spaces)
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
                'type': 'root',
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
            
def generate_socket_devices(graph: dict):
    for numa_node, cpu_list in find_socket_nodes().items():
        node_num = int(numa_node.lstrip("node"))
        socket_device = {
                'type': 'socket',
                'links': {numa_node},
                'parent': set(),
                'cpus': cpu_list,
                'dram': []
        }
        graph[numa_node]['parent'].add(f'socket{node_num}')
        graph[f'socket{node_num}'] = socket_device
        
def generate_memory_topology(graph):
    mem_info = get_memory_info()
    dualsocket_pattern = r'P\d+_Node\d+_Channel\w+_Dimm\d+'
    singlesocket_pattern = r'^P0 CHANNEL [A-Z]$'
    mem_topo = {}
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

                        
print(format_topology())
