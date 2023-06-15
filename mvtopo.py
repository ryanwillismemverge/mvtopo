import subprocess
import os
import re
import json

cxl_cmd = '~/ndctl/build/cxl/cxl'
dax_cmd = '~/ndctl/build/daxctl/daxctl'

def generate_topology() -> dict:
    graph = {}
    generate_numa_nodes(graph)
    generate_dax_devices(graph)
    generate_cxl_devices(graph)
    generate_root_devices(graph)
    generate_mem_dax_links(graph)
    return graph

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
    cxl_dir = "/sys/bus/cxl/devices/"
    for item in os.listdir(cxl_dir):
        if 'mem' in item:
            # Use lstopo-no-graphic
            memdev = {
                'type': 'cxl',
                'serial': get_memdev_serial(item),
                'links': set(),
                'parent': set(),
                'health': get_memdev_health(item)
            }
            memdev.update(parse_lstopo_output(item))
            graph[item] =  memdev
            


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
        associated_numa_device_name = 'node{}'.format(
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


def get_memdev_serial(memdev_name):
    file_path = f"/sys/bus/cxl/devices/{memdev_name}/serial"
    with open(file_path, "r") as file:
        serial_number = file.read().strip()
    return str(int(serial_number, 16))

def get_memdev_health(memdev):
    output = subprocess.getoutput(f'{cxl_cmd} list -H')
    data = json.loads(output)

    for device in data:
        if 'memdevs' in device:
            for memdev in device['memdevs']:
                if memdev['memdev'] == memdev:
                    return memdev['health']
    return None


def list_cxl_devices() -> list:
    out = subprocess.getoutput('ls /sys/bus/cxl/devices/')
    if "No such file or directory" in out:
        print('Warning: Couldn\'t access CXL directory')
        return []
    return out.split("\n")

def cxl_list_verbose():
    return json.loads(subprocess.getoutput("{} list -vvvv".format(cxl_cmd)))

def daxctl_list_dr():
    return json.loads(subprocess.getoutput("{} list -DR".format(dax_cmd)))

def parse_lstopo_output(memdev):
    lstopo_output = find_lstopo_parents(memdev)
    info_dict = {}
    host_bridge_info = []
    for line in lstopo_output:
        if "CXLMem" in line:
            size_match = re.search(r'(CXLRAMSize=)(\d+)', line)
            if size_match:
                info_dict['device_ram_size'] = int(size_match.group(2))
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

                        
print(generate_topology())
