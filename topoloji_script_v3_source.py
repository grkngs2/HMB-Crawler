import concurrent.futures
import subprocess
import sys
from collections import deque
import socket
import uuid
from netmiko import ConnectHandler
from netmiko import NetMikoTimeoutException
from netmiko import NetMikoAuthenticationException
import time
import datetime
import re
from N2G import drawio_diagram
import netmiko
from getpass import getpass
import netmiko.exceptions
import paramiko

# Global variables
diagram = drawio_diagram()
x_scale_value = 500.0
y_scale_value = 1500.0
cdpORlldp = 0
x = 0
treeGraph = {
    'nodes': [],
    'links': []
}

# Account lists
accountListSSH = [
    {
        'name': 'vdkadmin',
        'port': 22,
        'username': 'vdkadmin',
        'password': '@dminswpwd',
        'device_type': 'cisco_ios',
        'verbose': True
    },
    # ... (diğer hesaplar)
]

accountListTELNET = [
    {
        'name': 'admin',
        'port': 23,
        'username': 'admin',
        'password': '!*Muh@5ebaT2020*!',
        'device_type': 'cisco_ios_telnet',
        'verbose': True
    },
    # ... (diğer hesaplar)
]

def process_ip(ip):
    try:
        # Initialize variables for topology discovery
        old_ip_list = []
        root_hostname = 'BB'
        isSDWan = False
        base_Platform = "Backbone"
        
        # Create topology tree
        mytree = Create_Tree(ip, old_ip_list, root_hostname, isSDWan, base_Platform, True, None, False)
        
        # Shape the tree
        shapedTree = buchheim(mytree)
        
        # Process the tree and generate diagram
        process_tree(shapedTree)
        
        # Save the diagram
        diagram.from_dict(treeGraph, width=300, height=200, diagram_name=f"{ip}_Topology")
        diagram.dump_file(filename=f"{ip}_Topology.drawio", folder="./Output/")
        
        return {
            'ip': ip,
            'success': True,
            'output': f"Topology diagram generated for {ip}",
            'error': None
        }
    except Exception as e:
        return {
            'ip': ip,
            'success': False,
            'error': str(e)
        }

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python ip_processor.py <ip_listesi.txt>")
        sys.exit(1)

    ip_file = sys.argv[1]

    try:
        # IP listesini oku
        with open(ip_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Hata: {ip_file} dosyası bulunamadı")
        sys.exit(1)

    # Paralel işlem için ThreadPoolExecutor kullan
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Her IP için işlemi başlat
        future_to_ip = {executor.submit(process_ip, ip): ip for ip in ips}
        
        # Sonuçları topla ve göster
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                print(f"\nIP: {result['ip']}")
                if result['success']:
                    print("Çıktı:")
                    print(result['output'])
                    if result['error']:
                        print("Hata:")
                        print(result['error'])
                else:
                    print(f"Hata: {result['error']}")
            except Exception as e:
                print(f"IP {ip} için hata oluştu: {str(e)}")

def process_tree(shapedTree):
    """Process the tree structure and generate diagram.
    
    Args:
        shapedTree (DrawTree): The shaped tree structure to process
    """
    global treeGraph
    treeGraph = {
        "cells": []
    }
    
    # Add root node
    root = shapedTree.tree
    if root.value.authenticationCheck:
        style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
    elif root.value.timeoutCheck:
        style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;"
    elif root.value.duplicateCheck:
        style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
    else:
        style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
    
    # Add root node to diagram
    treeGraph["cells"].append({
        "id": str(uuid.uuid4()),
        "value": formatLabelString(root.value.ip, root.value.hostname, root.value.platform),
        "style": style,
        "vertex": 1,
        "geometry": {
            "x": shapedTree.x * 200,
            "y": shapedTree.y * 100,
            "width": 120,
            "height": 60
        }
    })
    
    # Process children
    depth_first_traversal(shapedTree)

def depth_first_traversal(shapedTreeCopy):
    """Perform depth-first traversal of the tree and add nodes to diagram.
    
    Args:
        shapedTreeCopy (DrawTree): The tree structure to traverse
    """
    global treeGraph
    
    for child in shapedTreeCopy.children:
        # Determine node style based on conditions
        if child.tree.value.authenticationCheck:
            style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#d5e8d4;strokeColor=#82b366;"
        elif child.tree.value.timeoutCheck:
            style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#f8cecc;strokeColor=#b85450;"
        elif child.tree.value.duplicateCheck:
            style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#fff2cc;strokeColor=#d6b656;"
        else:
            style = "rounded=1;whiteSpace=wrap;html=1;fillColor=#dae8fc;strokeColor=#6c8ebf;"
        
        # Add node to diagram
        node_id = str(uuid.uuid4())
        treeGraph["cells"].append({
            "id": node_id,
            "value": formatLabelString(child.tree.value.ip, child.tree.value.hostname, child.tree.value.platform),
            "style": style,
            "vertex": 1,
            "geometry": {
                "x": child.x * 200,
                "y": child.y * 100,
                "width": 120,
                "height": 60
            }
        })
        
        # Add edge to diagram
        treeGraph["cells"].append({
            "id": str(uuid.uuid4()),
            "source": node_id,
            "target": str(uuid.uuid4()),
            "edge": 1,
            "style": "endArrow=classic;html=1;"
        })
        
        # Recursively process children
        depth_first_traversal(child)

def formatLabelString(ip, hostname, platform):
    """Format the label string for a node.
    
    Args:
        ip (str): IP address
        hostname (str): Hostname
        platform (str): Platform information
    
    Returns:
        str: Formatted label string
    """
    # Clean up platform name
    if "Ruijie" in platform:
        platform = "Ruijie"
    
    # Remove extra whitespace
    ip = ' '.join(ip.split())
    hostname = ' '.join(hostname.split())
    platform = ' '.join(platform.split())
    
    return f"{hostname}\n{ip}\n{platform}"

def findDupSwitch(dupSwitch, shapedTreeforFunc, root=1):
    """Find duplicate switches in the tree structure.
    
    Args:
        dupSwitch (Switch): The switch to check for duplicates
        shapedTreeforFunc (DrawTree): The tree structure to search in
        root (int): Flag indicating if this is the root node (1) or not (0)
    
    Returns:
        bool: True if duplicate found, False otherwise
    """
    if root == 1:
        # Check root node
        if dupSwitch.ip == shapedTreeforFunc.tree.ip:
            return True
        # Check children of root
        return findDupSwitch(dupSwitch, shapedTreeforFunc.children, 0)
    else:
        # Check all children nodes
        for child in shapedTreeforFunc:
            if dupSwitch.ip == child.tree.ip:
                return True
            if findDupSwitch(dupSwitch, child.children, 0):
                return True
        return False

class DrawTree:
    def __init__(self, tree, parent=None, depth=0, number=1):
        self.x = -1.0
        self.y = depth
        self.tree = tree
        self.children = [
            DrawTree(c, self, depth + 1, i + 1) for i, c in enumerate(tree.children)
        ]
        self.parent = parent
        self.thread = None
        self.mod = 0
        self.ancestor = self
        self.change = self.shift = 0
        self._lmost_sibling = None
        self.number = number

    def left(self):
        return self.thread or len(self.children) and self.children[0]

    def right(self):
        return self.thread or len(self.children) and self.children[-1]

    def lbrother(self):
        n = None
        if self.parent:
            for node in self.parent.children:
                if node == self:
                    return n
                else:
                    n = node
        return n

    def get_lmost_sibling(self):
        if not self._lmost_sibling and self.parent and self != self.parent.children[0]:
            self._lmost_sibling = self.parent.children[0]
        return self._lmost_sibling

    lmost_sibling = property(get_lmost_sibling)

class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []
        
    def add_child(self, child):
        self.children.append(child)

class Switch:
    def __init__(self, ip, hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, platform, readTimeoutCheck, id, duplicateCheck, ipList):
        self.hostname = hostname
        self.ip = ip
        self.ipList = ipList
        self.intList = intList
        self.authenticationCheck = authenticationCheck
        self.timeoutCheck = timeoutCheck
        self.ipValueCheck = ipValueCheck
        self.isSDWan = isSDWan
        self.platform = platform
        self.readTimeoutCheck = readTimeoutCheck
        self.id = id
        self.duplicateCheck = duplicateCheck

class Interface:
    def __init__(self, localPort, remotePort, remoteIp, remoteHostname, remotePlatform):
        self.localPort = localPort
        self.remotePort = remotePort
        self.remoteIp = remoteIp
        self.remoteHostname = remoteHostname
        self.remotePlatform = remotePlatform

def buchheim(tree):
    dt = firstwalk(DrawTree(tree))
    min = second_walk(dt)
    if min < 0:
        third_walk(dt, -min)
    return dt

def firstwalk(v, distance=1.0):
    if len(v.children) == 0:
        if v.lmost_sibling:
            v.x = v.lbrother().x + distance
        else:
            v.x = 0.0
    else:
        default_ancestor = v.children[0]
        for w in v.children:
            firstwalk(w)
            default_ancestor = apportion(w, default_ancestor, distance)
        
        execute_shifts(v)

        midpoint = (v.children[0].x + v.children[-1].x) / 2

        w = v.lbrother()
        if w:
            v.x = w.x + distance
            v.mod = v.x - midpoint
        else:
            v.x = midpoint
    return v

def apportion(v, default_ancestor, distance):
    w = v.lbrother()
    if w is not None:
        vir = vor = v
        vil = w
        vol = v.lmost_sibling
        sir = sor = v.mod
        sil = vil.mod
        sol = vol.mod
        while vil.right() and vir.left():
            vil = vil.right()
            vir = vir.left()
            vol = vol.left()
            vor = vor.right()
            vor.ancestor = v
            shift = (vil.x + sil) - (vir.x + sir) + distance
            if shift > 0:
                move_subtree(ancestor(vil, v, default_ancestor), v, shift)
                sir = sir + shift
                sor = sor + shift
            sil += vil.mod
            sir += vir.mod
            sol += vol.mod
            sor += vor.mod
        if vil.right() and not vor.right():
            vor.thread = vil.right()
            vor.mod += sil - sor
        else:
            if vir.left() and not vol.left():
                vol.thread = vir.left()
                vol.mod += sir - sol
            default_ancestor = v
    return default_ancestor

def move_subtree(wl, wr, shift):
    subtrees = wr.number - wl.number
    wr.change -= shift / subtrees
    wr.shift += shift
    wl.change += shift / subtrees
    wr.x += shift
    wr.mod += shift

def execute_shifts(v):
    shift = change = 0
    for w in v.children[::-1]:
        w.x += shift
        w.mod += shift
        change += w.change
        shift += w.shift + change

def ancestor(vil, v, default_ancestor):
    if vil.ancestor in v.parent.children:
        return vil.ancestor
    else:
        return default_ancestor

def second_walk(v, m=0, depth=0, min=None):
    v.x += m
    v.y = depth

    if min is None or v.x < min:
        min = v.x

    for w in v.children:
        min = second_walk(w, m + v.mod, depth + 1, min)

    return min

def third_walk(tree, n):
    tree.x += n
    for c in tree.children:
        third_walk(c, n)

def trySSH(base_IP):
    """Try to connect to device using SSH"""
    for account in accountListSSH:
        account2 = dict(account, **{'ip': base_IP})
        account2.pop('name')
        try:
            ssh_connection = ConnectHandler(**account2)
            return ssh_connection
        except NetMikoTimeoutException:
            print(f"Couldn't connect to ip {base_IP} Reason: Timeout. Trying telnet")
            return tryTelnet(base_IP)
        except NetMikoAuthenticationException:
            if account == accountListSSH[-1]:
                print(f"Couldn't connect to ip {base_IP} with account {account2['username']} Reason: Authentication Failed. No more try.")
                raise NetMikoAuthenticationException
            else:
                print(f"Couldn't connect to ip {base_IP} with account {account2['username']} Reason: Authentication Failed. Trying again.")
        except ValueError:
            print(f"SSH Couldn't connect to ip {base_IP} Reason: IP syntax is incorrect or not exist")
            raise ValueError
        except netmiko.exceptions.ReadTimeout:
            try:
                account2['device_type'] = 'hp_procurve'
                ssh_connection = ConnectHandler(**account2)
                return ssh_connection
            except netmiko.exceptions.ReadTimeout:
                print('INVALID DEVICE')

def tryTelnet(base_IP):
    """Try to connect to device using Telnet"""
    if base_IP == "10.210.4.1":
        raise NetMikoTimeoutException
    for account in accountListTELNET:
        account2 = dict(account, **{'ip': base_IP})
        account2.pop('name')
        try:
            telnet_connection = ConnectHandler(**account2)
            return telnet_connection
        except NetMikoTimeoutException:
            print(f"Couldn't connect to ip {base_IP} Reason:Timeout")
            raise NetMikoTimeoutException
        except NetMikoAuthenticationException:
            if account == accountListTELNET[-1]:
                print(f"Couldn't connect to ip {base_IP} with account {account2['username']} Reason: Authentication Failed. No more try.")
                raise NetMikoAuthenticationException
            else:
                print(f"Couldn't connect to ip {base_IP} with account {account2['username']} Reason: Authentication Failed. Trying again.")
        except ValueError:
            print(f"Telnet Couldn't connect to ip {base_IP} Reason: IP syntax is incorrect or not exist")
            raise ValueError

def Create_Tree(base_IP, old_ip_list, base_Hostname, isSDWan, base_Platform, isRoot, fatherSwitch, duplicate):
    """Create topology tree for a device"""
    if "ECXS" in base_Platform or "Rev B" in base_Platform:
        isSDWan = True
    else:
        isSDWan = False
    
    print(f"Trying to connect to {base_IP}")
    
    timeoutCheck = True
    authenticationCheck = True
    ipValueCheck = True
    readTimeoutCheck = True
    isProcurve = False
    isComware = False
    
    if base_IP == '127.0.0.1':
        timeoutCheck = False
    else:
        if duplicate is False:
            try:
                ssh_connection = trySSH(base_IP)
            except NetMikoAuthenticationException:
                authenticationCheck = False
            except NetMikoTimeoutException:
                timeoutCheck = False
            except ValueError:
                ipValueCheck = False
            except TimeoutError:
                timeoutCheck = False
            except ConnectionRefusedError:
                authenticationCheck = False
            except socket.error:
                readTimeoutCheck = False
                return returnForInvalid(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck)
            except Exception as e:
                print(f"Invalid Device: {str(e)}")
                readTimeoutCheck = False
                return returnForInvalid(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck)
    
    if (authenticationCheck is True and timeoutCheck is True and ipValueCheck is True and 
        isSDWan is False and readTimeoutCheck is True and duplicate is False):
        try:
            deviceTypeCheck = ssh_connection.send_command('show ver')
            if 'invalid' in deviceTypeCheck.lower() or 'unrecognized' in deviceTypeCheck.lower():
                deviceTypeCheck = 'HPComware'
                isComware = True
                cdpORlldp = 1
            else:
                isComware = False
                deviceTypeCheck = ssh_connection.send_command('display clock')
                if 'invalid' in deviceTypeCheck.lower() or 'unrecognized' in deviceTypeCheck.lower():
                    isProcurve = False
                    cdpORlldp = 0
                    print('Ciscos')
                else:
                    isProcurve = True
                    cdpORlldp = 1
        except netmiko.exceptions.ReadTimeout:
            readTimeoutCheck = False
            return returnForInvalid(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck)
        
        if cdpORlldp == 0:
            return useCDP(ssh_connection, base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, isRoot, old_ip_list, readTimeoutCheck, fatherSwitch)
        elif cdpORlldp == 1:
            return useLLDP(ssh_connection, base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, isRoot, old_ip_list, readTimeoutCheck, isComware, isProcurve, fatherSwitch)
    else:
        if duplicate is True:
            return returnForDuplicate(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck)
        return returnForInvalid(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck)

def returnForInvalid(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck):
    """Return an invalid switch node"""
    intList = []
    id = str(uuid.uuid4())
    switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=False, ipList=None)
    root = TreeNode(switch)
    return root

def returnForDuplicate(base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck):
    """Return a duplicate switch node"""
    intList = []
    id = str(uuid.uuid4())
    switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=True, ipList=None)
    root = TreeNode(switch)
    return root

def useCDP(ssh_connection, base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, isRoot, old_ip_list, readTimeoutCheck, fatherSwitch):
    """Use CDP to discover neighbors"""
    interface = ssh_connection.send_command('show cdp ne de | inc Interface')
    print(f"BASE IP: {base_IP}")
    ip_list = askIPIntBriefForCDP(ssh_connection)
    old_ip_list.extend(ip_list)
    intList = formatInterfaceForCDP(interface, ssh_connection)
    ssh_connection.disconnect()
    id = str(uuid.uuid4())
    switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=False, ipList=ip_list)
    root = TreeNode(switch)
    for x in switch.intList:
        if fatherSwitch is not None and x.remoteIp in fatherSwitch.ipList:
            print("loop to father")
        elif x.remoteIp in old_ip_list:
            print("loop to nonfather")
            root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=True))
        else:
            root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=False))
    return root

def useLLDP(ssh_connection, base_IP, base_Hostname, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, isRoot, old_ip_list, readTimeoutCheck, isComware, isProcurve, fatherSwitch):
    """Use LLDP to discover neighbors"""
    if isComware:
        localPorts = ssh_connection.send_command('display lldp local | inc local-information')
        intList = formatInterfaceForComware(localPorts, ssh_connection)
        old_ip_list.extend(askIPIntBriefForLLDPComware(ssh_connection))
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=False, ipList=None)
        root = TreeNode(switch)
        for x in switch.intList:
            if x.remoteIp not in old_ip_list:
                print("CHILD \n")
                print(f"CHILD IP : {x.remoteIp}\n")
                print(f"CHILD HOSTNAME : {x.remoteHostname}\n")
                print(f"CHILD PLATFORM : {x.remotePlatform}\n")
        
        for x in switch.intList:
            if fatherSwitch is not None and x.remoteIp in fatherSwitch.ipList:
                print("loop to father")
            elif x.remoteIp in old_ip_list:
                print("loop to nonfather")
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=True))
            elif x.remoteIp.isspace() is not True and x.remoteIp != "":
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=False))
        return root
    elif isProcurve:
        localPorts = ssh_connection.send_command('show lldp info rem all | inc Local Port')
        intList = formatInterfaceForProcurve(localPorts, ssh_connection)
        old_ip_list.extend(askIPIntBriefForLLDPProcurve(ssh_connection))
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=False, ipList=None)
        root = TreeNode(switch)
        for x in switch.intList:
            if x.remoteIp not in old_ip_list:
                print("CHILD \n")
                print(f"CHILD IP : {x.remoteIp}\n")
                print(f"CHILD HOSTNAME : {x.remoteHostname}\n")
                print(f"CHILD PLATFORM : {x.remotePlatform}\n")
        for x in switch.intList:
            if fatherSwitch is not None and x.remoteIp in fatherSwitch.ipList:
                print("loop to father")
            elif x.remoteIp in old_ip_list:
                print("loop to nonfather")
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=True))
            elif x.remoteIp.isspace() is not True and x.remoteIp != "":
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=False))
        return root
    else:
        interface = ssh_connection.send_command('sh lldp ne de | inc LLDP neighbor-information of port')
        old_ip_list.extend(askIPIntBriefForLLDP(ssh_connection))
        intList = formatInterfaceForLLDP(interface, ssh_connection)
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP, base_Hostname, intList, authenticationCheck, timeoutCheck, ipValueCheck, isSDWan, base_Platform, readTimeoutCheck, id, duplicateCheck=False, ipList=None)
        root = TreeNode(switch)
        for x in switch.intList:
            if fatherSwitch is not None and x.remoteIp in fatherSwitch.ipList:
                print("loop to father")
            elif x.remoteIp in old_ip_list:
                print("loop to nonfather")
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=True))
            else:
                root.add_child(Create_Tree(x.remoteIp, old_ip_list, x.remoteHostname, False, x.remotePlatform, isRoot, switch, duplicate=False))
        return root

def askIPIntBriefForCDP(ssh_connection):
    """Get IP interfaces for CDP"""
    ipIntBr = ssh_connection.send_command('show ip int brief | inc Vlan')
    if ipIntBr == '':
        ipIntBr = ssh_connection.send_command('sh ip int br vrf all')
    myList = ipIntBr.splitlines()
    old_ip_list = []
    
    for vlanIp in myList:
        tryToFind = True
        try:
            indexOfIp = vlanIp.index('10.')
        except ValueError:
            try:
                indexOfIp = vlanIp.index('172.')
            except ValueError:
                tryToFind = False
            
        if tryToFind is True:
            vlanIp = vlanIp[indexOfIp:indexOfIp+15]
            vlanIp = ''.join(vlanIp.split())
            old_ip_list.append(vlanIp)
    print("ipintbrief: ")
    print(old_ip_list)
    return old_ip_list

def askIPIntBriefForLLDP(ssh_connection):
    """Get IP interfaces for LLDP"""
    ipIntBr = ssh_connection.send_command('show ip int brief | inc VLAN')
    myList = ipIntBr.splitlines()
    old_ip_list = []
    for vlanIp in myList:
        tryToFind = True
        try:
            indexOfIp = vlanIp.index('10.')
        except ValueError:
            try:
                indexOfIp = vlanIp.index('172.')
            except ValueError:
                tryToFind = False
        if tryToFind is True:
            indexOfSlash = vlanIp.index('/')
            vlanIp = vlanIp[indexOfIp:indexOfSlash]
            old_ip_list.append(vlanIp)
    return old_ip_list

def askIPIntBriefForLLDPComware(ssh_connection):
    """Get IP interfaces for LLDP on Comware devices"""
    ipIntBr = ssh_connection.send_command('display ip int brief')
    myList = ipIntBr.splitlines()
    old_ip_list = []
    for ip in myList:
        tryToFind = True
        try:
            indexOfIp = ip.index('10.')
        except ValueError:
            try:
                indexOfIp = ip.index('172.')
            except ValueError:
                tryToFind = False
        if tryToFind is True:
            ip = ip[indexOfIp:indexOfIp+15]
            ip = ''.join(ip.split())
            old_ip_list.append(ip)
    return old_ip_list

def askIPIntBriefForLLDPProcurve(ssh_connection):
    """Get IP interfaces for LLDP on Procurve devices"""
    ipIntBr = ssh_connection.send_command('show ip | inc 10')
    ipIntBr2 = ssh_connection.send_command('show ip | inc 172')
    myList = ipIntBr.splitlines()
    myList2 = ipIntBr2.splitlines()
    old_ip_list = []
    for ip in myList:
        if 'Default Gateway' not in ip:
            tryToFind = True
            try:
                indexOfIp = ip.index('10.')
            except ValueError:
                tryToFind = False
            if tryToFind is True:
                ip = ip[indexOfIp:indexOfIp+15]
                ip = ''.join(ip.split())
                old_ip_list.append(ip)

    for ip in myList2:
        if 'Default Gateway' not in ip:
            tryToFind = True
            try:
                indexOfIp = ip.index('172.')
            except ValueError:
                tryToFind = False
            if tryToFind is True:
                ip = ip[indexOfIp:indexOfIp+15]
                ip = ''.join(ip.split())
                old_ip_list.append(ip)
    return old_ip_list

def formatInterfaceForCDP(interface, ssh_connection):
    """Format interface information for CDP"""
    intList = []
    myList = interface.splitlines()
    
    for int in myList:
        try:
            int = int.replace('Interface:', '')
            int = ''.join(int.split())
            i = int.index(',PortID')
            localInt = int[:i]
            k = i + len(",PortID(outgoing port):")
            remoteInt = int[k:]
            print(f"accept: {int}")
            intList.append(Interface(localInt, remoteInt, askCdpNeighIpOfInterface(ssh_connection, localInt), 
                                   askCdpNeighHostnameOfInterface(ssh_connection, localInt), 
                                   askCdpNeighPlatformOfInterface(ssh_connection, localInt)))
        except ValueError:
            print(f"pass: {int}")
    return intList

def formatInterfaceForLLDP(interface, ssh_connection):
    """Format interface information for LLDP"""
    intList = []
    myList = interface.splitlines()
    for int in myList:
        int = int.replace('LLDP neighbor-information of port [', '')
        int = int.replace(']', '')
        localInt = int
        intList.append(Interface(localInt, askLldpNeighPort(ssh_connection, localInt), 
                               askLldpNeighIpOfInterface(ssh_connection, localInt), 
                               askLldpNeighHostnameOfInterface(ssh_connection, localInt), 
                               askLldpNeighPlatformOfInterface(ssh_connection, localInt)))
    return intList

def formatInterfaceForComware(localPorts, ssh_connection):
    """Format interface information for Comware devices"""
    intList = []
    myList = localPorts.splitlines()
    for int in myList:
        int = re.findall(r'\[.*?\]', int)
        if int:
            int = int[0]
            int = int.replace('[', '')
            int = int.replace(']', '')
            intList.append(Interface(int, askLldpNeighPortComware(ssh_connection, int), 
                                   askLldpNeighIpOfInterfaceComware(ssh_connection, int), 
                                   askLldpNeighHostnameOfInterfaceComware(ssh_connection, int), 
                                   askLldpNeighPlatformOfInterfaceComware(ssh_connection, int)))
    return intList

def formatInterfaceForProcurve(localPorts, ssh_connection):
    """Format interface information for Procurve devices"""
    intList = []
    myList = localPorts.splitlines()
    for int in myList:
        int = int[int.index(':')+1:]
        intList.append(Interface(int, askLldpNeighPortProcurve(ssh_connection, int), 
                               askLldpNeighIpOfInterfaceProcurve(ssh_connection, int), 
                               askLldpNeighHostnameOfInterfaceProcurve(ssh_connection, int), 
                               askLldpNeighPlatformOfInterfaceProcurve(ssh_connection, int)))
    return intList

def askCdpNeighIpOfInterface(ssh_connection, localPort):
    """Get neighbor IP for CDP interface"""
    output = ssh_connection.send_command(f'show cdp ne {localPort} de | inc IP address:')
    if 'Invalid' in output:
        output = ssh_connection.send_command(f'show cdp ne int {localPort} de | inc IPv4')
        ip = formatIPForCDPNexus(output)
    else:
        ip = formatIPForCDP(output)
    return ip

def askLldpNeighIpOfInterface(ssh_connection, localPort):
    """Get neighbor IP for LLDP interface"""
    output = ssh_connection.send_command(f'show lldp ne int {localPort} de | inc Management address                :')
    ip = formatIPForLLDP(output)
    return ip

def askCdpNeighHostnameOfInterface(ssh_connection, localPort):
    """Get neighbor hostname for CDP interface"""
    output = ssh_connection.send_command(f'show cdp ne {localPort} de | inc Device ID:')
    if 'Invalid' in output:
        output = ssh_connection.send_command(f'show cdp ne int {localPort} de | inc Device')
        hostname = formatHostnameForCDP(output)
    else:
        hostname = formatHostnameForCDP(output)
    return hostname

def askLldpNeighHostnameOfInterface(ssh_connection, localPort):
    """Get neighbor hostname for LLDP interface"""
    output = ssh_connection.send_command(f'show lldp ne int {localPort} de | inc System name')
    hostname = formatHostnameForLLDP(output)
    return hostname

def askCdpNeighPlatformOfInterface(ssh_connection, localPort):
    """Get neighbor platform for CDP interface"""
    platform = ssh_connection.send_command(f'show cdp ne {localPort} de | inc Platform:')
    if 'Invalid' in platform:
        platform = ssh_connection.send_command(f'show cdp ne int {localPort} de | inc Platform:')
    return platform

def askLldpNeighPlatformOfInterface(ssh_connection, localInt):
    """Get neighbor platform for LLDP interface"""
    platform = ssh_connection.send_command(f'show lldp ne int {localInt} de | inc System description')
    platform = platform.replace('  System description                : ', 'Platform: ')
    return platform

def askLldpNeighPort(ssh_connection, localInt):
    """Get neighbor port for LLDP interface"""
    remoteInt = ssh_connection.send_command(f'show lldp ne int {localInt} de  | inc Port description')
    remoteInt = remoteInt.replace('  Port description                  : ', '')
    return remoteInt

def askLldpNeighPortComware(ssh_connection, int):
    """Get neighbor port for LLDP interface on Comware devices"""
    output = ssh_connection.send_command(f'display lldp ne int {int} ver | inc Port')
    myList = output.splitlines()
    for remoteInt in myList:
        if 'type' not in remoteInt and 'ID' in remoteInt and 'VLAN' not in remoteInt:
            i = remoteInt.index(':')
            remoteInt = remoteInt[i+2:]
            return remoteInt
    return ''

def askLldpNeighIpOfInterfaceComware(ssh_connection, int):
    """Get neighbor IP for LLDP interface on Comware devices"""
    output = ssh_connection.send_command(f'display lldp ne int {int} ver | inc 10')
    myList = output.splitlines()
    for ip in myList:
        if '10.' in ip:
            ip = ip[ip.index('10.'):]
            return ip
    return ''

def askLldpNeighHostnameOfInterfaceComware(ssh_connection, int):
    """Get neighbor hostname for LLDP interface on Comware devices"""
    output = ssh_connection.send_command(f'display lldp ne int {int} ver | inc name')
    output2 = ssh_connection.send_command(f'display lldp ne int {int} ver | inc Chassis')
    myList = output.splitlines()
    myList2 = output2.splitlines()
    for hostname in myList:
        if 'System name' in hostname:
            hostname = hostname[hostname.index(':')+1:]
            return hostname
    
    for hostname in myList2:
        if 'Chassis ID' in hostname:
            hostname = hostname[hostname.index(':')+1:]
            return hostname
    return ''

def askLldpNeighPlatformOfInterfaceComware(ssh_connection, int):
    """Get neighbor platform for LLDP interface on Comware devices"""
    output = ssh_connection.send_command(f'display lldp ne int {int} ver | inc description')
    output2 = ssh_connection.send_command(f'display lldp ne int {int} ver | inc Platform')
    myList = output.splitlines()
    myList2 = output2.splitlines()
    for platform in myList:
        if 'System description' in platform:
            platform = platform[platform.index(':')+1:]
            return platform
    for platform in myList2:
        if 'Platform version' in platform:
            platform = platform[platform.index(':')+1:]
            return platform
    return ''

def askLldpNeighPortProcurve(ssh_connection, int):
    """Get neighbor port for LLDP interface on Procurve devices"""
    output = ssh_connection.send_command(f'show lldp info rem {int} | inc PortId')
    myList = output.splitlines()
    for remoteInt in myList:
        i = remoteInt.index(':')
        remoteInt = remoteInt[i+2:]
        return remoteInt
    return ''

def askLldpNeighIpOfInterfaceProcurve(ssh_connection, int):
    """Get neighbor IP for LLDP interface on Procurve devices"""
    output = ssh_connection.send_command(f'show lldp info rem {int} | inc Address :')
    myList = output.splitlines()
    for ip in myList:
        if '10.' in ip:
            ip = ip[ip.index('10.'):]
            return ip
    return ''

def askLldpNeighHostnameOfInterfaceProcurve(ssh_connection, int):
    """Get neighbor hostname for LLDP interface on Procurve devices"""
    output = ssh_connection.send_command(f'show lldp info rem {int} | inc SysName')
    myList = output.splitlines()
    for SysName in myList:
        if 'SysName' in SysName:
            SysName = SysName[SysName.index(':')+1:]
            return SysName
    return ''

def askLldpNeighPlatformOfInterfaceProcurve(ssh_connection, int):
    """Get neighbor platform for LLDP interface on Procurve devices"""
    output = ssh_connection.send_command(f'show lldp info rem {int} | inc Descr :')
    myList = output.splitlines()
    for platform in myList:
        if 'System Descr' in platform:
            platform = platform[platform.index(':')+1:]
            return platform
    return ''

def formatIPForCDP(ip):
    """Format IP address from CDP output"""
    if ip == '':
        return ''
    else:
        ip = ip.replace('  IP address: ', '')
        myList = ip.splitlines()
        myList = list(sorted(set(myList), key=myList.index))
        return myList[0]

def formatIPForCDPNexus(ip):
    """Format IP address from CDP Nexus output"""
    if ip == '':
        return ''
    else:
        ip = ip.replace('    IPv4 Address: ', '')
        myList = ip.splitlines()
        myList = list(sorted(set(myList), key=myList.index))
        return myList[0]

def formatIPForLLDP(ip):
    """Format IP address from LLDP output"""
    if ip == '':
        return ''
    else:
        ip = ip.replace('  Management address                : ', '')
        myList = ip.splitlines()
        myList = list(sorted(set(myList), key=myList.index))
        return myList[0]

def formatHostnameForCDP(hostname):
    """Format hostname from CDP output"""
    hostname = ''.join(hostname.split())
    hostname = hostname.replace('DeviceID:', '')
    myList = hostname.splitlines()
    myList = list(sorted(set(myList), key=myList.index))
    return myList[0]

def formatHostnameForLLDP(hostname):
    """Format hostname from LLDP output"""
    hostname = hostname.replace('  System name                       : ', '')
    if hostname == '':
        return ''
    else:
        myList = hostname.splitlines()
        myList = list(sorted(set(myList), key=myList.index))
        return myList[0]

if __name__ == "__main__":
    main() 