import socket
import uuid
from netmiko import ConnectHandler
from netmiko import NetMikoTimeoutException
from netmiko import NetMikoAuthenticationException
import time
import concurrent.futures
import datetime
import re
from N2G import drawio_diagram
import netmiko
from getpass import getpass

import netmiko.exceptions
import paramiko

diagram = drawio_diagram()
diagram.add_diagram("Page-1")
x_scale_value = 500.0
y_scale_value = 1500.0
cdpORlldp = 0
x = 0

accountListSSH = [
    
    ]
accountListTELNET = [
    
    ]


class DrawTree(object):
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
        # this is the number of the node in its group of siblings 1..n
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

    def __str__(self):
        return "%s: x=%s mod=%s" % (self.tree, self.x, self.mod)

    def __repr__(self):
        return self.__str__()


#Buchheim Tree Draw algoritması https://link.springer.com/content/pdf/10.1007/3-540-36151-0_32.pdf
def buchheim(tree): 
    dt = firstwalk(DrawTree(tree))
    min = second_walk(dt)
    if min < 0:
        third_walk(dt, -min)
    return dt


def third_walk(tree, n):
    tree.x += n
    for c in tree.children:
        third_walk(c, n)


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

        # ell = v.children[0]
        # arr = v.children[-1]
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
        # in buchheim notation:
        # i == inner; o == outer; r == right; l == left; r = +; l = -
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
    # the relevant text is at the bottom of page 7 of
    # "Improving Walker's Algorithm to Run in Linear Time" by Buchheim et al, (2002)
    # http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.16.8757&rep=rep1&type=pdf
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


class TreeNode:
    def __init__(self, value):
        self.value = value
        self.children = []
        
    def add_child(self, child):
        self.children.append(child)


class Switch:
    def __init__(self,ip,hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,platform,readTimeoutCheck,id):
        self.hostname = hostname
        self.ip = ip
        self.intList = intList
        self.authenticationCheck = authenticationCheck
        self.timeoutCheck = timeoutCheck
        self.ipValueCheck = ipValueCheck
        self.isSDWan = isSDWan
        self.platform = platform
        self.readTimeoutCheck = readTimeoutCheck
        self.id = id


class Interface:
    def __init__(self,localPort,remotePort,remoteIp,remoteHostname,remotePlatform):
        self.localPort = localPort
        self.remotePort = remotePort
        self.remoteIp = remoteIp
        self.remoteHostname = remoteHostname
        self.remotePlatform = remotePlatform

def askCdpNeighIpOfInterface(ssh_connection,localPort):
    output = ssh_connection.send_command('show cdp ne '+localPort+' de | inc IP address:')
    if('Invalid' in output):
        output = ssh_connection.send_command('show cdp ne int '+localPort+' de | inc IPv4')
        ip = formatIPForCDPNexus(output)
    else:
        ip = formatIPForCDP(output)
    return ip

def askLldpNeighIpOfInterface(ssh_connection,localPort):
    output = ssh_connection.send_command('show lldp ne int '+localPort+' de | inc Management address                :')
    ip = formatIPForLLDP(output)
    return ip

def askCdpNeighHostnameOfInterface(ssh_connection,localPort):
    output = ssh_connection.send_command('show cdp ne '+localPort+' de | inc Device ID:')
    if('Invalid' in output):
        output = ssh_connection.send_command('show cdp ne int '+localPort+' de | inc Device')
        hostname = formatHostnameForCDP(output)
    else:
        hostname = formatHostnameForCDP(output)
    return hostname

def askLldpNeighHostnameOfInterface(ssh_connection,localPort):
    output = ssh_connection.send_command('show lldp ne int '+localPort+' de | inc System name')
    hostname = formatHostnameForLLDP(output)
    return hostname

def askCdpNeighPlatformOfInterface(ssh_connection,localPort):
    platform = ssh_connection.send_command('show cdp ne '+localPort+' de | inc Platform:')
    if('Invalid' in platform):
        platform = ssh_connection.send_command('show cdp ne int '+localPort+' de | inc Platform:')

    
    return platform

def askLldpNeighPlatformOfInterface(ssh_connection,localInt):
    platform = ssh_connection.send_command('show lldp ne int '+localInt+' de | inc System description')
    platform = platform.replace('  System description                : ','Platform: ')
    return platform

def formatLabelString(ip,hostname,platform):
    return ip+" "+hostname+" "+platform

def depth_first_traversal(shapedTree):
    for child in shapedTree.children:

        ip=child.tree.value.ip
        hostname= child.tree.value.hostname
        platform= child.tree.value.platform
        if("Ruijie" in platform):
            platform = "Ruijie"

        ip = ''.join(ip.split())
        hostname = ''.join(hostname.split())
        platform = ''.join(platform.split())
        pList.write(ip+" "+hostname+" "+platform+'\n')
        if(child.tree.value.isSDWan == True):
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#00E8FF;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        elif(child.tree.value.authenticationCheck is False):
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#FF0000;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        elif(child.tree.value.timeoutCheck is False):
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#9E4712;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        elif(child.tree.value.ipValueCheck is False):
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#CFD0CF;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        elif(child.tree.value.readTimeoutCheck is False):
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#3E0D93;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        else:
            diagram.add_node(id=child.tree.value.id, x_pos=child.x*x_scale_value, y_pos=child.y*y_scale_value, label=formatLabelString(ip,hostname,platform),style="fillColor=#00FF17;fontStyle=1;whiteSpace=wrap;",width=200,height=100)
        for i in shapedTree.tree.value.intList:
            if(i.remoteIp == child.tree.value.ip and i.remoteHostname == child.tree.value.hostname and i.remotePlatform == child.tree.value.platform):
                diagram.add_link(shapedTree.tree.value.id, child.tree.value.id, label="DF", src_label=i.localPort, trgt_label=i.remotePort)
        depth_first_traversal(child),


def formatIPForCDP(ip):
    if(ip == ''):
        return ''
    else:
        ip = ip.replace('  IP address: ','')
        myList = ip.splitlines()
        myList = list (sorted(set(myList), key=myList.index))
        return myList[0]
    

def formatIPForCDPNexus(ip):
    if(ip == ''):
        return ''
    else:
        ip = ip.replace('    IPv4 Address: ','')
        myList = ip.splitlines()
        myList = list (sorted(set(myList), key=myList.index))
        return myList[0]

def formatIPForLLDP(ip):
    if(ip == ''):
        return ''
    else:
        ip = ip.replace('  Management address                : ','')
        myList = ip.splitlines()
        myList = list (sorted(set(myList), key=myList.index))
        return myList[0]

def formatHostnameForCDP(hostname):
    hostname =''.join(hostname.split())
    hostname = hostname.replace('DeviceID:','')
    myList = hostname.splitlines()
    myList = list (sorted(set(myList), key=myList.index))
    return myList[0]

def formatHostnameForLLDP(hostname):
    hostname = hostname.replace('  System name                       : ','')
    if(hostname == ''):
        return ''
    else:
        myList = hostname.splitlines()
        myList = list (sorted(set(myList), key=myList.index))
        return myList[0]

def askIPIntBriefForCDP(ssh_connection):
    ipIntBr = ssh_connection.send_command('show ip int brief | inc Vlan')
    if(ipIntBr == ''):
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
            
        
        if(tryToFind is True):
            vlanIp = vlanIp[indexOfIp:indexOfIp+15]
            vlanIp =''.join(vlanIp.split())
            
            old_ip_list.append(vlanIp)
    return old_ip_list
    
def askIPIntBriefForLLDP(ssh_connection):
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
        if(tryToFind is True):
            indexOfSlash = vlanIp.index('/')
            vlanIp = vlanIp[indexOfIp:indexOfSlash]
            
            old_ip_list.append(vlanIp)
    return old_ip_list

def askIPIntBriefForLLDPComware(ssh_connection):
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
        if(tryToFind is True):
            ip = ip[indexOfIp:indexOfIp+15]
            ip =''.join(ip.split())
            
            old_ip_list.append(ip)
    return(old_ip_list)
def formatInterfaceForCDP(interface,ssh_connection):
    intList = []
    myList = interface.splitlines()
    
    for int in myList:
        try:
            int = int.replace('Interface:','')
            int =''.join(int.split())
            i = int.index(',PortID')
            localInt = int[:i]
            k = i+len(",PortID(outgoing port):")
            remoteInt = int[k:]
            print(int)
            intList.append(Interface(localInt,remoteInt,askCdpNeighIpOfInterface(ssh_connection,localInt),askCdpNeighHostnameOfInterface(ssh_connection,localInt),askCdpNeighPlatformOfInterface(ssh_connection,localInt)))
        except ValueError:
            print("pass")
            print(int)
    return intList
def askLldpNeighPort(ssh_connection, localInt):
    remoteInt = ssh_connection.send_command('show lldp ne int '+localInt+' de  | inc Port description')
    remoteInt = remoteInt.replace('  Port description                  : ','')
    return remoteInt

def formatInterfaceForLLDP(interface,ssh_connection):
    intList = []
    myList = interface.splitlines()
    for int in myList:
        int = int.replace('LLDP neighbor-information of port [','')
        int = int.replace(']','')
        localInt = int
        intList.append(Interface(localInt,askLldpNeighPort(ssh_connection,localInt),askLldpNeighIpOfInterface(ssh_connection,localInt),askLldpNeighHostnameOfInterface(ssh_connection,localInt),askLldpNeighPlatformOfInterface(ssh_connection,localInt)))

    return intList

def useCDP(ssh_connection,base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,isRoot,old_ip_list,readTimeoutCheck):
        interface = ssh_connection.send_command('show cdp ne de | inc Interface')
        old_ip_list.extend(askIPIntBriefForCDP(ssh_connection))
        intList = formatInterfaceForCDP(interface,ssh_connection)
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP,base_Hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck,id)
        root = TreeNode(switch)
        for x in switch.intList:
            if(x.remoteIp in old_ip_list):
                print("loop")
            else:
                root.add_child(Create_Tree(x.remoteIp,old_ip_list,x.remoteHostname,False,x.remotePlatform,isRoot))
        return root 

def returnForInvalid(base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck):
    intList = []
    id = str(uuid.uuid4())
    switch = Switch(base_IP,base_Hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck,id)
    root = TreeNode(switch)
    return root

def askLldpNeighPortComware(ssh_connection,int):
    output = ssh_connection.send_command('display lldp ne int '+int+' ver | inc Port')
    myList = output.splitlines()
    for remoteInt in myList:
        if('type' not in remoteInt and 'ID' in remoteInt and 'VLAN' not in remoteInt):
            i = remoteInt.index(':')
            remoteInt = remoteInt[i+2:]
            return remoteInt
        

    return ''

def askLldpNeighIpOfInterfaceComware(ssh_connection,int):
    output = ssh_connection.send_command('display lldp ne int '+int+' ver | inc 10')
    myList = output.splitlines()
    for ip in myList:
        if('10.' in ip):
            ip = ip[ip.index('10.'):]
            return ip
    return ''

def askLldpNeighHostnameOfInterfaceComware(ssh_connection,int):
    output = ssh_connection.send_command('display lldp ne int '+int+' ver | inc name')
    output2 = ssh_connection.send_command('display lldp ne int '+int+' ver | inc Chassis')
    myList = output.splitlines()
    myList2 = output2.splitlines()
    for hostname in myList:
        if('System name' in hostname):
            hostname = hostname[hostname.index(':')+1:]
            return hostname
    
        
    for hostname in myList2:
         if('Chassis ID' in hostname):
            hostname = hostname[hostname.index(':')+1:]
            return hostname

    return ''

def askLldpNeighPlatformOfInterfaceComware(ssh_connection,int):
    output = ssh_connection.send_command('display lldp ne int '+int+' ver | inc description')
    output2 = ssh_connection.send_command('display lldp ne int '+int+' ver | inc Platform')
    myList = output.splitlines()
    myList2 = output2.splitlines()
    for platform in myList:
        if('System description' in platform):
            platform = platform[platform.index(':')+1:]
            return platform
    for platform in myList2:
         if('Platform version' in platform):
            platform = platform[platform.index(':')+1:]
            return platform
         

    return ''

def formatInterfaceForComware(localPorts,ssh_connection):
        intList = []
        myList = localPorts.splitlines()
        for int in myList:
            int = re.findall(r'\[.*?\]', int)
            if(int):
                int = int[0]
                int = int.replace('[','')
                int = int.replace(']','')
                intList.append(Interface(int,askLldpNeighPortComware(ssh_connection,int),askLldpNeighIpOfInterfaceComware(ssh_connection,int),askLldpNeighHostnameOfInterfaceComware(ssh_connection,int),askLldpNeighPlatformOfInterfaceComware(ssh_connection,int)))
        

        return intList 

def askLldpNeighPortProcurve(ssh_connection,int):
    output = ssh_connection.send_command('show lldp info rem '+int+' | inc PortId')
    myList = output.splitlines()
    for remoteInt in myList:
        i = remoteInt.index(':')
        remoteInt = remoteInt[i+2:]
        return remoteInt
        

    return ''
def askLldpNeighIpOfInterfaceProcurve(ssh_connection,int):
    output = ssh_connection.send_command('show lldp info rem '+int+' | inc Address :')
    myList = output.splitlines()
    for ip in myList:
        if('10.' in ip):
            ip = ip[ip.index('10.'):]
            return ip
    return ''

def askLldpNeighHostnameOfInterfaceProcurve(ssh_connection,int):
    output = ssh_connection.send_command('show lldp info rem '+int+' | inc SysName')
    myList = output.splitlines()
    for SysName in myList:
        if('SysName' in SysName):
            SysName = SysName[SysName.index(':')+1:]
            return SysName

    return ''

def askLldpNeighPlatformOfInterfaceProcurve(ssh_connection,int):
    output = ssh_connection.send_command('show lldp info rem '+int+' | inc Descr :')
    myList = output.splitlines()
    for platform in myList:
        if('System Descr' in platform):
            platform = platform[platform.index(':')+1:]
            return platform

    return ''


def formatInterfaceForProcurve(localPorts,ssh_connection):
    intList = []
    myList = localPorts.splitlines()
    for int in myList:
        int = int[int.index(':')+1:]
        intList.append(Interface(int,askLldpNeighPortProcurve(ssh_connection,int),askLldpNeighIpOfInterfaceProcurve(ssh_connection,int),askLldpNeighHostnameOfInterfaceProcurve(ssh_connection,int),askLldpNeighPlatformOfInterfaceProcurve(ssh_connection,int)))
    

    return intList 

def askIPIntBriefForLLDPProcurve(ssh_connection):
    ipIntBr = ssh_connection.send_command('show ip | inc 10')
    ipIntBr2 = ssh_connection.send_command('show ip | inc 172')
    myList = ipIntBr.splitlines()
    myList2 = ipIntBr2.splitlines()
    old_ip_list = []
    for ip in myList:
        if('Default Gateway' not in ip):
            tryToFind = True
            try:
                indexOfIp = ip.index('10.')
            except ValueError:
                tryToFind = False
            if(tryToFind is True):
                ip = ip[indexOfIp:indexOfIp+15]
                ip =''.join(ip.split())
                
                old_ip_list.append(ip)

    for ip in myList2:
        if('Default Gateway' not in ip):
            tryToFind = True
            try:
                indexOfIp = ip.index('172.')
            except ValueError:
                tryToFind = False
            if(tryToFind is True):
                ip = ip[indexOfIp:indexOfIp+15]
                ip =''.join(ip.split())
                
                old_ip_list.append(ip)
    return(old_ip_list)

def useLLDP(ssh_connection,base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,isRoot,old_ip_list,readTimeoutCheck,isComware,isProcurve):
    if(isComware is True):
        localPorts = ssh_connection.send_command('display lldp local | inc local-information')
        intList = formatInterfaceForComware(localPorts,ssh_connection)
        old_ip_list.extend(askIPIntBriefForLLDPComware(ssh_connection))
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        print("MY IP IS: "+base_IP+" MY HOSTNAME IS: "+base_Hostname)
        print("THESE ARE MY CHILDREN:")
        
                
        switch = Switch(base_IP,base_Hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck,id)
        root = TreeNode(switch)
        for x in switch.intList:
            if(x.remoteIp not in old_ip_list):
                print("CHILD \n")
                print("CHILD IP : "+x.remoteIp+"\n")
                print("CHILD HOSTNAME : "+x.remoteHostname+"\n")
                print("CHILD PLATFORM : "+x.remotePlatform+"\n")

        
        for x in switch.intList:
            if(x.remoteIp in old_ip_list):
                print("loop")
            elif(x.remoteIp.isspace() is not True and x.remoteIp != ""):
                root.add_child(Create_Tree(x.remoteIp,old_ip_list,x.remoteHostname,False,x.remotePlatform,isRoot))
        return root 
    elif(isProcurve is True):
        localPorts = ssh_connection.send_command('show lldp info rem all | inc Local Port')
        intList = formatInterfaceForProcurve(localPorts,ssh_connection)
        old_ip_list.extend(askIPIntBriefForLLDPProcurve(ssh_connection))
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP,base_Hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck,id)
        root = TreeNode(switch)
        for x in switch.intList:
            if(x.remoteIp not in old_ip_list):
                print("CHILD \n")
                print("CHILD IP : "+x.remoteIp+"\n")
                print("CHILD HOSTNAME : "+x.remoteHostname+"\n")
                print("CHILD PLATFORM : "+x.remotePlatform+"\n")
        for x in switch.intList:
            if(x.remoteIp in old_ip_list):
                print("loop")
            elif(x.remoteIp.isspace() is not True and x.remoteIp != ""):
                root.add_child(Create_Tree(x.remoteIp,old_ip_list,x.remoteHostname,False,x.remotePlatform,isRoot))
        return root 
    else:
        interface = ssh_connection.send_command('sh lldp ne de | inc LLDP neighbor-information of port')
        old_ip_list.extend(askIPIntBriefForLLDP(ssh_connection))
        intList = formatInterfaceForLLDP(interface,ssh_connection)   
        ssh_connection.disconnect()
        id = str(uuid.uuid4())
        switch = Switch(base_IP,base_Hostname,intList,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck,id)
        root = TreeNode(switch)
        for x in switch.intList:
            if(x.remoteIp in old_ip_list):
                print("loop")
            else:
                root.add_child(Create_Tree(x.remoteIp,old_ip_list,x.remoteHostname,False,x.remotePlatform,isRoot))
        return root 

def trySSH(base_IP):
    for account in accountListSSH:
            account2 = dict(account, **{'ip': base_IP})
            account2.pop('name')
            try:
                ssh_connection = ConnectHandler(**account2)
                return ssh_connection
            except NetMikoTimeoutException:
                print("Couldn't connect to ip "+base_IP+" Reason: Timeout. Trying telnet")
                return tryTelnet(base_IP)
            except NetMikoAuthenticationException:
                if(account == accountListSSH[-1]):
                    print("Couldn't connect to ip "+base_IP+" with account "+account2['username']+" Reason: Authentication Failed. No more try.")
                    raise NetMikoAuthenticationException
                else:
                    print("Couldn't connect to ip "+base_IP+" with account "+account2['username']+" Reason: Authentication Failed. Trying again.")
            except ValueError:
                print("SSH Couldn't connect to ip "+base_IP+" Reason: IP syntax is incorrect or not exist")
                raise ValueError
            except netmiko.exceptions.ReadTimeout:
                try:
                    account2['device_type'] = 'hp_procurve'
                    ssh_connection = ConnectHandler(**account2)
                    return ssh_connection
                except netmiko.exceptions.ReadTimeout:
                    print('INVALID DEVICE')


def tryTelnet(base_IP):
    for account in accountListTELNET:
        account2 = dict(account, **{'ip': base_IP})
        account2.pop('name')
        try:
            telnet_connection = ConnectHandler(**account2)
            return telnet_connection
        except NetMikoTimeoutException:
                print("Couldn't connect to ip "+base_IP+" Reason: Timeout.")
                raise NetMikoTimeoutException
        except NetMikoAuthenticationException:
                if(account == accountListTELNET[-1]):
                    print("Couldn't connect to ip "+base_IP+" with account "+account2['username']+" Reason: Authentication Failed. No more try.")
                    raise NetMikoAuthenticationException
                else:
                    print("Couldn't connect to ip "+base_IP+" with account "+account2['username']+" Reason: Authentication Failed. Trying again.")
        except ValueError:
                print("TElnet Couldn't connect to ip "+base_IP+" Reason: IP syntax is incorrect or not exist")
                raise ValueError

def Create_Tree(base_IP, old_ip_list,base_Hostname,isSDWan,base_Platform,isRoot):
    if("ECXS" in base_Platform or "Rev B" in base_Platform):
        isSDWan = True
    else:
        isSDWan = False
    
    print("Trying to connect to "+base_IP)
    
    
    timeoutCheck = True
    authenticationCheck = True
    ipValueCheck = True
    readTimeoutCheck = True
    isProcurve = False
    isComware = False
    if(base_IP == '127.0.0.1'):
        timeoutCheck = False
    else:
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
            return returnForInvalid(base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck)
        except paramiko.ssh_exception.SSHException:
            print("Invalid Device")
            readTimeoutCheck = False
            return returnForInvalid(base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck)
        
    if(authenticationCheck is True and timeoutCheck is True and ipValueCheck is True and isSDWan is False and readTimeoutCheck is True):
        try:
            deviceTypeCheck = ssh_connection.send_command('show ver')
            if('invalid' in deviceTypeCheck.lower() or 'unrecognized' in deviceTypeCheck.lower()):
                deviceTypeCheck = 'HPComware'
                isComware = True
                cdpORlldp = 1
            else:
                isComware = False
                deviceTypeCheck = ssh_connection.send_command('display clock')
                if('invalid' in deviceTypeCheck.lower() or 'unrecognized' in deviceTypeCheck.lower()):
                    isProcurve = False
                    cdpORlldp = 0
                    print('Ciscos')
                else:
                    isProcurve = True
                    cdpORlldp = 1
        except netmiko.exceptions.ReadTimeout:
            readTimeoutCheck = False
            return returnForInvalid(base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck)
        



        if(selectMethod == '1'):
            cdpORlldp = 0
        elif(selectMethod == '2'):
            cdpORlldp = 1


        if(cdpORlldp == 0):
            return useCDP(ssh_connection,base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,isRoot,old_ip_list,readTimeoutCheck)
        elif(cdpORlldp ==1):
            return useLLDP(ssh_connection,base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,isRoot,old_ip_list,readTimeoutCheck,isComware,isProcurve)
    else:
        return returnForInvalid(base_IP,base_Hostname,authenticationCheck,timeoutCheck,ipValueCheck,isSDWan,base_Platform,readTimeoutCheck)
    
    
        
    
selectMethod = input('Sadece CDP kullanimi icin 1, sadece LLDP kullanimi icin 2, ikisinin de kullanimi icin herhangi bir tusa basin(Cisco cihazlarda CDP non-Cisco cihazlarda LLDP calistirilir):')
tacacsUsername = input('Tacacs auth icin kullanilacak username girin:\n')
tacacsPassword = getpass(tacacsUsername+' kullanicisi icin password girin:\n')
accountListSSH.append({
            'name': tacacsUsername,
            'port': 22,
            'username': tacacsUsername,
            'password': tacacsPassword,
            'device_type': 'cisco_ios',
            'verbose': True})
print('Kayitli hesap listesi:\n')
for x in accountListSSH:
    print(str(accountListSSH.index(x))+': '+x['name'])

newAccoutSelection = input('Kayitli hesaplara ek olarak yeni bir hesap eklemek icin 1 girin:\n')

while(newAccoutSelection == '1'):
    newAccountUsername = input('Yeni eklenecek hesap icin username girin:\n')
    newAccountPassword = getpass(newAccountUsername+' kullanicisi icin password girin:\n')
    accountListSSH.append({
            'name': newAccountUsername,
            'port': 22,
            'username': newAccountUsername,
            'password': newAccountPassword,
            'device_type': 'cisco_ios',
            'verbose': True})
    print('Guncel hesap listesi:\n')
    for x in accountListSSH:
        print(str(accountListSSH.index(x))+': '+x['name'])
    newAccoutSelection = input('Yeni hesap eklemeye devam etmek icin 1 girin')


orderSelection = input('Uygulama bir cihaza bağlanirken sirayla bu hesaplar ile giris yapmayi deneyecektir. Sirada ilk olan hesap en once denenir. Hesap sirasini değistirmek icin 1 girin:\n')



while(orderSelection == '1'):
    selectedAccount1 = input('Sirasini degistirmek istediğiniz hesabin indexini girin:')
    selectedAccount2 = input('Hesabi yerlestirmek istediginiz indexi girin:')
    copyValue = accountListSSH[int(selectedAccount2)]
    accountListSSH[int(selectedAccount2)] = accountListSSH[int(selectedAccount1)]
    accountListSSH[int(selectedAccount1)] = copyValue
    print('Guncel hesap listesi:\n')
    for x in accountListSSH:
        print(str(accountListSSH.index(x))+': '+x['name'])
    orderSelection = input('Sira degistirmeye devam etmek icin 1, cikis yapmak icin 2 girin:')


old_ip_list = []
root_ip = input('Backbone IPsini girin. Tree cizimi bu cihaz etrafinda sekillenecektir:\n')
root_hostname = 'BB'





mytree = Create_Tree(root_ip,old_ip_list,root_hostname,isSDWan=False,base_Platform="Backbone",isRoot=True) #Cihazlarla tree yapısı yarat


shapedTree = buchheim(mytree) #Nodeları buchheim algoritmasıyla pozisyonla


diagram.add_node(id="authFail", x_pos=shapedTree.x*x_scale_value, y_pos=-0.25*y_scale_value, label="Authentication Hatasi",style="fillColor=#FF0000;whiteSpace=wrap;fontStyle=1")        
diagram.add_node(id="timeout", x_pos=shapedTree.x*x_scale_value, y_pos=-0.5*y_scale_value, label="Timeout",style="fillColor=#9E4712;whiteSpace=wrap;fontStyle=1")      
diagram.add_node(id="ipSyntax", x_pos=shapedTree.x*x_scale_value, y_pos=-0.75*y_scale_value, label="Cihaz mevcut ancak bir IP paylasmiyor.",style="fillColor=#CFD0CF;whiteSpace=wrap;fontStyle=1")   
diagram.add_node(id="sdwan", x_pos=shapedTree.x*x_scale_value, y_pos=-1.0*y_scale_value, label="SDWan.",style="fillColor=#00E8FF;whiteSpace=wrap;fontStyle=1")   
diagram.add_node(id="deviceSyntax", x_pos=shapedTree.x*x_scale_value, y_pos=-1.25*y_scale_value, label="Aygitin konsol syntax'i farkli",style="fillColor=#3E0D93;fontStyle=1;whiteSpace=wrap;")

print(shapedTree.tree.value.hostname+'\n')
print(shapedTree.tree.value.ip+'\n')
print(shapedTree.tree.value.platform+'\n')


#Rootu çiz
if(shapedTree.tree.value.authenticationCheck is False):
    diagram.add_node(id=shapedTree.tree.value.id, x_pos=shapedTree.x*x_scale_value, y_pos=shapedTree.y*y_scale_value, label=shapedTree.tree.value.hostname+" "+shapedTree.tree.value.ip+" "+shapedTree.tree.value.platform,style="fillColor=#FF0000;whiteSpace=wrap;fontStyle=1")        
elif(shapedTree.tree.value.timeoutCheck is False):
    diagram.add_node(id=shapedTree.tree.value.id, x_pos=shapedTree.x*x_scale_value, y_pos=shapedTree.y*y_scale_value, label=shapedTree.tree.value.hostname+" "+shapedTree.tree.value.ip+" "+shapedTree.tree.value.platform,style="fillColor=#9E4712;whiteSpace=wrap;fontStyle=1")
elif(shapedTree.tree.value.ipValueCheck is False):
    diagram.add_node(id=shapedTree.tree.value.id, x_pos=shapedTree.x*x_scale_value, y_pos=shapedTree.y*y_scale_value, label=shapedTree.tree.value.hostname+" "+shapedTree.tree.value.ip+" "+shapedTree.tree.value.platform,style="fillColor=#CFD0CF;whiteSpace=wrap;fontStyle=1")
elif(shapedTree.tree.value.readTimeoutCheck is False):
    diagram.add_node(id=shapedTree.tree.value.id, x_pos=shapedTree.x*x_scale_value, y_pos=shapedTree.y*y_scale_value, label=shapedTree.tree.value.hostname+" "+shapedTree.tree.value.ip+" "+shapedTree.tree.value.platform,style="fillColor=#3E0D93;whiteSpace=wrap;fontStyle=1")
else:
    diagram.add_node(id=shapedTree.tree.value.id, x_pos=shapedTree.x*x_scale_value, y_pos=shapedTree.y*y_scale_value, label=shapedTree.tree.value.hostname+" "+shapedTree.tree.value.ip+" "+shapedTree.tree.value.platform,style="fillColor=#00FF17;whiteSpace=wrap;fontStyle=1")
pList = open("platformList"+str(root_ip)+".txt", "a")
depth_first_traversal(shapedTree) #Treenin çocuklarını traverse ederek çiz

diagram.dump_file(filename=str(root_ip)+" Topology", folder="./Output/") #Çizimin ismi ve atılacağı yer
