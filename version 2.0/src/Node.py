"""
This module contains node objects
"""

from operator import attrgetter
from random import *
from math import *


class node(object):
    """
    Create basic node object.
    """
    
    def __init__(self, name):
        self.name = name
        #Set connections        
        self.con = []
        #Store lower layer info     
        self.child = None
        #Set default value of start/end
        self.isStart = False
        self.isEnd = False
        #self.vul = None
        #self.type = None
        self.subnet = []

        #added by KO Chee
        #status of the node: True = healthy; False = Infected
        self.healthy = True
        #Indicate whether the node is ready to become an attacker to propagate or not
        self.propagation = False
        #status of the port: True = Open; False = Close
        self.port = True
        #Carrying exploit
        self.carryExploit = []
        #Carrying credentials
        self.carryCredential = []
        #set default value for attacker
        self.isAttacker = False
        #set default value for target
        self.isTarget = False
        self.id = None
        self.vul = None
        self.timeline = []
        self.nextTargetNode = []
        self.mode = None
        self.CNCNode = []
        self.scanTime = 0
        self.accessTime = 0
        self.reportTime = 0
        self.infectionTime = 0
        self.accumulatedTime = 0
        self.log = []
        self.meanTime = 0
        self.targetPort = []
        self.compromisedPort = []
        self.realPort = {}
        self.scanPort = []
        self.scanMethod = None
        self.IPv4Add = ""
        self.protocol = None
        self.content = []
        self.position = []
        self.canBeCompromised = True

        self.loginUsername = ""
        self.loginPassword = ""
        self.exploitType = []
        self.credentialPort = []
        self.propagationType = None

        self.resourceMeterAll = 100
        self.resourceMeterCurrent = 0
        self.resourceMeterBreakLimit = 95
        self.resourceConsumptionNLimit = []
        self.resourceConsume = 0
        
        self.filelist = []
        self.folderlist = []
        self.cronFolder = []
        self.initFolder = []
        self.processlist = []

        self.commandFromCNC = ""
        self.commandCurrent = ""
        self.commandList = [["propagate", True, 20], ["ddos", False, 40], ["exfiltrate data", False, 10] , ["pdos", False, 100], ["cryptomining", False, 45], ["proxy server", False, 20]]
        self.botTaskList = []
        self.conditionChoice = ["enable", "disable", "rebooting", "crashed", "busy"]
        self.isRebooting = None
        self.chanceToReboot = 0
        self.respondToReboot = ["terminated", "prevent", "survive"]
        self.resideLocation = []
        self.rebootable = []
        self.conditionNow = ""

        self.killerBlackList = []
        self.fortificationList = []
        self.evasionList = []
        self.nextAction = 0
        self.botAttackList = []
        self.binaryfile = []
        
        #self.con = [] this can show the connection on a node
        self.connectionLimit = 0
        '''
        self.realPort = {
            '23' : {
                'name' : "Telnet protocol - unencrypted text communications",
                'open' : True
            },
            '80' : {
                'name' : "Hypertext Transfer Protocol (HTTP)",
                'open' : True
            },
            '8008' : {
                'name' : "Hypertext Transfer Protocol (HTTP) - Alt 1",
                'open' : True
            },
            '8080' : {
                'name' : "Hypertext Transfer Protocol (HTTP) - Alt 2",
                'open' : True
            }
        }
        '''
    #added by KO Chee
    #set the node as attacker/target
    def setAttacker(self):
        self.isAttacker = True
    def setTarget(self):
        self.isTarget = True
    def setFromTargetToAttacker(self):
        self.isTarget = False
        self.isAttacker = True
    def setIdle(self):
        self.isAttacker = False
        self.isTarget = False

    #Set the node as normal/start/end
    def setStart(self):
        self.isStart = True
    def setNormal(self):
        self.isStart = False
        self.isEnd = False
    def setEnd(self):        
        self.isEnd = True
    #Check whether the node is leaf or not
    def isLeaf(self):
        return (len(self.con) is 1)
        
class iot(node):
    def __int__(self, name):
        super(iot, self).__init__(name)
        self.vul = None
        
class computer(node):
    def __int__(self, name):
        super(computer, self).__init__(name)
        self.vul = None
        

class sensor(node):
    """
    Create sensor node object.
    """
    def __init__(self, name):
        super(sensor, self).__init__(name)
        #Initialize vulnerability network
        self.vul = None
        #Initialize subnet which defines sensor classification
        self.subnet = []
        #Heterogeneous sensor
        self.type = None
        #For tree topology
        self.height = None
        self.parent = []


class device(node):
    """
    Create smart device object.
    """
    def __init__(self, name):
        super(device, self).__init__(name)
        #Initialize vulnerability network
        self.vul = None
        self.type = None
        self.critical = None
        self.comp = None
        #Initialize subnet which defines device classification
        self.subnet = []
        #For tree topology
        self.height = None
        self.parent = []
        self.comm = []
        self.pro = None
        self.prev_comp = 0.0

class attacker(node):
    """
    Create basic attacker object.
    """
    def __init__(self, name):
        super(attacker, self).__init__(name)
        #Initialize vulnerability network
        self.vul = None
        self.type = None
        self.critical = None
        self.comp = None
        #Initialize subnet which defines device classification
        self.subnet = []
        #For tree topology
        self.height = None
        self.parent = []
        self.comm = []
        self.pro = None
        self.prev_comp = 0.0
        #added by CKO
        self.id = 999
        self.carryExploit = []
        self.carryCredential = []
        self.nextTargetNode = []
        self.CNCNode = []
        self.goal = None
        self.collude = False
        self.mode = None
        self.group = None
        self.botCollude = False
        self.cycle = 0
        self.active = False
        self.scanTime = 0
        self.accessTime = 0
        self.reportTime = 0
        self.infectionTime = 0
        self.accumulatedTime = 0
        self.timeline = []
        self.targetPort = []
        self.binaryName = []
        #attack status
        self.attackData = []
        self.status = 0
        self.canBeCompromised = False

        self.credentialExploitationList = []
        self.credentialExploitationWordListName = []
        self.botActionList = []

class CommandNControl(node):
    """
    Create CNC node
    """
    def __init__(self, name):
        super(CommandNControl, self).__init__(name)
        self.type = None
        self.username = None
        self.password = None
        self.targetNode = []
        self.cncAtkerList = []
        self.listofBots = []
        self.atkInfoDict = {}
        self.attackCommand = []
        self.atkMode = None
        self.content = "malware"
        self.id = 666
        self.port = False
        self.group = None
        self.timeline = []
        #credential data
        self.attackData = []
        self.status = 0
        self.goal = []
        self.binaryName = []
        self.CNCMemory = {}
        self.avoidList = {"nodeX" : {"p0" : {"num" : 0, "avoid" : False}}}
        self.canBeCompromised = False

        self.credentialExploitationList = []
        self.credentialExploitationWordListName = []
        self.botActionList = []
        self.networkDataRecord = {"nodeX" : {"port" : [], "connection" : [], "credential" : [], "processlist" : [], "filelist" : [], "folderlist" : [], "vulnerability" : [], "ipaddress" : None, "resourceLevel" : 0, "condition" : None, "anySpecialData" : None}}

class Server(node):
    """
    Create server node for DDoS attack modelling
    """
    def __init__(self, name):
        super(Server, self).__init__(name)
        self.type = None
        self.username = None
        self.password = None
        self.buffer = 100
        self.bufferCurrent = 0
        self.resource = 100
        self.connectionList = []
        self.defendCommand = []
        self.content = "ddos target"
        self.id = 888 
        self.port = False
        self.timeline = []
        self.status = 0
        self.banList = []
        self.canBeCompromised = False

class sdSensor(node):
    """
    Create a software-defined sensor node object.
    """
    def __init__(self, name):
        super(sdSensor, self).__init__(name)
        #Initialize vulnerability network
        self.vul = None
        #Initialize subnet which defines sensor classification
        self.subnet = []
        #Heterogeneous sensor
        self.type = None
        #For tree topology, store parent and children of the node
        self.parent = []
        self.childcon = []
        #Depth of the node based on the distance
        self.depth = None
        #Initial number of hops to the root
        self.inihop = -1
        #Number of hops to the root
        self.hop = -1
        #Coordinates which define the location of the nodes and will be used for limiting the wireless transmission range
        self.coordinates = None
        #Tier of the node from the root in the coordinates, used for setting up coordinates (real distance)
        self.tier = None
        #Temporary radius value used for new connections (distance)
        self.radius = None
        #Indicate the security state of a node: vulnerable as v, compromised as c, detected as d, patched as p, isolated as i
        self.sec = 'v'
        #Specify a value used for maximum sum optimization
        #0: for non-patchable in case 3 or easy-to-exploit in case 2
        #1: for patchable in case 3 or hard-to-exploit in case 2
        self.typev = 0
        #Indicate whether the node is reconfigured or not
        #0: not reconfigured
        #1: reconfigured
        self.reconfig = 0
        #Indicate the maximum sum
        self.sum = 0
        #Indicate the child nodes coming from the maximum sum
        self.chlist = [] 
        #Indicate the parent nodes coming from the maximum sum
        self.plist = []
        #Define label for each node
        self.label = 1

class realNode(node):
    #Create a real node in the network
    def __init__(self, name):
        super(realNode, self).__init__(name)
        self.vul = None
        #Indicate real device
        self.type = True
        #Indicate node number
        self.id = None
        #Represent the metric value
        self.val = []
        #Indicate whether node is critical or not
        self.critical = False
        #Represent whether the node is compromised or not
        self.comp = False
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = 1.0
        #Record previous compromise time
        self.prev_comp = 0.0
        
        #added by KO Chee
        #status of the node: True = healthy; False = Infected
        self.healthy = True
        #Indicate whether the node is ready to become an attacker to propagate or not
        self.propagation = False
        #status of the port: True = Open; False = Close
        self.port = True # old -> realPort
        """
        can introduce multiple ports on a device to birng in the competition between botnets
        
        self.port80 = True
        self.port33 = True
        """

        #hop value
        self.hopValue = None
        #is compromised by
        self.isCompBy = None
        #group info
        self.group = None
        #bot cooperation status
        self.botCollude = False
        #attack status
        self.attackData = []
        #stage status
        self.status = 0
        self.collude = False
        self.lastAP = None
        self.decoy = False
        self.model = None

        #can add more realistic option here to indicate malicious process run by other/enermy malware
        
class routerNode(node):
    #Create a real node in the network
    def __init__(self, name):
        super(routerNode, self).__init__(name)
        self.vul = None
        #Indicate real device
        self.type = True
        #Indicate node number
        self.id = None
        #Represent the metric value
        self.val = []
        #Indicate whether node is critical or not
        self.critical = False
        #Represent whether the node is compromised or not
        self.comp = False
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = 1.0
        #Record previous compromise time
        self.prev_comp = 0.0
        
        #added by KO Chee
        #status of the node: True = healthy; False = Infected
        self.healthy = True
        #Indicate whether the node is ready to become an attacker to propagate or not
        self.propagation = False
        #status of the port: True = Open; False = Close
        self.port = True # old -> realPort
        """
        can introduce multiple ports on a device to birng in the competition between botnets
        
        self.port80 = True
        self.port33 = True
        """

        #hop value
        self.hopValue = None
        #is compromised by
        self.isCompBy = None
        #group info
        self.group = None
        #bot cooperation status
        self.botCollude = False
        #attack status
        self.attackData = []
        #stage status
        self.status = 0
        self.collude = False
        self.fwRules = None

        #can add more realistic option here to indicate malicious process run by other/enermy malware
        

class decoyNode(node):
    #Create a decoy node in the network
    def __init__(self, name):
        super(decoyNode, self).__init__(name)
        self.vul = None
        #Indicate decoy device (emulated or real OS based)
        self.type = False
        #Represent the metric value
        self.val = []
        #Indicate node number
        self.id = -1
        #Indicate whether node is critical or not
        self.critical = None
        #Represent whether the node is compromised or not
        self.comp = False
        #Indicate the probability of the attacker to proceed using the decoy
        self.pro = None
        #Record previous comprmoise time
        self.prev_comp = 0.0

        #added by KO Chee
        #status of the node: True = healthy; False = Infected
        self.healthy = True
        #Indicate whether the node is ready to become an attacker to propagate or not
        self.propagation = False
        #status of the port: True = Open; False = Close
        self.port = True

        # added by KO Chee
        #hop value
        self.hopValue = None
        #is compromised by
        self.isCompBy = None
        #group info
        self.group = None
        #bot cooperation status
        self.botCollude = False
        #attack status
        self.attackData = []
        #stage status
        self.status = 0
        self.collude = False
        self.dataCollection = []
        self.model = None

class binaryFile(node):
    #Create a binary File in the device node
    def __init__(self, name):
        super(binaryFile, self).__init__(name)
        self.filesize = 0
        self.resourceConsume = 0

class intelligenceCenter(node):
    #Create 
    def __init__(self, name):
        super(intelligenceCenter, self).__init__(name)
        self.configuration = []
        # [which node, node num, [binary file names], time to check, [response]]
        # = [['all', 50, ['mirai', 'carna', 'hns', 'hajime'], 2s, ['reset', 'update']], 
        # ['lightbulb', 5, ['mirai', 'carna'], 5s, ['reset', 'update']]]
        self.response = None
        self.update = []
        self.decoyrecord = []

class processFile(node):
    #Create 
    def __init__(self, name):
        super(processFile, self).__init__(name)
        self.filesize = 0
        self.resourceConsume = 0
        
class sdnSwitch(node):
    #Create 
    def __init__(self, name):
        super(sdnSwitch, self).__init__(name)
        self.shufflelist = []
        self.nodenum = 0
        self.isolationlist = []
        self.shuffletime = 0

def generatePointsOnDepth(net, depth):
    """
    Generate a list of nodes based on the depth of the target node: nodes with the same depth and nodes with depth - 1, depth + 1.
    """
    list = []
    
    for node in net.nodes:
        if node.depth == depth or node.depth == depth - 1 or node.depth == depth + 1:
            list.append(node)
    
    return list

def generateNodesOnHop(net, hop):
    """
    Generate a list of nodes based on the hop of the target node.
    """
    list = []
    
    for node in net.nodes:
        if node.hop == hop:
            list.append(node)
    
    return list

def removeExistingConNode(list, temp):
    """
    Remove nodes with existing connections.
    """
    
    for node in list:
        if node == temp:
            list.pop(list.index(node))
            
    return list


def checkParent(node):
    """
    There is one parent.
    Check whether there is a path from the node to the root or not.
    """

    if len(node.parent) == 0: #the new connection's parent is the node
        #print(-1, node.name, len(node.parent))
        return -1
    elif node.parent[0].depth == 0:
        #print(0, node.parent[0].name)
        return 0
    else:
        return(checkParent(node.parent[0]))


def checkParentWithNodes(node, temp):
    """
    Check whether the parent of the node is root or not.
    """
    d = 0
    if len(node.parent) == 0:
        d = -1
    elif node.parent[0].depth == 0: 
        temp.append(node.parent[0])
        d = 0
    else:
        temp.append(node.parent[0])
        d, temp = checkParentWithNodes(node.parent[0], temp)

    return d, temp

def getParentNodes(node, temp):
    """
    Get all nodes along the path to root.
    """

    if node.parent[0].depth > 0:
        temp.append(node.parent[0])
        temp = getParentNodes(node.parent[0], temp)
    elif node.parent[0].depth == 0: 
        temp.append(node.parent[0])

    return temp

def calcNodeHopsToRoot(node, i):
    """
    Calculate the number of hops from the node to the root.
    """
    if len(node.parent) == 0:
        return -1
    elif node.parent[0].hop == 0:
        return i
    else:
        i += 1
        return calcNodeHopsToRoot(node.parent[0], i)


def checkChildHop(node, hop):
    """
    Check the number of hops of every node in the path to the leaf node.
    Find the maximum hop change.
    If any node has increased number of hops exceeding the reconfiguration limitation, reconfiguration cannot happen.
    """

    max_hop = hop - node.inihop
    
    if len(node.childcon) != 0:
        for child in node.childcon:
            max_hop_child = checkChildHop(child, hop + 1)
            if max_hop_child > max_hop:
                max_hop = max_hop_child

    return max_hop

    
def changeChildHop(node):
    """
    Change the number of hops of the node's children.
    """

    if len(node.childcon) != 0:
        for child in node.childcon:
            child.hop = node.hop + 1
            #print(child.name, child.hop)
            changeChildHop(child)

    return 1

def checkNodeSec(node, sec1, sec2):
    """
    Check the security state of a node.
    """
    
    if node.sec == sec1 or node.sec == sec2:
        return 1
    
    return 0

def chooseRandomNodes(list, cov):
    """
    Choose nodes from a list based on the coverage.
    """
    
    num = int(round(len(list)*cov))
    
    temp = []
    
    #Generate a list of random indices within range    
    index = sample(range(0, len(list)), num)
    
    for node in list:
        for i in index:
            if  list.index(node) == i:
                temp.append(node)
                
    return temp

def chooseNodesType(list, type):
    """
    Choose nodes from a list based on the type of the node.
    """
    temp = []
    
    for node in list:
        #print(node.type)
        if node.type == type:
            temp.append(node)
                
    return temp

def chooseNodesSec(net, list, sec_list):
    """
    Choose nodes from a list based on the security state of the nodes.
    """
    temp = []
    
    for node in net.nodes:
        for name in list:
            if node.name == name:
                #print(node.name, node.sec)
                for s in sec_list:
                    if node.sec == s:
                        temp.append(node)
                        #Get out of the inner loop
                        break
                #Get out of the middle loop
                break
    
    return temp

def chooseNodesInList(net, list):
    """
    Choose nodes from a list.
    """
    temp = []
    
    for node in net.nodes:
        for name in list:
            if node.name == name:
                temp.append(node)
                break
    
    return temp

def chooseNodesInNodeList(net, list):
    """
    Choose nodes from a list.
    """
    temp = []
    
    for node1 in list:
        for node2 in net.nodes:
            if node1.name == node2.name:
                temp.append(node2)
                break
    
    return temp

def checkNodeInCons(node1, node2):
    """
    Check whether the node1 is in the connections of node2.
    """
    for temp in node2.con:
        if node1.name == temp.name:
            return 1
    
    return 0

def checkNodeInList(node, list):
    """
    Check whether the node is in the list or not.
    """
    for temp in list:
        if node.name == temp.name:
            return True 
        
    return False

def checkNodeSecNotInList(temp, sec_list):
    """
    Check the security states of all nodes in a list.
    :returns False, there is at least one compromised node along the path; True, no compromised nodes along the path
    """
    for node in temp:
        for s in sec_list:
            if node.sec == s:
                return False    
    
    return True

def printList(list):
    """
    Print a node's name
    """
    for node in list:
        if len(node.parent) > 0: 
            print(node.name, node.parent[0])
            
def removeNodes(list, net):
    """
    Remove a node
    """
    for node1 in list:
        for node2 in net.nodes:
            if node1.name == node2.name:
                net.nodes.remove(node2)
                break
        
    return None
    