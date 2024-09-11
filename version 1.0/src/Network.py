"""
This module contains network object and relevant functions.

@author: Mengmeng Ge
"""
import copy

from Node import *

class network(object):
    """
    Create network object.
    """
    def __init__(self):
        #Initialize node list
        self.nodes = []
        #Initialize start and end points
        self.s = None
        self.e = None
        #Initialize subnets which contain each node's subnet
        self.subnets = []
        #Initialize vulnerability list which contains all node vulnerabilities
        self.vuls = []
        #Store the maximum depth
        self.max_depth = 0
        #Store the maximum hop
        self.max_hop = 0

        #added by KO Chee
        #initialize attacker and target
        self.atk = []
        self.tgt = []
        self.defMode = {}
        self.AtkerTimeDataDict = {}
        self.saveSimDir = ""
        self.saveFolder = ""
        self.entryPointNode = []

def copyNet(net):
    """
    Copy the network to a network.
    """
    
    temp = network()
    temp = copy.deepcopy(net)
    
    return temp
          
def connectOneWay(node1, node2):
    """
    Connect node1 to node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #connect node1 to node2
    if (node2 not in node1.con):
        node1.con.append(node2)    

def connectTwoWays(node1, node2):
    """
    Connect node1 with node2 in the network.
    """
    #no self connection
    if node1 is node2:
        return None
    #create connections
    if (node2 not in node1.con):
        node1.con.append(node2)
    if (node1 not in node2.con):
        node2.con.append(node1)

def removeNodeFromList(node, con_list):
    """
    Remove node from the original connection list
    """
    for i in con_list:
        if i.name == node.name:
            con_list.remove(i)
            break
    return None

def disconnectOneWay(node1, node2):
    """
    Disconnect node1 with node2 in the network
    """
    names = [i.name for i in node1.con]
    if node2.name in names:
        #print(node2.name, names)
        removeNodeFromList(node2, node1.con)
    return None

def disconnectTwoWays(node1, node2):
    """
    Disconnect node1 and node2 in the network.
    """
    if node2 in node1.con:
        node1.con.remove(node2)   
    if node1 in node2.con:
        node2.con.remove(node1)  
        
