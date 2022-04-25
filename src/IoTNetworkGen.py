'''
This module constructs IoT network for IoTSecSim.

@co-authors: Kok Onn Chee, Mengmeng Ge
'''

import copy
import sys
from random import random, choice
from ipaddress import IPv4Address, IPv4Network, IPv6Address

from Node import *
from Network import *
from Vulnerability import *
from harm import *
from RandomNetworkGen import *
from Port import *
from ConventionalDefence import *
from SecurityAnalysis import *

def addRandomTopology(net, saveFolder):
    """
    Create a random graph from networkx
    """
    num = len(net.nodes)

    newListDif = [(0, 0), (750, -750), (1500, 0), (-310, 265), (-310, -265), (-310, 0), (235, -135), (235, 350), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (1085, -1240), (1085, -1430), (405, -645), (1175, 350), (1175, -110), (1850, 280), (1850, 0), (1850, -265), (-310, 510), (70, 510), (-310, -510), (70, -510), (1175, 510), (1630, 510), (1175, -510), (1630, -510), (-105, 510), (235, 510), (-105, -510), (235, -510), (235, 0), (1380, 510), (1850, 510), (1380, -510), (1850, -510), (235, 165), (895, -105), (550, -130), (1175, 170), (450, -245), (1085, -855), (975, -260), (405, -1045), (1085, -1045), (750, 0), (580, -1430)]
    j = 0
    for node in net.nodes:

        node.position = newListDif[j]
        j+=1

    data = createRandomGraph(num, saveFolder)

    for x, y in data.items():
        node1 = net.nodes[int(x)]
        for z in y:
            node2 = net.nodes[int(z)]
            connectOneWay(node1, node2)

    return None

## Create an other graph from networkx
def addDifferentTopology(net, topoType, saveFolder):
    num = len(net.nodes)
    
    deductNum = 0
    addNum = 0
    newListDif = [(0, 0), (750, -750), (1500, 0), (-310, 265), (-310, -265), (-310, 0), (235, -135), (235, 350), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (1085, -1240), (1085, -1430), (405, -645), (1175, 350), (1175, -110), (1850, 280), (1850, 0), (1850, -265), (-310, 510), (70, 510), (-310, -510), (70, -510), (1175, 510), (1630, 510), (1175, -510), (1630, -510), (-105, 510), (235, 510), (-105, -510), (235, -510), (235, 0), (1380, 510), (1850, 510), (1380, -510), (1850, -510), (235, 165), (895, -105), (550, -130), (1175, 170), (450, -245), (1085, -855), (975, -260), (405, -1045), (1085, -1045), (750, 0), (580, -1430)]
    j = 0
    for node in net.nodes:
        node.position = newListDif[j]
        j+=1

    if topoType is not None:
        data = createNetworkGraph(num, saveFolder, topoType)
    else:
        print("Topology style not found!!")

    tempNum = 0

    for x, y in data.items():
        node1 = net.nodes[int(x)]
        for z in y:
            node2 = net.nodes[int(z)]
            connectOneWay(node1, node2)
            tempNum += 1

    return None

## Create a complete graph from networkx
def addCompleteTopology(net, saveFolder):
    """
    Complete graph
    """
    num = len(net.nodes)

    newListDif = [(0, 0), (750, -750), (1500, 0), (-310, 265), (-310, -265), (-310, 0), (235, -135), (235, 350), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (1085, -1240), (1085, -1430), (405, -645), (1175, 350), (1175, -110), (1850, 280), (1850, 0), (1850, -265), (-310, 510), (70, 510), (-310, -510), (70, -510), (1175, 510), (1630, 510), (1175, -510), (1630, -510), (-105, 510), (235, 510), (-105, -510), (235, -510), (235, 0), (1380, 510), (1850, 510), (1380, -510), (1850, -510), (235, 165), (895, -105), (550, -130), (1175, 170), (450, -245), (1085, -855), (975, -260), (405, -1045), (1085, -1045), (750, 0), (580, -1430)]
    j = 0
    for node in net.nodes:

        node.position = newListDif[j]
        j+=1

    data = createCompleteGraph(num, saveFolder)

    tempNum = 0
    for x, y in data.items():
        node1 = net.nodes[int(x)]
        for z in y:
            node2 = net.nodes[int(z)]
            connectOneWay(node1, node2)
            tempNum += 1

    return None

def addDifDensityTopology2(net, degnum, saveFolder):
    #vlan 1: 1 router; 5 light bulbs; 4 printers; 5 laptops; 1 ipcamera; 0 tvs; 0 projectors;

    #vlan 2: 1 router; 9 light bulbs; 0 printers; 0 laptops; 2 ipcamera; 3 tvs; 2 projectors;

    #vlan 3: 1 router, 5 light bulbs; 4 printers; 4 laptops; 1 ipcamera; 0 tvs; 0 projectors;

    routerCanBeCompromised = False

    for x in net.nodes:
        text = x.name.split('-')
        if 'router' in text:
            if x.canBeCompromised == True:
                routerCanBeCompromised = True

    vlan1 = []
    vlan2 = []
    vlan3 = []
    vlan4 = []

    k = 0
    #square view
    #            1       2               3           4           5       6           7           8           9           10              11          12            13        14              15      16              17          18          19          20          21              22            23            24          25              26          27          28          29              30          31              32          33              34          35              36          37          38              39          40              41          42          43          44              45          46          47          48          49              50          
    newList = [(0, 0), (750, -750), (1500, 0), (235, 165), (235, 0), (235, 510), (70, 510), (70, -510), (235, -510), (-105, 510), (-310, 510), (-105, -510), (-310, -510), (235, -135), (-310, 265), (-310, -265), (235, 350), (-310, 0), (235, -305), (750, 0), (895, -105), (550, -130), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (405, -1045), (1085, -1430), (405, -645), (450, -245), (1085, -1045), (1085, -855), (1085, -1240), (580, -1430), (1020, -305), (675, -285), (1175, 170), (1175, -110), (1850, -510), (1630, -510), (1380, -510), (1175, -510), (1630, 510), (1850, 510), (1175, 510), (1380, 510), (1850, 280), (1850, 0), (1850, -265), (1175, 350), (1175, -255), (235, -265), (650, -265), (1175, 0)]

    for node in net.nodes:
        node.position = newList[k]
        k+=1

    temp1 = net.nodes.copy()

    totalEdge = degnum * len(net.nodes)
    if routerCanBeCompromised == True:
        numbers = [3, 15, 18, 14]
    else:
        numbers = [3, 16, 19, 15]
    
    for i in range(0, len(numbers)):
        temp2 = temp1.copy()
        for j in range(0, numbers[i]):
            if i == 0:
                vlan1.append(temp2[j])
            if i == 1:
                vlan2.append(temp2[j])
            if i == 2:
                vlan3.append(temp2[j])
            if i == 3:
                vlan4.append(temp2[j])
            temp1.remove(temp2[j])

    for node in vlan2:
        connectTwoWays(vlan1[0], node)

    for node in vlan3:
        connectTwoWays(vlan1[1], node)

    for node in vlan4:
        connectTwoWays(vlan1[2], node)
   
    connectTwoWays(vlan1[1], vlan1[0])
    connectTwoWays(vlan1[2], vlan1[1])

    if totalEdge > 124 and routerCanBeCompromised == True:
        connectTwoWays(vlan3[1], vlan3[0])
        connectTwoWays(vlan3[2], vlan3[0])

        connectTwoWays(vlan2[0], vlan3[0])
        connectTwoWays(vlan2[1], vlan3[0])

        connectTwoWays(vlan4[0], vlan3[0])

        connectTwoWays(vlan2[2], vlan2[3])
        connectTwoWays(vlan2[4], vlan2[5])
        connectTwoWays(vlan2[6], vlan2[7])
        connectTwoWays(vlan2[8], vlan2[9])

        connectTwoWays(vlan4[2], vlan4[3])
        connectTwoWays(vlan4[4], vlan4[5])
        connectTwoWays(vlan4[6], vlan4[7])
        connectTwoWays(vlan4[8], vlan4[9])

        if totalEdge >= 150: #+13
            connectTwoWays(vlan2[10], vlan2[11])
            connectTwoWays(vlan2[12], vlan2[13])
            connectTwoWays(vlan2[14], vlan2[10])
            
            connectTwoWays(vlan3[3], vlan3[4])
            connectTwoWays(vlan3[5], vlan3[6])
            connectTwoWays(vlan3[7], vlan3[8])
            connectTwoWays(vlan3[9], vlan3[10])
            connectTwoWays(vlan3[11], vlan3[12])
            connectTwoWays(vlan3[13], vlan3[14])
            connectTwoWays(vlan3[15], vlan3[16])
                        
            connectTwoWays(vlan4[10], vlan4[11])
            connectTwoWays(vlan4[12], vlan4[13])
            connectTwoWays(vlan4[12], vlan4[10])

            if totalEdge >= 200: #38-13 = 25
                connectTwoWays(vlan2[0], vlan2[1])
                connectTwoWays(vlan2[1], vlan2[2])
                connectTwoWays(vlan2[3], vlan2[4])
                connectTwoWays(vlan2[5], vlan2[6])
                connectTwoWays(vlan2[7], vlan2[8])
                connectTwoWays(vlan2[9], vlan2[10])
                connectTwoWays(vlan2[11], vlan2[12])
                connectTwoWays(vlan2[13], vlan2[14])

                connectTwoWays(vlan3[1], vlan3[2])
                connectTwoWays(vlan3[2], vlan3[3])
                connectTwoWays(vlan3[4], vlan3[5])
                connectTwoWays(vlan3[6], vlan3[7])
                connectTwoWays(vlan3[8], vlan3[9])
                connectTwoWays(vlan3[10], vlan3[11])
                connectTwoWays(vlan3[12], vlan3[13])
                connectTwoWays(vlan3[14], vlan3[15])
                connectTwoWays(vlan3[16], vlan3[17])

                connectTwoWays(vlan4[0], vlan4[1])
                connectTwoWays(vlan4[1], vlan4[2])
                connectTwoWays(vlan4[3], vlan4[4])
                connectTwoWays(vlan4[5], vlan4[6])
                connectTwoWays(vlan4[7], vlan4[8])
                connectTwoWays(vlan4[9], vlan4[10])
                connectTwoWays(vlan4[11], vlan4[12])
                connectTwoWays(vlan4[13], vlan4[0])

                if totalEdge >= 250: #63 - 38 = 25
                    connectTwoWays(vlan2[0], vlan2[8])
                    connectTwoWays(vlan2[1], vlan2[9])
                    connectTwoWays(vlan2[2], vlan2[10])
                    connectTwoWays(vlan2[3], vlan2[11])
                    connectTwoWays(vlan2[4], vlan2[12])
                    connectTwoWays(vlan2[5], vlan2[13])
                    connectTwoWays(vlan2[6], vlan2[14])
                    connectTwoWays(vlan2[7], vlan2[0])

                    connectTwoWays(vlan3[0], vlan3[9])
                    connectTwoWays(vlan3[1], vlan3[10])
                    connectTwoWays(vlan3[2], vlan3[11])
                    connectTwoWays(vlan3[3], vlan3[12])
                    connectTwoWays(vlan3[4], vlan3[13])
                    connectTwoWays(vlan3[5], vlan3[14])
                    connectTwoWays(vlan3[6], vlan3[15])
                    connectTwoWays(vlan3[7], vlan3[16])
                    connectTwoWays(vlan3[8], vlan3[17])

                    connectTwoWays(vlan4[0], vlan4[8])
                    connectTwoWays(vlan4[1], vlan4[9])
                    connectTwoWays(vlan4[2], vlan4[10])
                    connectTwoWays(vlan4[3], vlan4[11])
                    connectTwoWays(vlan4[4], vlan4[12])
                    connectTwoWays(vlan4[5], vlan4[13])
                    connectTwoWays(vlan4[6], vlan4[0])
                    connectTwoWays(vlan4[7], vlan4[1])

    elif totalEdge > 134 and routerCanBeCompromised == False:
        connectTwoWays(vlan3[1], vlan3[0])
        connectTwoWays(vlan3[2], vlan3[0])

        connectTwoWays(vlan2[0], vlan3[0])
        connectTwoWays(vlan2[1], vlan3[0])

        connectTwoWays(vlan4[0], vlan3[0])

        connectTwoWays(vlan2[2], vlan2[3])
        connectTwoWays(vlan2[4], vlan2[5])
        connectTwoWays(vlan2[6], vlan2[7])
        connectTwoWays(vlan2[8], vlan2[9])

        connectTwoWays(vlan4[2], vlan4[3])
        connectTwoWays(vlan4[4], vlan4[5])
        connectTwoWays(vlan4[6], vlan4[7])
        connectTwoWays(vlan4[8], vlan4[9])

        connectTwoWays(vlan2[-1], vlan3[-1])
        connectTwoWays(vlan4[-1], vlan3[-1])

        if totalEdge >= 160: #+13
            connectTwoWays(vlan2[10], vlan2[11])
            connectTwoWays(vlan2[12], vlan2[13])
            connectTwoWays(vlan2[14], vlan2[10])
            
            connectTwoWays(vlan3[3], vlan3[4])
            connectTwoWays(vlan3[5], vlan3[6])
            connectTwoWays(vlan3[7], vlan3[8])
            connectTwoWays(vlan3[9], vlan3[10])
            connectTwoWays(vlan3[11], vlan3[12])
            connectTwoWays(vlan3[13], vlan3[14])
            connectTwoWays(vlan3[15], vlan3[16])
                        
            connectTwoWays(vlan4[10], vlan4[11])
            connectTwoWays(vlan4[12], vlan4[13])
            connectTwoWays(vlan4[12], vlan4[10])

            if totalEdge >= 212: #+26
                connectTwoWays(vlan2[0], vlan2[1])
                connectTwoWays(vlan2[1], vlan2[2])
                connectTwoWays(vlan2[3], vlan2[4])
                connectTwoWays(vlan2[5], vlan2[6])
                connectTwoWays(vlan2[7], vlan2[8])
                connectTwoWays(vlan2[9], vlan2[10])
                connectTwoWays(vlan2[11], vlan2[12])
                connectTwoWays(vlan2[13], vlan2[14])

                connectTwoWays(vlan3[1], vlan3[2])
                connectTwoWays(vlan3[2], vlan3[3])
                connectTwoWays(vlan3[4], vlan3[5])
                connectTwoWays(vlan3[6], vlan3[7])
                connectTwoWays(vlan3[8], vlan3[9])
                connectTwoWays(vlan3[10], vlan3[11])
                connectTwoWays(vlan3[12], vlan3[13])
                connectTwoWays(vlan3[14], vlan3[15])
                connectTwoWays(vlan3[16], vlan3[17])

                connectTwoWays(vlan4[0], vlan4[1])
                connectTwoWays(vlan4[1], vlan4[2])
                connectTwoWays(vlan4[3], vlan4[4])
                connectTwoWays(vlan4[5], vlan4[6])
                connectTwoWays(vlan4[7], vlan4[8])
                connectTwoWays(vlan4[9], vlan4[10])
                connectTwoWays(vlan4[11], vlan4[12])
                connectTwoWays(vlan4[13], vlan4[14])
                connectTwoWays(vlan4[14], vlan4[0])

                if totalEdge >= 266: #+27
                    connectTwoWays(vlan2[0], vlan2[8])
                    connectTwoWays(vlan2[1], vlan2[9])
                    connectTwoWays(vlan2[2], vlan2[10])
                    connectTwoWays(vlan2[3], vlan2[11])
                    connectTwoWays(vlan2[4], vlan2[12])
                    connectTwoWays(vlan2[5], vlan2[13])
                    connectTwoWays(vlan2[6], vlan2[14])
                    connectTwoWays(vlan2[7], vlan2[0])

                    connectTwoWays(vlan3[0], vlan3[9])
                    connectTwoWays(vlan3[1], vlan3[10])
                    connectTwoWays(vlan3[2], vlan3[11])
                    connectTwoWays(vlan3[3], vlan3[12])
                    connectTwoWays(vlan3[4], vlan3[13])
                    connectTwoWays(vlan3[5], vlan3[14])
                    connectTwoWays(vlan3[6], vlan3[15])
                    connectTwoWays(vlan3[7], vlan3[16])
                    connectTwoWays(vlan3[8], vlan3[17])
                    connectTwoWays(vlan3[9], vlan3[18])

                    connectTwoWays(vlan4[0], vlan4[8])
                    connectTwoWays(vlan4[1], vlan4[9])
                    connectTwoWays(vlan4[2], vlan4[10])
                    connectTwoWays(vlan4[3], vlan4[11])
                    connectTwoWays(vlan4[4], vlan4[12])
                    connectTwoWays(vlan4[5], vlan4[13])
                    connectTwoWays(vlan4[6], vlan4[0])
                    connectTwoWays(vlan4[7], vlan4[1])
                    connectTwoWays(vlan4[7], vlan4[14])

    return None
    
def add50NodesOfficeTopology(net):
    #vlan 1: 1 router; 5 light bulbs; 4 printers; 5 laptops; 1 ipcamera; 0 tvs; 0 projectors; 0 iotdevice;

    #vlan 2: 1 router; 9 light bulbs; 0 printers; 0 laptops; 2 ipcamera; 3 tvs; 2 projectors; 0 iotdevice;

    #vlan 3: 1 router, 5 light bulbs; 4 printers; 4 laptops; 1 ipcamera; 0 tvs; 0 projectors; 0 iotdevice;

    topology = {
        "vlan1": {"router" : 1,
                    "lightbulb" : 5,
                    "printer" : 4,
                    "laptop" : 5,
                    "ipcamera" : 1,
                    "tv" : 0,
                    "projector" : 0,
                    "nvr" : 0,
                    "fridge" : 0,
                    "smokeAlarm" : 1,
                    "iotdevice" : 0},
        "vlan2": {"router" : 1,
                    "lightbulb" : 9,
                    "printer" : 0,
                    "laptop" : 0,
                    "ipcamera" : 2,
                    "tv" : 3,
                    "projector" : 2,
                    "nvr" : 1,
                    "fridge" : 1,
                    "smokeAlarm" : 1,
                    "iotdevice" : 0},
        "vlan3": {"router" : 1,
                    "lightbulb" : 5,
                    "printer" : 4,
                    "laptop" : 4,
                    "ipcamera" : 1,
                    "tv" : 0,
                    "projector" : 0,
                    "nvr" : 0,
                    "fridge" : 0,
                    "smokeAlarm" : 1,
                    "iotdevice" : 0}
    }

    j = 0
    #square view
    newListDif = [(0, 0), (750, -750), (1500, 0), (-310, 265), (-310, -265), (-310, 0), (235, -135), (235, 350), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (1085, -1240), (1085, -1430), (405, -645), (1175, 350), (1175, -110), (1850, 280), (1850, 0), (1850, -265), (-310, 510), (70, 510), (-310, -510), (70, -510), (1175, 510), (1630, 510), (1175, -510), (1630, -510), (-105, 510), (235, 510), (-105, -510), (235, -510), (235, 0), (1380, 510), (1850, 510), (1380, -510), (1850, -510), (235, 165), (895, -105), (550, -130), (1175, 170), (450, -245), (1085, -855), (1020, -305), (405, -1045), (1085, -1045), (750, 0), (580, -1430), (235, -305), (675, -285), (1175, -255)]

    for node in net.nodes:
        node.position = newListDif[j]
        j+=1

    router = []
    lightbulb = []
    printer = []
    laptop = []
    ipcamera = []
    tv = []
    projector = []
    nvr = []
    fridge = []
    smokeAlarm = []
    iotdevice = []

    for node in net.nodes:
        text = node.name.split("-")
        if 'router' in text:
            router.append(node)
        if 'lightbulb' in text:
            lightbulb.append(node)
        if 'printer' in text:
            printer.append(node)
        if 'laptop' in text:
            laptop.append(node)
        if 'ipcamera' in text:
            ipcamera.append(node)
        if 'tv' in text:
            tv.append(node)
        if 'projector' in text:
            projector.append(node)
        if 'nvr' in text:
            nvr.append(node)
        if 'fridge' in text:
            fridge.append(node)
        if 'smokeAlarm' in text:
            smokeAlarm.append(node)
        if 'iotdevice' in text:
            iotdevice.append(node)

    ipcamera2 = ipcamera.copy()
    laptop2 = laptop.copy()
    printer2 = printer.copy()
    smokeAlarm2 = smokeAlarm.copy()
    i = 0
    numbers = [[5, 4, 5, 1, 0, 0, 0, 1], [9, 0, 0, 2, 3, 2, 0, 1],[5, 4, 4, 1, 0, 0, 0, 1]]
    for node in router:
        tempLB = lightbulb.copy()
        tempP = printer.copy()
        tempL = laptop.copy()
        tempIP = ipcamera.copy()
        tempTV = tv.copy()
        tempProj = projector.copy()
        tempSA = smokeAlarm.copy()
        
        if numbers[i][0] > 0:
            temp = numbers[i][0]
            for j in range(0, temp):
                connectTwoWays(tempLB[j], node)
                lightbulb.remove(tempLB[j])
        if numbers[i][1] > 0:
            temp = numbers[i][1]
            for j in range(0, temp):
                connectTwoWays(tempP[j], node)
                printer.remove(tempP[j])
        if numbers[i][2] > 0:
            temp = numbers[i][2]
            for j in range(0, temp):
                connectTwoWays(tempL[j], node)
                laptop.remove(tempL[j])
        if numbers[i][3] > 0:
            temp = numbers[i][3]
            for j in range(0, temp):
                connectTwoWays(tempIP[j], node)
                ipcamera.remove(tempIP[j])
        if numbers[i][4] > 0:
            temp = numbers[i][4]
            for j in range(0, temp):
                connectTwoWays(tempTV[j], node)
                tv.remove(tempTV[j])
        if numbers[i][5] > 0:
            temp = numbers[i][5]
            for j in range(0, temp):
                connectTwoWays(tempProj[j], node)
                projector.remove(tempProj[j])
        if numbers[i][7] > 0:
            temp = numbers[i][7]
            for j in range(0, temp):
                connectTwoWays(tempSA[j], node)
                smokeAlarm.remove(tempSA[j])

        if i == 1:
            connectTwoWays(nvr[0], node)
            connectTwoWays(fridge[0], node)
            
        i += 1

    for node in ipcamera2:
        connectTwoWays(nvr[0], node)

    for i in range(0, len(printer2)):
        if i < 4:
            connectTwoWays(printer2[i], laptop2[i])
        else:
            connectTwoWays(printer2[i], laptop2[i+1])

    connectTwoWays(smokeAlarm2[0], smokeAlarm2[1])
    connectTwoWays(smokeAlarm2[2], smokeAlarm2[1])
    connectTwoWays(nvr[0], laptop2[4])
    connectTwoWays(router[1], router[0])
    connectTwoWays(router[2], router[1])

    return None

def add50SameNodesOfficeTopology(net):
    #vlan 1: 1 router; 5 light bulbs; 4 printers; 5 laptops; 1 ipcamera; 0 tvs; 0 projectors;

    #vlan 2: 1 router; 9 light bulbs; 0 printers; 0 laptops; 2 ipcamera; 3 tvs; 2 projectors;

    #vlan 3: 1 router, 5 light bulbs; 4 printers; 4 laptops; 1 ipcamera; 0 tvs; 0 projectors;

    vlan1 = []
    vlan2 = []
    vlan3 = []
    vlan4 = []

    k = 0

    #square view
    newList = [(0, 0), (750, -750), (1500, 0), (235, 165), (235, 0), (235, 510), (70, 510), (70, -510), (235, -510), (-105, 510), (-310, 510), (-105, -510), (-310, -510), (235, -135), (-310, 265), (-310, -265), (235, 350), (-310, 0), (235, -305), (750, 0), (895, -105), (550, -130), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (405, -1045), (1085, -1430), (405, -645), (450, -245), (1085, -1045), (1085, -855), (1085, -1240), (580, -1430), (1020, -305), (675, -285), (1175, 170), (1175, -110), (1850, -510), (1630, -510), (1380, -510), (1175, -510), (1630, 510), (1850, 510), (1175, 510), (1380, 510), (1850, 280), (1850, 0), (1850, -265), (1175, 350), (1175, -255), (235, -265), (650, -265), (1175, 0)]
    #            1       2               3           4           5       6           7           8           9           10              11          12            13        14              15      16              17          18          19          20          21              22            23            24          25              26          27          28          29              30          31              32          33              34          35              36          37          38              39          40              41          42          43          44              45          46          47          48          49              50          51             52          53

    for node in net.nodes:
        node.position = newList[k]
        k+=1

    temp1 = net.nodes.copy()

    numbers = [3, 16, 19, 15]
    
    for i in range(0, len(numbers)):
        temp2 = temp1.copy()
        for j in range(0, numbers[i]):
            if i == 0:
                vlan1.append(temp2[j])
            if i == 1:
                vlan2.append(temp2[j])
            if i == 2:
                vlan3.append(temp2[j])
            if i == 3:
                vlan4.append(temp2[j])
            temp1.remove(temp2[j])

    for node in vlan2:
        connectTwoWays(vlan1[0], node)

    for node in vlan3:
        connectTwoWays(vlan1[1], node)

    for node in vlan4:
        connectTwoWays(vlan1[2], node)
   
    connectTwoWays(vlan3[1], vlan3[0])
    connectTwoWays(vlan3[2], vlan3[0])

    connectTwoWays(vlan2[0], vlan3[0])
    connectTwoWays(vlan2[1], vlan3[0])

    connectTwoWays(vlan4[0], vlan3[0])

    connectTwoWays(vlan2[2], vlan2[3])
    connectTwoWays(vlan2[4], vlan2[5])
    connectTwoWays(vlan2[6], vlan2[7])
    connectTwoWays(vlan2[8], vlan2[9])

    connectTwoWays(vlan4[2], vlan4[3])
    connectTwoWays(vlan4[4], vlan4[5])
    connectTwoWays(vlan4[6], vlan4[7])
    connectTwoWays(vlan4[8], vlan4[9])

    connectTwoWays(vlan1[1], vlan1[0])
    connectTwoWays(vlan1[2], vlan1[1])

    connectTwoWays(vlan2[-1], vlan3[-1])
    connectTwoWays(vlan4[-1], vlan3[-1])

    return None

def add25nodes(net):

    vlan1 = []
    vlan2 = []
    vlan3 = []
    vlan4 = []

    k = 0
    #square view
    #            1       2               3           4           5       6           7           8           9           10              11          12            13        14              15      16              17          18          19          20          21              22            23            24          25              26          27          28          29              30          31              32          33              34          35              36          37          38              39          40              41          42          43          44              45          46          47          48          49              50          
    newList = [(0, 0), (750, -750), (1500, 0), (235, 510), (70, 510), (-105, 510), (-310, 510), (70, -510), (235, -510), (-105, -510), (-310, -510), (405, -645), (405, -1045), (405, -1430), (750, -1430), (1085, -1430), (1085, -1045), (1085, -645), (550, -130), (895, -105), (1175, 510), (1380, 510), (1630, 510), (1850, 510), (1850, -510), (1630, -510), (1380, -510), (1175, -510)]
    
    for node in net.nodes:
        node.position = newList[k]
        k+=1

    temp1 = net.nodes.copy()

    numbers = [3, 8, 9, 8]
    
    for i in range(0, len(numbers)):
        temp2 = temp1.copy()
        for j in range(0, numbers[i]):
            if i == 0:
                vlan1.append(temp2[j])
            if i == 1:
                vlan2.append(temp2[j])
            if i == 2:
                vlan3.append(temp2[j])
            if i == 3:
                vlan4.append(temp2[j])
            temp1.remove(temp2[j])

    for node in vlan2:
        connectTwoWays(vlan1[0], node)

    for node in vlan3:
        connectTwoWays(vlan1[1], node)

    for node in vlan4:
        connectTwoWays(vlan1[2], node)
   
    connectTwoWays(vlan2[0], vlan3[7])

    connectTwoWays(vlan4[0], vlan3[7])

    connectTwoWays(vlan2[2], vlan2[3])
    connectTwoWays(vlan2[4], vlan2[5])
    connectTwoWays(vlan2[6], vlan2[7])

    connectTwoWays(vlan4[2], vlan4[3])
    connectTwoWays(vlan4[4], vlan4[5])
    connectTwoWays(vlan4[6], vlan4[7])

    connectTwoWays(vlan1[1], vlan1[0])
    connectTwoWays(vlan1[2], vlan1[1])

    return None

def add75nodes(net):

    vlan1 = []
    vlan2 = []
    vlan3 = []
    vlan4 = []

    k = 0
    #square view
    #            1       2               3           4           5       6           7           8           9           10              11          12            13        14              15      16              17          18          19          20          21              22            23            24          25              26          27          28          29              30          31              32          33              34          35              36          37          38              39          40              41          42          43          44              45          46          47          48          49              50          
    newList = [(0, 0), (750, -750), (1500, 0), (235, 165), (235, 0), (235, 510), (70, 510), (70, -510), (235, -510), (-105, 510), (-310, 510), (-105, -510), (-310, -510), (235, -135), (-310, 265), (-310, -265), (235, 350), (-310, 0), (235, -305), (0, 600), (-350, 450), (-350, 375), (-350, 220), (-350, 100), (-350, -100), (-350, -220), (-350, -375), (0, -600), (750, 0), (895, -105), (550, -130), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (405, -1045), (1085, -1430), (405, -645), (450, -245), (1085, -1045), (1085, -855), (1085, -1240), (580, -1430), (1020, -305), (675, -285), (300, -900), (300, -1140), (300, -1340), (1175, -1340), (1175, -1140), (1175, -900), (1175, 170), (1175, -110), (1850, -510), (1630, -510), (1380, -510), (1175, -510), (1630, 510), (1850, 510), (1175, 510), (1380, 510), (1850, 280), (1850, 0), (1850, -265), (1175, 350), (1175, -255), (1175, 0), (1500, 600), (1900, 450), (1900, 375), (1900, 220), (1900, 100), (1900, -100), (1900, -220), (1900, -375), (1500, -600)]

    for node in net.nodes:
        node.position = newList[k]
        k+=1

    temp1 = net.nodes.copy()

    numbers = [3, 25, 25, 25]
    
    for i in range(0, len(numbers)):
        temp2 = temp1.copy()
        for j in range(0, numbers[i]):
            if i == 0:
                vlan1.append(temp2[j])
            if i == 1:
                vlan2.append(temp2[j])
            if i == 2:
                vlan3.append(temp2[j])
            if i == 3:
                vlan4.append(temp2[j])
            temp1.remove(temp2[j])

    for node in vlan2:
        connectTwoWays(vlan1[0], node)

    for node in vlan3:
        connectTwoWays(vlan1[1], node)

    for node in vlan4:
        connectTwoWays(vlan1[2], node)
   
    connectTwoWays(vlan3[1], vlan3[0])
    connectTwoWays(vlan3[2], vlan3[0])

    connectTwoWays(vlan2[0], vlan3[0])
    connectTwoWays(vlan2[1], vlan3[0])

    connectTwoWays(vlan4[0], vlan3[0])

    connectTwoWays(vlan2[2], vlan2[3])
    connectTwoWays(vlan2[4], vlan2[5])
    connectTwoWays(vlan2[6], vlan2[7])
    connectTwoWays(vlan2[8], vlan2[9])

    connectTwoWays(vlan2[18], vlan2[19])
    connectTwoWays(vlan2[22], vlan2[23])

    connectTwoWays(vlan3[7], vlan3[16])
    connectTwoWays(vlan3[5], vlan3[10])
    connectTwoWays(vlan3[19], vlan3[20])

    connectTwoWays(vlan4[2], vlan4[3])
    connectTwoWays(vlan4[4], vlan4[5])
    connectTwoWays(vlan4[6], vlan4[7])
    connectTwoWays(vlan4[8], vlan4[9])

    connectTwoWays(vlan4[18], vlan4[19])
    connectTwoWays(vlan4[22], vlan4[23])

    connectTwoWays(vlan1[1], vlan1[0])
    connectTwoWays(vlan1[2], vlan1[1])

    connectTwoWays(vlan2[15], vlan3[18])
    connectTwoWays(vlan4[14], vlan3[18])

    return None

def add100nodes(net):

    vlan1 = []
    vlan2 = []
    vlan3 = []
    vlan4 = []

    k = 0
    #square view
    #            1       2               3           4           5       6           7           8           9           10              11          12            13        14              15      16              17          18          19          20          21              22            23            24          25              26          27          28          29              30          31              32          33              34          35              36          37          38              39          40              41          42          43          44              45          46          47          48          49              50          
    newList = [(0, 0), (750, -750), (1500, 0), (235, 165), (235, 0), (235, 510), (70, 510), (70, -510), (235, -510), (-105, 510), (-310, 510), (-105, -510), (-310, -510), (235, -135), (-310, 265), (-310, -265), (235, 350), (-310, 0), (235, -305), (0, 600), (-350, 450), (-350, 375), (-350, 220), (-350, 100), (-350, -100), (-350, -220), (-350, -375), (0, -600), (-200, 600), (150, 600), (300, 450), (300, 265), (300, -70), (300, -375), (150, -600), (-200, -600), (750, 0), (895, -105), (550, -130), (1085, -645), (750, -1430), (920, -1430), (405, -1240), (405, -1430), (405, -855), (405, -1045), (1085, -1430), (405, -645), (450, -245), (1085, -1045), (1085, -855), (1085, -1240), (580, -1430), (1020, -305), (675, -285), (300, -900), (300, -1140), (300, -1340), (1175, -1340), (1175, -1140), (1175, -900), (405, -570), (405, -750), (300, -1550), (690, -1550), (810, -1700), (1175, -1550), (1085, -750), (1085, -570), (500, -400), (1175, 170), (1175, -110), (1850, -510), (1630, -510), (1380, -510), (1175, -510), (1630, 510), (1850, 510), (1175, 510), (1380, 510), (1850, 280), (1850, 0), (1850, -265), (1175, 350), (1175, -255), (1175, 0), (1500, 600), (1900, 450), (1900, 375), (1900, 220), (1900, 100), (1900, -100), (1900, -220), (1900, -375), (1500, -600), (1270, 600), (1750, 600), (1125, 450), (1125, 265), (1125, -70), (1125, -375), (1750, -600), (1270, -600)]

    for node in net.nodes:
        node.position = newList[k]
        k+=1

    temp1 = net.nodes.copy()
    numbers = [3, 33, 34, 33]
    
    for i in range(0, len(numbers)):
        temp2 = temp1.copy()
        for j in range(0, numbers[i]):
            if i == 0:
                vlan1.append(temp2[j])
            if i == 1:
                vlan2.append(temp2[j])
            if i == 2:
                vlan3.append(temp2[j])
            if i == 3:
                vlan4.append(temp2[j])
            temp1.remove(temp2[j])

    for node in vlan2:
        connectTwoWays(vlan1[0], node)

    for node in vlan3:
        connectTwoWays(vlan1[1], node)

    for node in vlan4:
        connectTwoWays(vlan1[2], node)
   
    connectTwoWays(vlan3[1], vlan3[0])
    connectTwoWays(vlan3[2], vlan3[0])

    connectTwoWays(vlan2[0], vlan3[0])
    connectTwoWays(vlan2[1], vlan3[0])

    connectTwoWays(vlan4[0], vlan3[0])

    connectTwoWays(vlan2[2], vlan2[3])
    connectTwoWays(vlan2[4], vlan2[5])
    connectTwoWays(vlan2[6], vlan2[7])
    connectTwoWays(vlan2[8], vlan2[9])

    connectTwoWays(vlan2[18], vlan2[19])
    connectTwoWays(vlan2[20], vlan2[21])
    connectTwoWays(vlan2[22], vlan2[23])

    connectTwoWays(vlan3[7], vlan3[16])
    connectTwoWays(vlan3[5], vlan3[10])
    connectTwoWays(vlan3[19], vlan3[20])
    connectTwoWays(vlan3[23], vlan3[24])

    connectTwoWays(vlan4[2], vlan4[3])
    connectTwoWays(vlan4[4], vlan4[5])
    connectTwoWays(vlan4[6], vlan4[7])
    connectTwoWays(vlan4[8], vlan4[9])

    connectTwoWays(vlan4[18], vlan4[19])
    connectTwoWays(vlan4[20], vlan4[21])
    connectTwoWays(vlan4[22], vlan4[23])

    connectTwoWays(vlan1[1], vlan1[0])
    connectTwoWays(vlan1[2], vlan1[1])

    connectTwoWays(vlan2[15], vlan3[18])
    connectTwoWays(vlan4[14], vlan3[18])

    connectTwoWays(vlan3[17], vlan3[33])
    connectTwoWays(vlan3[11], vlan3[26])
    connectTwoWays(vlan3[3], vlan3[31])

    return None

def assignIPAddressForNetwork(net):
    iotNet = IPv4Network("192.168.2.0/24")
    ipList = list(iotNet)
    for x in net.nodes:
        tempNet = ipList.copy()
        temp = choice(tempNet)
        x.IPv4Add = temp
        ipList.remove(temp)

    return None

def assignRandomIPAddress(num):
    '''
    https://stackoverflow.com/questions/63534813/generate-random-ips
    '''
    randomIP = ""
    MAX_IPV4 = IPv4Address._ALL_ONES  # 2 ** 32 - 1
    MAX_IPV6 = IPv6Address._ALL_ONES  # 2 ** 128 - 1

    if num == 4:
        randomIP = IPv4Address._string_from_ip_int(randint(0, MAX_IPV4))
    elif num == 6:
        randomIP = IPv6Address._string_from_ip_int(randint(0, MAX_IPV6))

    return randomIP

def add_vulNew(net, IoTDeviceSetup):#, defMode):
    """
    Add vulnerabilities for real devices.
    """
    ##Values are according to CVSS version 3.1 - 22 July 2020
    for node in net.nodes:
        text = node.name.split("-")

        if 'iotdevice' in text or 'decoy+iotdevice' in text: #unspecified IoT device for control case
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8
            
            for x in IoTDeviceSetup['iotdevice']['openPort']:
                for y in IoTDeviceSetup['iotdevice']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['iotdevice']['openPort'])
                    
        elif 'lightbulb' in text or 'decoy+lightbulb' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['lightbulb']['openPort']:
                for y in IoTDeviceSetup['lightbulb']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['lightbulb']['openPort'])

        elif 'slowcooker' in text or 'decoy+slowcooker' in text:
            #Belkin Wemo Enabled Crock-Pot allows command injection in the Wemo UPnP API via the SmartDevURL argument to the SetSmartDevInfo action
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8
            #https://nvd.nist.gov/vuln/detail/CVE-2019-12780
            
            #createVulsWithoutTypeNew(node, 0.004, 0.39, 5.9, 1, "CVE-2019-12780")

            for x in IoTDeviceSetup['slowcooker']['openPort']:
                for y in IoTDeviceSetup['slowcooker']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 0.004, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['slowcooker']['openPort'])

        elif 'ipcamera' in text or 'decoy+ipcamera' in text:
            #Wireless IP Camera (P2P) WIFICAM devices
            #CVSS Base Score: 7.5; Impact Subscore: 3.6; Exploitability Subscore: 3.9; Overall: 7.5
            #https://nvd.nist.gov/vuln/detail/CVE-2017-8221

            #createVulsWithoutTypeNew(node, 0.006, 0.39, 3.6, 1, "CVE-2017-8221")

            for x in IoTDeviceSetup['ipcamera']['openPort']:
                for y in IoTDeviceSetup['ipcamera']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 0.006, 0.39, 3.6, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['ipcamera']['openPort'])
            
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8
            #https://nvd.nist.gov/vuln/detail/CVE-2017-18377

        ##        createVulsWithoutTypeNew(node, 0.006, 0.39, 5.9, 1, "CVE-2017-18377")#this is how to add multiple vulnerabilities
        elif 'dvr' in text or 'decoy+dvr' in text:
            #XiongMai uc-httpd 1.0.0 Buffer overflow
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8
            #https://nvd.nist.gov/vuln/detail/CVE-2018-10088

            #createVulsWithoutTypeNew(node, 0.042, 0.39, 5.9, 1, "CVE-2018-10088")

            for x in IoTDeviceSetup['dvr']['openPort']:
                for y in IoTDeviceSetup['dvr']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 0.042, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['dvr']['openPort'])
            
        elif 'router' in text or 'decoy+router' in text:
            #Huawei HG532 Router
            #CVSS Base Score: 8.8; Impact Subscore: 5.9; Exploitability Subscore: 2.8; Overall: 8.8
            #https://nvd.nist.gov/vuln/detail/CVE-2017-17215

            #createVulsWithoutTypeNew(node, 0.042, 0.28, 5.9, 1, "CVE-2017-17215")

            for x in IoTDeviceSetup['router']['openPort']:
                for y in IoTDeviceSetup['router']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 0.042, 0.28, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['router']['openPort'])
            
        elif 'nvr' in text or 'decoy+nvr' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['nvr']['openPort']:
                for y in IoTDeviceSetup['nvr']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['nvr']['openPort'])
            
        elif 'printer' in text or 'decoy+printer' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['printer']['openPort']:
                for y in IoTDeviceSetup['printer']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['printer']['openPort'])
            
        elif 'laptop' in text or 'decoy+laptop' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['laptop']['openPort']:
                for y in IoTDeviceSetup['laptop']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['laptop']['openPort'])
            
        elif 'projector' in text or 'decoy+projector' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['projector']['openPort']:
                for y in IoTDeviceSetup['projector']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['projector']['openPort'])
            
        elif 'fridge' in text or 'decoy+fridge' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['fridge']['openPort']:
                for y in IoTDeviceSetup['fridge']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['fridge']['openPort'])

        elif 'tv' in text or 'decoy+tv' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['tv']['openPort']:
                for y in IoTDeviceSetup['tv']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['tv']['openPort'])

        elif 'smokeAlarm' in text or 'decoy+smokeAlarm' in text:
            #Default credential vul
            #CVSS Base Score: 9.8; Impact Subscore: 5.9; Exploitability Subscore: 3.9; Overall: 9.8

            for x in IoTDeviceSetup['smokeAlarm']['openPort']:
                for y in IoTDeviceSetup['smokeAlarm']['openPort'][x]['Vuln']:
                    createVulsWithoutTypeNew(node, 365, 0.39, 5.9, 1, y)
            node.realPort = copy.deepcopy(IoTDeviceSetup['smokeAlarm']['openPort'])

        else:
            print("Vulnerability not found!")                  

        #check if it can be compromised
        if node.canBeCompromised == False:
            removeAllVuln(node)

    return None

def createIoTNetwork(node_vlan_list, topologyStyle, IoTDeviceSetup, defMode, AtkerTimeDataDict, saveDir, saveFolder, entryPointNode, percentageOfVulnNodes, specialChanges, graphDensity): ## add num for random graph
    """
    Create an IoT network.
    """    
    net = network()
    net.defMode = defMode
    net.saveSimDir = saveDir
    net.saveFolder = saveFolder
    net.entryPointNode = entryPointNode
    net.AtkerTimeDataDict = AtkerTimeDataDict
    temp1 = []
    temp2 = []
    for x in node_vlan_list:
        text = x.split('-')
        if 'router' in text:
            temp1.append(x)
        else:
            temp2.append(x)
    if len(temp1) > 0 and len(temp2) > 0:
        node_vlan_list = temp1 + temp2

    id = 1
    #Add real devices into VLANs of network
    for i in range(0, len(node_vlan_list)):
        temp = node_vlan_list[i]
        vlan = "vlan" + str(i+1)
        text1 = temp.split('-')
        if 'router' in text1:
            iot = routerNode(temp)
        else:
            iot = realNode(temp)
        text = iot.name.split('-')
        if IoTDeviceSetup[text[0]]['otherValues'] == "Cannot be compromised":
            iot.canBeCompromised = False

        iot.id = id
        iot.subnet = vlan
        net.nodes.append(iot)
        id += 1
        
        net.subnets.append(vlan)
    
    if topologyStyle == "home":
        pass
    elif topologyStyle == "office25" or topologyStyle == "25same":
        add25nodes(net)
    elif topologyStyle == "office50same" or topologyStyle == "50same":
        add50SameNodesOfficeTopology(net) # for 50 identical nodes
    elif topologyStyle == "office75" or topologyStyle == "75same":
        add75nodes(net)
    elif topologyStyle == "office100" or topologyStyle == "100same":
        add100nodes(net)
    elif topologyStyle == "office50dif" or topologyStyle == "50dif":
        add50NodesOfficeTopology(net) # for 50 different nodes
    elif topologyStyle == "grid" or topologyStyle == "IAS" or topologyStyle == "smallworld" or topologyStyle == "scalefree" or topologyStyle == "tree" or topologyStyle == "RGG" or topologyStyle == "mesh":
        addDifferentTopology(net, topologyStyle, saveDir)
    elif topologyStyle == "graphDen":
        addDifDensityTopology2(net, graphDensity, saveDir)
    elif topologyStyle == "complete":
        addCompleteTopology(net, saveDir)
    elif topologyStyle == "circle":
        addDifferentTopology(net, "circle", saveDir)
    elif topologyStyle == "random":
        addRandomTopology(net, saveDir)
    else:
        print("Topology style not found!")
        sys.exit(1)

    intersectNum = 0
    nonIntersectNum = 0
    for node in net.nodes:
        if len(node.con) > 2:
            intersectNum += 1
        else:
            nonIntersectNum += 1

    decoyNameList = []
    decoyNodeList = []
    decoyModel = None
    dm = defenceMethods()
    newNet = None

    mtdStatus = False
    if defMode["MTD"]["operational"] == True:
        mtdStatus = True
        mtdMode = defMode["MTD"]["mode"]

    if mtdStatus == True:
        net = dm.movingTargetDefence(net, mtdMode, 1)

    cdStatus = False
    if defMode["Deception"]["operational"] == True:
        cdStatus = True
        cdMode = defMode["Deception"]["mode"]
        decoyModel = defMode["Deception"]["model"]

    if cdStatus == True:
        decoyNameList, decoyNodeList, newNet = dm.cyberDeceptionSetup(net, cdMode, decoyModel)

        if newNet is not None:
            net = copyNet(newNet)

    createGraph(net, "original topology", saveDir)

    #Add vulnerabilities to real devices
    add_vulNew(net, IoTDeviceSetup)
        
    assignIPAddressForNetwork(net)

    if len(percentageOfVulnNodes) > 0:
        randomRemoveVul(net, percentageOfVulnNodes)

    if specialChanges["Vuln"]["Change"] == True or specialChanges["Port"]["Change"] == True:
        specialRandomChanges(net, specialChanges)

    folderName = saveFolder.split("/")
    if len(folderName) == 1:
        folderName = saveFolder.split('\\')

    if defMode["Firewall"]["operational"] == True:
        for z in net.defMode["Firewall"]["rule"]:
            if net.defMode["Firewall"]["rule"][z] is not None:
                if net.defMode["Firewall"]["rule"][z]["SourceIP"] == "any":
                    pass
                else:
                    text = net.defMode["Firewall"]["rule"][z]["SourceIP"]
                    for x in net.nodes:
                        if x.name == text:
                            net.defMode["Firewall"]["rule"][z]["SourceIP"] = x.IPv4Add
                            break

                if net.defMode["Firewall"]["rule"][z]["DestinationIP"] == "any":
                    pass
                else:
                    text = net.defMode["Firewall"]["rule"][z]["DestinationIP"]
                    for x in net.nodes:
                        if x.name == text:
                            net.defMode["Firewall"]["rule"][z]["DestinationIP"] = x.IPv4Add
                            break

    if defMode["IPS"]["operational"] == True:
        for z in net.defMode["IPS"]["rule"]:
            if net.defMode["IPS"]["rule"][z] is not None:
                if net.defMode["IPS"]["rule"][z]["SourceIP"] == "any":
                    pass
                else:
                    text = net.defMode["IPS"]["rule"][z]["SourceIP"]
                    for x in net.nodes:
                        if x.name == text:
                            net.defMode["IPS"]["rule"][z]["SourceIP"] = x.IPv4Add
                            break

                if net.defMode["IPS"]["rule"][z]["DestinationIP"] == "any":
                    pass
                else:
                    text = net.defMode["IPS"]["rule"][z]["DestinationIP"]
                    for x in net.nodes:
                        if x.name == text:
                            net.defMode["IPS"]["rule"][z]["DestinationIP"] = x.IPv4Add
                            break

    if defMode["IDS"]["operational"] == True:
        for z in net.defMode["IDS"]["rule"]:
            if net.defMode["IDS"]["rule"][z] is not None:
                if net.defMode["IDS"]["rule"][z]["SourceIP"] == "any":
                    pass
                else:
                    text = net.defMode["IDS"]["rule"][z]["SourceIP"]
                    for x in net.nodes:
                        if x.name == text:
                            net.defMode["IDS"]["rule"][z]["SourceIP"] = x.IPv4Add
                            break

                if net.defMode["IDS"]["rule"][z]["DestinationIP"] == "any":
                    pass
                else:
                    text = net.defMode["IDS"]["rule"][z]["DestinationIP"]
                    
                    if type(text) is list:
                        tempList = []
                        for x in text:
                            tempText = x.split("-")
                            
                            for y in net.nodes:
                                tempIP = None
                                if len(tempText) > 1:
                                    if y.name == str(x):
                                        tempIP = y.IPv4Add
                                else:
                                    tempText2 = y.name.split("-")
                                    if tempText2[0] == str(x):
                                        tempIP = y.IPv4Add
                                        

                                if tempIP is not None:
                                    if tempIP not in tempList:
                                            tempList.append(tempIP)

                        net.defMode["IDS"]["rule"][z]["DestinationIP"] = tempList.copy()
                    
    if defMode["Patching"]["operational"] == True:
        dm.patchVulnerability(defMode["Patching"]["mode"], defMode["Patching"]["vulnerability"], None, None, net.nodes)

    return net

def constructHARM(net):
    #Create security model
    h = harm()
    
    h.constructHarm(net, "attackgraph", 1, "attacktree", 1, 1)
    
    return h

def addAttackersToPool(net, attackerList):
    i = 1

    CNC = None
    sameCNC = False
    tempInfo = {}

    for id, info in attackerList.items():
        A = attacker(id)
        A.setStart()
        A.setAttacker()
        
        for key in info:
            if key == 'AverageTime':
                A.meanTime = info[key]
            elif key == 'scanPort':
                A.scanPort = info[key]
            elif key == 'IP':
                A.IPv4Add = info[key]
            elif key == 'protocol':
                A.protocol = info[key]
            elif key == 'content':
                A.content = info[key]
            elif key == 'exploit':
                A.carryExploit = info[key]
            elif key == 'cooperative':
                A.coop = info[key]
            elif key == 'botCoop':
                A.botCoop = info[key]
            elif key == 'group':
                A.group = info[key]
            elif key == 'signature':
                A.signature = info[key]
            elif key == 'goal':
                A.goal = info[key]
            elif key == 'mode':
                A.mode = info[key]
            elif key == 'target':
                if info[key] is not None:
                    A.nextTargetNode = info[key]
            elif key == 'attackData':
                A.attackData = info[key]
            elif key == 'accumulatedTime':
                A.accumulatedTime = info[key]
            elif key == 'status':
                A.status = info[key]
            elif key == 'scanningMethod':
                A.scanMethod = info[key]
            else:
                print("Error")
        A.active = True

        #trying to add same CNC to coop and same group attackers and vice versa
        if CNC is None:
            temp = []
            if A.coop == True:
                
                if len(tempInfo) == 0:
                    CNC = CommandNControl('CNC-' + str(i))
                    CNC.IPv4Add = assignRandomIPAddress(4)
                    i += 1
                    tempInfo[A.group] = CNC
                    
                else:
                    if str(A.group) in tempInfo:
                        sameCNC = True
                        CNC = tempInfo[A.group]
                        
                    else:
                        CNC = CommandNControl('CNC-' + str(i))
                        CNC.IPv4Add = assignRandomIPAddress(4)
                        
                        i += 1
                        tempInfo[A.group] = CNC
            else:
                CNC = CommandNControl('CNC-' + str(i))
                CNC.IPv4Add = assignRandomIPAddress(4)
                i += 1
            temp.append(A.name)
            temp.append(A.goal)
            temp.append(False)
            if A.name == 'attacker-1':
                CNC.IPv4Add = "10.127.162.234" #purposely add for IDS and Firewall's blacklist

            CNC.goal.append(temp)
            CNC.signature.append(A.signature)
            
        else:
            pass
        CNC.setIdle()
        connectTwoWays(CNC, A)
        A.CNCNode.append(CNC.name)

        net.nodes.append(A)
        if sameCNC == True:
            CNC.scanPort = assignPortNumberAndInfo(list(A.scanPort), CNC.scanPort)
        else:
            CNC.scanPort = assignPortNumberAndInfo(list(A.scanPort), None)
            net.nodes.append(CNC)
        net.atk.append([A])
        sameCNC = False
        CNC = None

    return net

def randomRemoveVul(net, percentageOfVulnNodes):
    """
    randomly remove vulnerability of a network
    """
    for x in percentageOfVulnNodes:
        if x[0] == "all":
            nodeNum = 0
            for y in net.nodes:
                if y.canBeCompromised == True:
                    nodeNum += 1
                else:
                    pass
            num = x[1]*nodeNum
            while (num > 0):
                tempNode = choice(net.nodes)
                if len(tempNode.vul.nodes) > 0 and tempNode.canBeCompromised == True:
                    removeAllVuln(tempNode)
                    num -= 1
        else:
            tempNum = 0
            tempList = []
            for y in net.nodes:
                text = y.name.split('-')
                if str(text[0]) == x[0]:
                    tempList.append(y)
                    tempNum += 1
            num = x[1]*tempNum
            while num > 0:
                tempNode = choice(tempList)
                if len(tempNode.vul.nodes) > 0 and tempNode.canBeCompromised == True:
                    removeAllVuln(tempNode)

    return None

def specialRandomChanges(net, specialChanges):
    
    if specialChanges["Vuln"]["Change"] == True:
        if specialChanges["Vuln"]["Overlap"] == True:
            pass
        else:
            tempNum = []
            bigTempList = []
            
            for x in specialChanges["Vuln"]["Content"]:
                tempList2 = []
                if specialChanges["Vuln"]["Content"][x] == 1 or specialChanges["Vuln"]["Content"][x] == 0:
                    pass
                else:
                    num = specialChanges["Vuln"]["Content"][x]*len(net.nodes)
                    tempNum.append(num)
                    while(num > 0):
                        tempNode = choice(net.nodes)
                        if tempNode in bigTempList:
                            pass
                        else:
                            bigTempList.append(tempNode)
                            tempList2.append(tempNode)
                            num -= 1
                    for y in tempList2:
                        for z in y.vul.nodes:
                            if z.name == str(x):
                                y.vul.nodes.remove(z)
                                for a in y.realPort:
                                    for b in y.realPort[a]:
                                        if str(b) == "Vuln":
                                            temp2 = y.realPort[a][b].copy()
                                            for c in temp2:
                                                if c == str(x):
                                                    y.realPort[a][b].remove(c)

    if specialChanges["Port"]["Change"] == True:
        if specialChanges["Port"]["Overlap"] == True:
            pass
        else:
            tempNum = []
            bigTempList = []
            
            for x in specialChanges["Port"]["Content"]:
                tempList2 = []
                if specialChanges["Port"]["Content"][x] == 1 or specialChanges["Port"]["Content"][x] == 0:
                    pass
                else:
                    num = specialChanges["Port"]["Content"][x]*len(net.nodes)
                    tempNum.append(num)
                    while(num > 0):
                        tempNode = choice(net.nodes)
                        if tempNode in bigTempList:
                            pass
                        else:
                            bigTempList.append(tempNode)
                            tempList2.append(tempNode)
                            num -= 1
                    for y in tempList2:
                        temp = y.realPort.copy()
                        for z in temp:
                            if str(z) == str(x):
                                del y.realPort[z]
    return None