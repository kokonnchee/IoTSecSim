'''
This module constructs other network topology using NetworkX graph generators for IoTSecSim.

@author: Kok Onn Chee
'''

import networkx as nx
import matplotlib.pyplot as plt
import numpy as np
import os
from random import choice
import copy

from SaveToFile import *

def createNetworkGraph(num, saveFolder, graphType):
    """
    Return the 2d grid graph of m * n nodes, each connected to its nearest neighbors. 
    """
    loopStop = False

    while(loopStop == False):
        G = generateNewGraph(num, graphType)

        edgeNum = G.number_of_edges()

        addNum, deductNum = calculateEdgeNum(edgeNum)

        components = list(nx.connected_components(G))

        if len(components) > 1:
            pass
        else:
            loopStop = True

    saveGraphAsFigure(G, graphType, saveFolder, "ori")
    G = addRemoveEdge(G, deductNum, addNum, graphType)

    data = nx.to_dict_of_lists(G)

    if graphType == "tree" or graphType == "grid":
        data = convertInfo(data)

    edgeNum2 = G.number_of_edges()
    createRecord(data, os.path.join(saveFolder, "graph.txt"))
    saveGraphAsFigure(G, graphType, saveFolder, "modified")

    return data

def generateNewGraph(num, graphType):

    goodGraph = False
    while(goodGraph == False):
        if graphType == "grid":
            G = nx.grid_2d_graph(5, 10)
        elif graphType == "IAS":
            G = nx.random_internet_as_graph(50)#, seed = 2)
        elif graphType == "smallworld":
            G = nx.newman_watts_strogatz_graph(n=50, k=2, p=0.3)
        elif graphType == "scalefree":
            G = nx.barabasi_albert_graph(50, 2)#, seed=1)
        elif graphType == "tree":
            G = nx.random_tree(num)
        elif graphType == "RGG":
            G = nx.random_geometric_graph(50, 0.25)
        elif graphType == "mesh":
            G = nx.complete_graph(num)
        else:
            print("Graph generator not found!")
            goodGraph = True

        tempComponents = list(nx.connected_components(G))
        if len(tempComponents) > 1:
            pass
        else:
            goodGraph = True

    if len(G.nodes) > num:
        G = addRemoveNode(G, num)

    return G

def createRandomGraph(numNodes, saveFolder):

    G = nx.fast_gnp_random_graph(numNodes, 0.3, seed=np.random)

    data = nx.to_dict_of_lists(G)

    createRecord(data, os.path.join(saveFolder, "graph.txt"))
    createRecord(nx.info(G), os.path.join(saveFolder, "graph.txt"))
    createRecord(nx.density(G), os.path.join(saveFolder, "graph.txt"))
    plt.savefig(os.path.join(saveFolder, 'Random Graph.png'), format='png')

    return data

def createCompleteGraph(num, saveFolder):
    G = nx.complete_graph(num)

    data = nx.to_dict_of_lists(G)

    createRecord(data, os.path.join(saveFolder, "graph.txt"))
    createRecord(nx.info(G), os.path.join(saveFolder, "graph.txt"))
    createRecord(nx.density(G), os.path.join(saveFolder, "graph.txt"))
    plt.savefig(os.path.join(saveFolder, 'Complete Graph.png'), format='png')

    return data

def addRemoveNode(G, num):
    deductNum = 0
    H = G.copy()
    if len(H.nodes) >= num:
        deductNum = len(H.nodes) - num
        if deductNum > 0:
            while(deductNum > 0):
                tempNode = choice(list(H.nodes))
                if len(H.edges(tempNode)) <= 2:
                    tempEdge = list(H.edges(tempNode))
                    for x in tempEdge:
                        H.remove_edge(x[0], x[1])
                    H.remove_node(tempNode)

                    tempComponents = list(nx.connected_components(H))
                    if len(tempComponents) > 1:
                        H = G.copy()
                    else:
                        deductNum -= 1
                        G = H.copy()
                else:
                    pass
    else:
        print("Graph is lack of nodes.")

    return G

def calculateEdgeNum(edgeNum):
    addNum = 0
    deductNum = 0

    if edgeNum >= 67: #62 if router can be compromised
        deductNum = edgeNum - 67
    else:
        addNum = 67 - edgeNum

    return addNum, deductNum

def addRemoveEdge(G, deductNum, addNum, graphType):
    H = G.copy()
    if deductNum > 0:
        while(deductNum > 0):
            tempEdge = None
            if graphType == "grid" or graphType == "tree" or graphType == "mesh":
                tempNode = choice(list(H.nodes))
                if len(H.edges(tempNode)) >= 3:
                    tempEdge = choice(list(H.edges(tempNode)))
                else:
                    pass
            else:
                tempEdge = choice(list(H.edges))

            if tempEdge is not None:
                proceed = False
                if graphType == "mesh":
                    if len(H.edges(tempEdge[0])) > 2 and len(H.edges(tempEdge[1])) > 3:
                        proceed = True
                    else:
                        pass
                else:
                    proceed = True

                if proceed == True:
                    H.remove_edge(tempEdge[0], tempEdge[1])
                    
                    tempComponents = list(nx.connected_components(H))
                    if len(tempComponents) > 1:
                        H = G.copy()
                    else:
                        deductNum -= 1
                        G = H.copy()

    if addNum > 0:
        while(addNum > 0):
            tempEdge = choice(list(nx.non_edges(H)))
            proceed2 = False
            if graphType == "tree":
                if len(H.edges(tempEdge[0])) >= 2 and len(H.edges(tempEdge[1])) > 2:
                    proceed2 = True
            else:
                proceed2 = True

            if proceed2 == True:
                H.add_edge(tempEdge[0], tempEdge[1])
                tempComponents = list(nx.connected_components(H))
                if len(tempComponents) > 1:
                    H = G.copy()
                else:
                    addNum -= 1
                    G = H.copy()
    return G

def convertInfo(dict2):

    keys = list(dict2.keys())
    dict3 = {}
    dict4 = copy.deepcopy(dict2)
    dict5 = {}

    for i in range(0, 50):
        index = keys.index(keys[i])
        dict3[keys[i]] = index
        
    for id, info in dict2.items():
        for x in info:
            for id1, info1 in dict3.items():
                if x == id1:
                    dict4[id][info.index(x)] = int(dict3[id1])

    i = 0
    for id, info in dict4.items():
        dict5[i] = dict4[id]
        i += 1

    return dict5

def saveGraphAsFigure(G, graphType, saveFolder, name2):
    
    if graphType == "RGG":
        pos = nx.get_node_attributes(G, "pos")
    elif graphType == "grid":
        pos = dict((n, n) for n in G.nodes())
    elif graphType == "smallworld":
        pos = nx.circular_layout(G)
    else:
        pos = nx.spring_layout(G)

    options = {
        'width': 1,
        'with_labels': False, 
    }
    nx.draw(G, **options, pos=pos)

    createRecord(nx.info(G), os.path.join(saveFolder, "graph.txt"))
    createRecord(nx.density(G), os.path.join(saveFolder, "graph.txt"))
    plt.savefig(os.path.join(saveFolder, '{} {} graph.pdf'.format(graphType, name2)), format='pdf', dpi=300, bbox_inches = 'tight')
    plt.close()

    return None