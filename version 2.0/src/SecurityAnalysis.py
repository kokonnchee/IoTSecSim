'''
This module conducts security analysis.

@author: Kok Onn Chee
'''
import csv
import collections
import os

from attackGraph import *
from attackTree import *
from harm import *
from IoTNetworkGen import *
from SaveToFile import *
from Node import *
from Network import *
from GraphsGen import *

def calculateSecMetrics(net, data, filepath, saveFolder):
    """
    Calculates data using various security metrics
    Example dict output:  

        self.timelineDict = {'startNode': [], 'endNode': [], 'startTime': [], 'endTime': [], 'compBy': []}

    Export CSV file:
        ['Attacking Node', 'Target Node', 'Start Time', 'End Time', 'Duration', 'Comp By', 'Compromise Rate', 'Attack Success Probability', 'Attack Impact', 'Attack Risk', 'MTTC', 'MTTCAN', 'Node Connection', 'NodeCS', 'NetCS']

    """

    df = pd.DataFrame(data)
    if len(df) > 0:
        ordered_df = df.sort_values(['compBy', 'startTime'], ascending=[True, True])
        my_range=range(1,len(df.index)+1)
        mttc = 0
        mttcan = 0
        nodeCS = 0
        netCS = 0
        mttcanList = []
        netCSList = []
        tempXList = []
        tempWList = []
        xList = []
        wList = []
        i = 0
        tempList = []
        newList = []
        for u, v, w, x, y, z in zip(ordered_df['startNode'], ordered_df['endNode'], ordered_df['startTime'], ordered_df['endTime'], ordered_df['compBy'], my_range):
            nc = 0
            risk = 0
            duration = x-w
            cr = 1/duration
            mttc = 1/cr
            nodeASP = 0
            nodeAIM = 0

            for a in net.nodes:
                sumASP = 0
                sumAim = 0
                if a.name == str(v):
                    nc = len(a.con)-1 #because its connected to CNC
                    for c in a.vuls: ## error if len(y.vuls) > 1 ## can use -> sum(X)/len(X) to get average
                        sumASP += c.asp
                        sumAim += c.aim
                    nodeASP = sumASP/len(a.vuls)
                    nodeAIM = sumAim/len(a.vuls)
                    risk = nodeASP * nodeAIM
                    nodeCS = nc * (nodeAIM)
            if i > 0:
                if y == tempList[-1]: #to differentiate different log/attacker
                    mttcan += mttc
                    netCS += nodeCS
                    tempXList.append(x)
                    tempWList.append(w)
                else:
                    xList.append(tempXList.copy())
                    wList.append(tempWList.copy())
                    tempXList.clear()
                    tempWList.clear()
                    tempXList.append(x)
                    tempWList.append(w)
                    temp=[]
                    temp.append(tempList[-1])
                    temp.append(mttcan)
                    mttcanList.append(temp)
                    mttcan = 0
                    netCS = 0
                    mttcan += mttc
                    netCS += nodeCS
            else:
                tempXList.append(x)
                tempWList.append(w)
                mttcan += mttc
                netCS += nodeCS
            tempList.append(y)
            netCSList.append(netCS)
            createSecurityMetricsCSVFile([z, u, v, w, x, duration, y, cr, nodeASP, nodeAIM, risk, mttc, mttcan, nc, nodeCS, netCS], filepath)
            
            i+=1
        xList.append(tempXList.copy())
        wList.append(tempWList.copy())
        calculatePropagationGrowth(saveFolder, xList, tempList)
        
        temp1=[]
        temp1.append(y)
        temp1.append(mttcan)
        mttcanList.append(temp1)
        totalTimeToCompromiseNodeAndNetwork(net, wList, xList, ordered_df['compBy'], filepath, saveFolder)
    return None

def createNetworkCompromisePercentageChart(net, filepath, folderpath):
    """
    Existing metrics: Network Compromise Percentage (NCP)
    How much percentage of the network has been compromised overall
    """
    healthy = 0
    compromised = 0
    attackers = []
    compromisedNodes = []
    keyList = []
    valueList = []
    for x in net.nodes:
        text = x.name.split("-")
        if x.canBeCompromised == False:
            if 'ag_attacker' in text or 'attacker' in text:
                text2 = x.name.split("_")
                attackers.append(text2[1])
        else:
            if x.healthy == True:
                healthy += 1
            else:
                compromised += 1
                compromisedNodes.append(x.log[1])

    if len(compromisedNodes) > 0:
        #sort and count attackers
        compromisedNodes.sort()
        counter = collections.Counter(compromisedNodes)
        values = []
        newKeys = []
        keyList = list(counter.keys())
        valueList = list(counter.values())
        if len(counter.keys()) < len(attackers):
            for x in attackers:
                found = False
                for y, z in zip(keyList, valueList):
                    if str(x) == str(y):
                        found = True
                        values.append(z)
                        newKeys.append(x)
                if found == False:
                    values.append(0)
                    newKeys.append(x)
            keyList = newKeys.copy()
            valueList = values.copy()
        generatePieChart(['Healthy Node', 'Compromised Node'], [healthy, compromised], keyList, valueList, "Network Compromise Percentage", "Network", "Compromised Node", None, 'Set1', filepath)
    else:
        keyList = attackers.copy()
        for i in range(len(keyList)):
            valueList.append(0)
        generateGeneralPieChart(['Healthy Node', 'Compromised Node'], [healthy, compromised], "Network Compromise Percentage", "Network", None, True, filepath)

    folderName = folderpath.split("/")
    if len(folderName) == 1:
        folderName = folderpath.split('\\')

    tempName = folderName[-1].split('-I')
    ncpfilename = str(tempName[0])+"+ncp.c"

    filename = os.path.join(folderpath, ncpfilename)

    createGeneralCSVFile([healthy, compromised], filename)
    createGeneralCSVFile(keyList, filename)
    createGeneralCSVFile(valueList, filename)

    return None

def networkCompromisePercentageGraphForAllSims(file, saveFolder):
    """
    Compute NCP for multiple sims
    """
    infoList = []
    try:
        os.path.isfile(file)
    except:
        print("ncp c file not found!!")

    with open(file) as csvfile:
        csvReader = csv.reader(csvfile, delimiter=',')

        for x in csvReader:
            infoList.append(x)
    
    namelist = []
    numlist = []
    healthyList = []
    xNum = []
    j = 0
    temp = None

    for i in range(0, len(infoList)):
        if i % 3 == 0:
            j += 1
            xNum.append(j)
            healthyList.append(int(infoList[i][0]))
        elif i % 3 == 1:
            for x in infoList[i]:
                if x is not None:
                    namelist.append(x)
                    temp = x
        else:
            data2 = [int(x) for x in infoList[i]]
            if len(data2) == 0:
                namelist.append(temp)
                data2.append(0)
            numlist = numlist + data2
            
    for i in range(0, len(namelist)):
        if namelist[i] == None:
            namelist[i] = temp

    ncpDict = dict(healthy = healthyList, xNum = xNum)
    keylist = list(dict.fromkeys(namelist))
    keylist.sort()

    for u in keylist:
        temp = []
        for x, y in zip(namelist, numlist):
            if str(u) == str(x):
                temp.append(y)
        ncpDict.update({u : temp})
    
    generateGeneralAreaPlot(ncpDict, "NCP", saveFolder)

    return None

def createVulnerableHostPercentageChart(net, saveFolder):
    """
    Existing metrics: Vulnerable Host Percentage (VHP)
    How much percentage of the host/nodes are vulnerable
    """

    immune = 0
    vulnerable = 0
    vulnerabilities = []
    for x in net.nodes:
        if x.canBeCompromised == False:
            pass
        else:
            if len(x.vuls) > 0:
                vulnerable += 1
                for y in x.vuls:
                    vulnerabilities.append(str(y))
            else:
                immune += 1

    if len(vulnerabilities) > 0:
        vulnerabilities.sort()
        counter = collections.Counter(vulnerabilities)
        generatePieChart(['Immune Node', 'Vulnerable Node'], [immune, vulnerable], counter.keys(), counter.values(), "Vulnerable Host Percentage", "Network", "Types of Vulnerability", None, 'tab20', saveFolder)
    else:
        generateGeneralPieChart(['Immune Node', 'Vulnerable Node'], [immune, vulnerable], "Vulnerable Host Percentage", "Network", None, True, saveFolder)
    return None

def totalTimeToCompromiseNodeAndNetwork(net, startList, endList, compByList, filepath, saveFolder):
    """
    Create a bar graph for amount of time to compromise a network with node numbers 
    """
    counter = collections.Counter(compByList)

    namelist = list(counter.keys())
    valuelist = []
    total = 0
    tempNameList = []
    tempName = []

    for x in net.nodes:
        text = x.name.split('-')
        if 'ag_attacker' in text or 'attacker' in text:
            text2 = x.name.split('_')
            tempNameList.append(text2[1])

    if len(namelist) <= len(tempNameList):
        for x in tempNameList:
            if x in namelist:
                pass
            else:
                tempName.append(x)
    
    nodeTimeList = []
    
    for x, y in zip(startList, endList):
        tempList = []
        temp = y[-1] - x[0]
        valuelist.append(temp)

        for a, b in zip(x, y):
            temp1 = b - a
            tempList.append(temp1)

        nodeTimeList.append(sum(tempList))

    nodeNumList = list(counter.values())

    if len(tempName) > 0:
        for x in tempName:
            namelist.append(x)
            valuelist.append(0.0)
            nodeNumList.append(0)
            nodeTimeList.append(0)

    generateGeneralBarGraph(namelist, valuelist, nodeNumList, " Nodes", "Amount of Time to Compromise Network", None, "", "Time(s)", 'Set1', filepath)

    total = sum(nodeTimeList)
    maxValue = max(valuelist)

    folderName = saveFolder.split("/")
    if len(folderName) == 1:
        folderName = saveFolder.split('\\')

    tempName = folderName[-1].split('-I')

    sumTfilename = str(tempName[0])+"+summary.t"
    sumCfilename = str(tempName[0])+"+summary.c"

    createRecord(total, os.path.join(saveFolder, sumTfilename))
    createRecord(maxValue, os.path.join(saveFolder, sumTfilename))
    createGeneralCSVFile(namelist, os.path.join(saveFolder, sumCfilename))
    createGeneralCSVFile(nodeTimeList, os.path.join(saveFolder, sumCfilename))
    createGeneralCSVFile(nodeNumList, os.path.join(saveFolder, sumCfilename))

    return None

def averageTimeToCompromiseNetwork(file, file2, saveFolder):
    """
    Create 2 graphs showing the average time to compromise 1 node and 1 network from multiple sims and average time to compromise 1 node by different attackers in multiple sims
    """
    try:
        os.path.isfile(file)
    except:
        print("Summary t file not found!!")


    with open(file, 'r') as f:
        data = [line.rstrip() for line in f]
        
    data = [float(i) for i in data]
    
    infoList = []

    try:
        os.path.isfile(file2)
    except:
        print("Summary c file not found!!")

    with open(file2) as csvfile:
        csvReader = csv.reader(csvfile, delimiter=',')

        for x in csvReader:
            infoList.append(x)
    
    namelist = []
    valuelist = []
    numlist = []

    for i in range(0, len(infoList)):
        if i % 3 == 0:
            for x in infoList[i]:
                namelist.append(x)
        elif i % 3 == 1:
            data1 = [float(x) for x in infoList[i]]
            valuelist = valuelist + data1
        else:
            data2 = [int(x) for x in infoList[i]]
            numlist = numlist + data2

    keylist = list(dict.fromkeys(namelist))
    keylist.sort()
    sumValue = []
    sumNode = []

    for u in keylist:
        temp = 0
        temp1 = 0
        for x, y, z in zip(namelist, valuelist, numlist):
            if str(u) == str(x):
                temp += y
                temp1 += z

        sumValue.append(temp)
        sumNode.append(temp1)

    #split odd and even data into 2 lists
    oddList = []
    evenList = []

    for i in range(0, len(data)):
        if i % 2 == 0:
            evenList.append(data[i])
        else:
            oddList.append(data[i])

    avgValue = []
    totalNodeNum = []
    avgNodeNum = []
    for x, y in zip(sumValue, sumNode):
        temp = 0
        temp1 = 0
        temp2 = 0
        if x > 0 and y > 0:
            temp = x/y
            temp1 = y
            temp2 = y/len(oddList)
            
        else:
            temp = 0 # solved zero node problem
            temp1 = 0
            temp2 = 0

        avgValue.append(temp)
        totalNodeNum.append(temp1)
        avgNodeNum.append(temp2)

    average1Node = sum(evenList) / sum(sumNode)

    average1Network = sum(oddList) / len(oddList)

    print("\nFrom ", len(oddList), " simulation(s)...") 
    print("The Mean time to compromise a node is: ", average1Node, " seconds; and")
    print("The Mean time to compromise a network is: ", average1Network, " seconds.")

    folderName = saveFolder.split("/")
    if len(folderName) == 1:
        folderName = saveFolder.split('\\')

    tempName = folderName[-1].split('-I')
    mttcfilename = str(tempName[0])+"+mttc.t"
    createRecord(folderName[-1], os.path.join(saveFolder, mttcfilename))
    createRecord(average1Node, os.path.join(saveFolder, mttcfilename))
    createRecord(average1Network, os.path.join(saveFolder, mttcfilename))

    for x in keylist:
        createRecord(x, os.path.join(saveFolder, mttcfilename))

    for x in totalNodeNum:
        createRecord(x, os.path.join(saveFolder, mttcfilename))

    for x in avgNodeNum:
        createRecord(x, os.path.join(saveFolder, mttcfilename))

    generateGeneralBarGraph(["1 Node", "1 Network"], [average1Node, average1Network], None, None, "From "+str(len(oddList))+" simulation(s), the Mean time to compromise", "Mean time to compromise by 1 Node 1 Network", "", "Time(s)", 'Set2', saveFolder)
    generateGeneralBarGraph(keylist, avgValue, None, None, "From "+str(len(oddList))+" simulation(s), the Mean time for * to compromise 1 node", "Mean time to compromise by attackers",  "", "Time(s)", 'Set1', saveFolder)
    
    combineImage([os.path.join(saveFolder, 'Mean time to compromise by 1 Node 1 Network.png'), os.path.join(saveFolder, 'Mean time to compromise by attackers.png')], "Mean time to compromise", saveFolder)

    generateGeneralBarGraph(keylist, totalNodeNum, None, None, "From "+str(len(oddList))+" simulation(s), total nodes compromised by each attacker", "Total nodes compromised by attackers",  "", "Numbers", 'Set1', saveFolder)
    generateGeneralBarGraph(keylist, avgNodeNum, None, None, "From "+str(len(oddList))+" simulation(s), average nodes compromised by each attacker", "Average nodes compromised by attackers",  "", "Numbers", 'Set1', saveFolder)

    combineImage([os.path.join(saveFolder, 'Total nodes compromised by attackers.png'), os.path.join(saveFolder, 'Average nodes compromised by attackers.png')], "Total and Average Nodes Compromised", saveFolder)

    return None

def computeNumberOfIoTNodes(net):
    """
    Get IoT node numbers
    """
    total = 0

    for u in net.nodes:
        text = u.name.split("-")
        # if 'ag_attacker' in text:
        #     total += 0
        # elif 'ag_CNC' in text:
        #     total += 0
        if 'ag_attacker' in text or 'ag_CNC' in text or 'ag_server' in text or 'ag_router' in text:
            pass
        else:
            total += 1

    return total

def computeNumberOfCompromisedNodes(net):
    """
    Get number of compromised nodes
    """
    num = 0
    for node in net.nodes:
        if node.comp == True:
            num += 1
    
    return num

def computePercentageOfCompromisedNodes(net):
    """
    Compute percentage of compromised nodes
    """
    total1 = computeNumberOfIoTNodes(net)
    total2 = computeNumberOfCompromisedNodes(net)

    percent = total2 / total1 * 100

    return percent

def createInOutTrafficTimelineCSV(data, filepath):
    """
    Save in out traffic to CSV file
    """

    for i in range(len(data)):
        createInOutTrafficCSVFile(i+1, data[i], filepath)

    j = 1
    for x in data:
        if x[0] == "IN":
            createInOutTrafficCSVFileSimple(j, [1, x[3], x[4]], filepath)
            j += 1
        elif x[0] == "OUT":
            createInOutTrafficCSVFileSimple(j, [-1, x[3], x[4]], filepath)
            j += 1
        elif x[0] == "INOUT":
            createInOutTrafficCSVFileSimple(j, [1, x[3], x[4]], filepath)
            createInOutTrafficCSVFileSimple(j+1, [-1, x[3], x[4]], filepath)
            j += 2
        else:
            pass
    return None

def calculatePropagationGrowth(saveFolder, end, compBy):
    """
    Compute propagation growth
    """

    atkerCounter = collections.Counter(compBy)
    atker = list(atkerCounter.keys())

    for a, b in zip(end, atker):

        tempList = []

        for x in a:
            num = round(x)
            if num < x:
                num += 1
            tempList.append(num)

        values = []
        newKeys = []

        tempNum = tempList[-1]+1
        for i in range(tempNum):
            newKeys.append(str(i))

        for x in newKeys:
            num = 0
            for y in tempList:
                if str(x) == str(y):
                    num += 1
            values.append(num)

        totalValues = []
        temp = 0
        for x in values:
            temp += x
            totalValues.append(temp)

        folderName = saveFolder.split("/")
        if len(folderName) == 1:
            folderName = saveFolder.split('\\')

        tempName = folderName[-1].split('-I')

        growthfilename = str(tempName[0])+"+growth.t"
        growthfilename2 = str(tempName[0])+"+growthV.csv"
        growthfilename3 = str(tempName[0])+"+growthTV.csv"
        growthfilename4 = str(tempName[0])+"+growthReal.csv"


        createRecord(str(b), os.path.join(saveFolder, growthfilename))

        createRecord("keys", os.path.join(saveFolder, growthfilename))
        createGeneralCSVFile(newKeys, os.path.join(saveFolder, growthfilename))
        
        createRecord("values", os.path.join(saveFolder, growthfilename))
        createGeneralCSVFile(values, os.path.join(saveFolder, growthfilename))

        createRecord("totalValues", os.path.join(saveFolder, growthfilename))
        createGeneralCSVFile(totalValues, os.path.join(saveFolder, growthfilename))

        createGeneralCSVFile(values, os.path.join(saveFolder, growthfilename2))
        createGeneralCSVFile(totalValues, os.path.join(saveFolder, growthfilename3))
        createGeneralCSVFile(a, os.path.join(saveFolder, growthfilename4))

    return None

# def calculateAttackSurface(net, previousNum, saveFolder, asfilename):
#     """
#     Compute attack surface
#     """
#     num = 0
#     newNum = 0
#     for x in net.nodes:
#         if x.canBeCompromised == True:
#             for y in x.realPort:
#                 for z in x.realPort[y]["Vuln"]:
#                     num += 1

#     if previousNum == 0:
#         print("Initial AS : ", num)
#     else:
#         newNum = previousNum - num
#         print("Current AS : ", num)
#         ASPer = (num/previousNum)*100
#         ASRed = ASPer - 100
#         print("Current AS (%) : ", "{0:.2f}".format(ASPer), "%")
#         print("AS Reduction : ", newNum, " (", "{0:.2f}".format(ASRed), "%)")

#     if asfilename != None:
#         createRecord("Initial AS", os.path.join(saveFolder, asfilename))
#         createRecord(previousNum, os.path.join(saveFolder, asfilename))
#         createRecord("Current AS", os.path.join(saveFolder, asfilename))
#         createRecord(num, os.path.join(saveFolder, asfilename))
#         createRecord("Current AS (%)", os.path.join(saveFolder, asfilename))
#         createRecord("{0:.2f}".format(ASPer), os.path.join(saveFolder, asfilename))
#         createRecord("AS Reduction", os.path.join(saveFolder, asfilename))
#         createRecord(newNum, os.path.join(saveFolder, asfilename))
#         createRecord("{0:.2f}".format(ASRed), os.path.join(saveFolder, asfilename))

#     return num

