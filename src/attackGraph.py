"""
This module constructs attack graph and simulates attack on the IoT network with or without defence.

@co-authors: Kok Onn Chee, Mengmeng Ge
"""

from random import choice
from math import *
from operator import getitem

from Node import *
from Network import *
from Vulnerability import *
from SaveToFile import *
from GraphsGen import *
from SecurityAnalysis import *
from ConventionalDefence import *
  
class gnode(node):
    """
    Create attack graph node object.
    """
    def __init__(self, name):
        super(gnode, self).__init__(name)
        #Store the network node
        self.n = None
        #Store the Simulation value used in security analysis
        self.val = 0
        self.vuls = []
        self.type = None
        self.pro = None
        #Used to check whether the node is included in the attack path or not
        self.inPath = 0
        self.subnet = []

        #added by KO Chee
        self.carryExploit = []
        self.listofBots = []
        self.cncAtkerList = []
        self.atkInfoDict = {}
        self.id = None
        self.hopValue = None
        self.comp = False
        self.nextTargetNode = []
        self.CNCNode = []
        self.goal = None
        self.coop = False
        self.botCoop = False
        self.isCompBy = None
        self.mode = None
        self.group = None
        self.cr = 0
        self.asp = 0
        self.aim = 0
        self.cycle = 0
        self.active = False
        self.scanTime = 0
        self.accessTime = 0
        self.reportTime = 0
        self.infectionTime = 0
        self.accumulatedTime = 0
        self.timeline = []
        self.status = 0
        self.attackData = []
        self.signature = []
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
        self.CNCMemory = {}
        self.avoidList = {}
        self.dataCollection = []
        self.model = None
        self.position = []
        self.canBeCompromised = None
        
    def __str__(self):
        return self.name
    
               
class gVulNode(vulNode):
    """
    Create attack graph vulnerability object.
    """
    def __init__(self, name):
        super(gVulNode, self).__init__(name)
        #Store the vulnerability node
        self.n = None
        #Store the Simulation value used in security analysis
        self.val = 0
        self.inPath = 0
        
    def __str__(self):
        return self.name
                              

class ag(network):
    """
    Create attack graph.
    """
    #Construct the attack graph
    def __init__(self, network, val, *arg):
        super(ag, self).__init__()        
        self.path = [] 
        #Store all possible paths from start to end
        self.allpath = []
        self.isAG = 1
        self.subnets = network.subnets  #All subnets in the network
        self.vuls = network.vuls        #All vuls in the network

        # added by KO Chee
        self.atkerList = []
        self.tgtList = []
        self.tempLongPath = []
        self.longPath = []
        self.time = 0
        self.totalVulnerableNodes = 0
        self.totalInfectedNodes = 0
        self.infectedNodesList = []
        self.healthyNodeNum = []
        self.rate = []
        self.previousGoal = 0
        self.currentGoal = 0
        self.repeat = 0
        self.AtkerTimeDataDict = network.AtkerTimeDataDict
        self.timelineDict = {'startNode': [], 'endNode': [], 'startTime': [], 'endTime': [], 'compBy': []}
        self.defMode = network.defMode
        self.saveSimDir = network.saveSimDir
        self.saveFolder = network.saveFolder
        self.entryPointNode = network.entryPointNode
        self.initialCNC = ["CNCX"]
        self.tempcncInstallDict = {'startTime': None, 'cncNodeNData': [], 'atkerSign': None}
        self.cncInstallDict = dict(zip(self.initialCNC, [self.tempcncInstallDict]))
        self.failProcess = []

        #Instantiate nodes in attack graph using network info
        for u in [network.s, network.e] + network.nodes:
            if u is not None:   
                #For vulnerability
                if type(u) is vulNode:
                    gn = gVulNode('ag_' + str(u.name))
                    gn.privilege = u.privilege
                    gn.val = u.val

                elif type(u) is CommandNControl:
                    gn = gnode('ag_' + str(u.name))
                    gn.id = u.id
                    gn.cncAtkerList = u.cncAtkerList
                    gn.atkInfoDict = u.atkInfoDict
                    gn.group = u.group
                    gn.timeline = u.timeline
                    gn.attackData = u.attackData
                    gn.status = u.status
                    gn.goal = u.goal
                    gn.signature = u.signature
                    gn.IPv4Add = u.IPv4Add
                    gn.scanPort = u.scanPort
                    gn.content = u.content
                    gn.CNCMemory = u.CNCMemory
                    gn.position = u.position
                    gn.avoidList = u.avoidList
                    gn.canBeCompromised = u.canBeCompromised
                #For node
                else:
                    gn = gnode('ag_' + str(u.name))
                    gn.id = u.id
                    gn.position = u.position
                    gn.canBeCompromised = u.canBeCompromised
                        
                    #Assign default value to attacker node
                    if u.isStart == True:
                        gn.val = -1
                    else:
                        gn.val = val

                    if [u] in network.atk:
                        gn.carryExploit = u.carryExploit
                        gn.CNCNode = u.CNCNode
                        gn.nextTargetNode = u.nextTargetNode
                        gn.goal = u.goal
                        gn.coop = u.coop
                        gn.botCoop = u.botCoop
                        gn.mode = u.mode
                        gn.group = u.group
                        gn.cycle = u.cycle
                        gn.active = u.active
                        gn.accumulatedTime = u.accumulatedTime
                        gn.timeline = u.timeline
                        gn.scanTime = u.scanTime
                        gn.accessTime = u.accessTime
                        gn.reportTime = u.reportTime
                        gn.infectionTime = u.infectionTime
                        gn.accumulatedTime = u.accumulatedTime
                        gn.status = u.status
                        gn.attackData = u.attackData
                        gn.signature = u.signature
                        gn.meanTime = u.meanTime
                        gn.targetPort = u.targetPort
                        gn.IPv4Add = u.IPv4Add
                        gn.scanPort = u.scanPort
                        gn.protocol = u.protocol
                        gn.content = u.content
                        gn.scanMethod = u.scanMethod
                    else:
                        if type(u) is not CommandNControl and type(u) is not attacker:
                            gn.vuls = u.vul.nodes.copy()
                            self.totalVulnerableNodes += 1
                            gn.hopValue = u.hopValue
                            gn.isCompBy = u.isCompBy
                            gn.group = u.group
                            gn.botCoop = u.botCoop
                            gn.status = u.status
                            gn.attackData = u.attackData
                            gn.timeline = u.timeline
                            gn.nextTargetNode = u.nextTargetNode
                            gn.coop = u.coop
                            gn.scanTime = u.scanTime
                            gn.accessTime = u.accessTime
                            gn.reportTime = u.reportTime
                            gn.infectionTime = u.infectionTime
                            gn.accumulatedTime = u.accumulatedTime
                            gn.CNCNode = u.CNCNode
                            gn.log = u.log
                            gn.meanTime = u.meanTime
                            gn.realPort = u.realPort
                            gn.compromisedPort = u.compromisedPort
                            gn.IPv4Add = u.IPv4Add
                            gn.content = u.content

                            if type(u) is decoyNode:
                                gn.dataCollection = u.dataCollection
                                gn.model = u.model

                    if u is not network.s and u is not network.e:
                        gn.type = u.type
                        gn.pro = u.pro
                        gn.critical = u.critical
                        gn.comp = u.comp
                        gn.prev_comp = u.prev_comp
                        
                gn.n = u
                
                #Assign default value to start and end in network
                if u in [network.s, network.e]:
                    gn.val = -1    
                        
                self.nodes.append(gn)

        #Initialize connections for attack graph node   
        for u in self.nodes:       
            for v in u.n.con:
                #For upper layer
                if len(arg) is 0:
                    for t in self.nodes:
                        if t.n.name == v.name:
                            u.con.append(t)
                #For lower layer
                else:
                    if arg[0] >= v.privilege:
                        for t in self.nodes:
                            if t.n is v:
                                u.con.append(t) 
        
        #Initialize start and end in attack graph   
        for u in self.nodes:
            if u.n is network.s:
                self.s = u    
            if u.n is network.e:
                self.e = u
            if [u.n] in network.atk:
                self.atk.append([u])
            if [u.n] in network.tgt:
                self.tgt.append([u])
        
        #Remove start and end from nodes in attack graph      
        if self.s is not None:
            self.nodes.remove(self.s)
        if self.e is not None:
            self.nodes.remove(self.e)           


## added and modified by KO Chee----------------------------------------------
    def simAtk(self, attacksDict, attackerDict, targetDict, hopValueDict, fw):
        """
        Simulate attack on IoT network
        """
        val = 0
        
        allGoal = len(attackerDict)
        goalAchieved = False

        tempPath = []
        tempPath2 = []

        CNC = []
        for x in self.nodes:
            text = x.name.split("-")
            if 'ag_CNC' in text:
                CNC.append(x)

        attacksDict = self.sortDict(attacksDict)

        firewallStatus = False
        if self.defMode["Firewall"]["operational"] == True:
            firewallStatus = True
            if self.defMode["Firewall"]["rule"] is not None:
                for id, info in self.defMode["Firewall"]["rule"].items():
                    fw.createNewRuleset("firewall", str(id), self.defMode["Firewall"]["rule"][id])

        idsStatus = False
        if self.defMode["IDS"]["operational"] == True:
            if self.defMode["IDS"]["mode"] == 1:
                logType = ["all", "alert"]
            idsStatus = True
            if self.defMode["IDS"]["rule"] is not None:
                for id, info in self.defMode["IDS"]["rule"].items():
                    fw.createNewRuleset("ids", str(id), self.defMode["IDS"]["rule"][id])

        ipsStatus = False
        if self.defMode["IPS"]["operational"] == True:
            ipsStatus = True
            if self.defMode["IPS"]["rule"] is not None:
                for id, info in self.defMode["IPS"]["rule"].items():
                    fw.createNewRuleset("ips", str(id), self.defMode["IPS"]["rule"][id])

        decoyStatus = False
        if self.defMode["Deception"]["operational"] == True:
            decoyStatus = True

        for x in attacksDict:
            compareAT, getAvgTime = self.generatePhaseTime(attacksDict)
            maxAT = max(getAvgTime)
            maxCAT = max(compareAT)

            for u in attacksDict[x]["attackerNode"]:
                temp = []
                csvFilename = os.path.join(self.saveSimDir, "NodeSARIInfo.csv")
                createCSVFile([u.name, u.scanTime, u.accessTime, u.reportTime, u.infectionTime], ['Node', 'scanTime', 'accessTime', 'reportTime', 'infectionTime'], csvFilename)
                tempAvgTime = (u.scanTime + u.accessTime + u.reportTime + u.infectionTime)/4

                text = u.name.split("-")
                if (u.accumulatedTime + tempAvgTime) < (maxCAT + maxAT) or len(compareAT) == 1: 

                    ###############################################
                    if u.status == 1: # status = '1' = SCANNING Phase
                        targetFound = False
                        tempRouter = None
                        goThruAP = False
                        targetBlockedFW1 = False
                        targetBlockedIPS1 = False
                        replyMsg = ""
                        SSStatus = None
                        if len(u.signature) > 0:
                            tempText = "ag_" + str(u.signature[1])
                        else:
                            tempText = "ag_" + str(u.log[1])
                        uport = ""
                        vport = ""
                        
                        if u.mode == "global":
                            if u.accumulatedTime == 0 or 'ag_attacker' in text:
                                if len(targetDict[tempText]["targets"]) > 0:
                                    targetDict[tempText]["remaining"] = targetDict[tempText]["targets"].copy()

                            if len(targetDict[tempText]["remaining"]) > 0:
                                tempList = targetDict[tempText]["remaining"]
                                if u.accumulatedTime == 0 or 'ag_attacker' in text:
                                    tempRouter, targetFound, uport, vport = self.scanForInitialTarget(u.mode, u, tempList, u.nextTargetNode, fw, firewallStatus, ipsStatus)
                                else:
                                    u.nextTargetNode.clear()
                                    targetFound, SSStatus, uport, vport, goThruAP  = self.scanForSubsequentTarget(u.mode, u, tempList, u.nextTargetNode, fw)
                            else:
                                print("No target found!!1")
                                pass
                            if targetFound == True:
                                if len(u.nextTargetNode) == 3:
                                    if str(u.nextTargetNode[0].name) in targetDict[tempText]["remaining"]:
                                        targetDict[tempText]["remaining"].remove(str(u.nextTargetNode[0].name))
                                    targetDict[tempText]["onHold"].append(str(u.nextTargetNode[0].name))
                                elif len(u.nextTargetNode) == 4:
                                    if str(u.nextTargetNode[1].name) in targetDict[tempText]["remaining"]:
                                        targetDict[tempText]["remaining"].remove(str(u.nextTargetNode[1].name))
                                    targetDict[tempText]["onHold"].append(str(u.nextTargetNode[1].name))
                        else: #for local learning
                            if u.accumulatedTime == 0 or 'ag_attacker' in text:
                                tempRouter, targetFound, uport, vport  = self.scanForInitialTarget(u.mode, u, None, u.nextTargetNode, fw, firewallStatus, ipsStatus)
                            else:
                                u.nextTargetNode.clear()
                                targetFound, SSStatus, uport, vport, goThruAP  = self.scanForSubsequentTarget(u.mode, u, None, u.nextTargetNode, fw)

                        if targetFound == True:
                            u.accumulatedTime += u.scanTime
                            attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                            u.status = 2
                            temp.append("SS")
                            temp.append(u.scanTime)
                            temp.append(u.accumulatedTime)
                            u.timeline.append(temp)
                        else:
                            u.accumulatedTime += u.scanTime/2
                            attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                            if SSStatus == False:
                                u.status = 0
                            else:
                                if 'ag_attacker' in text: #initial scanning
                                    for y in attackerDict:
                                        if str(y) == u.name:
                                            attackerDict[y]["attempt"] += 1
                                            if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
                                                u.status = 0
                                            break
                                else:
                                    if SSStatus == None:
                                        u.status = 0
                                        
                            temp.append("SF")
                            temp.append(u.scanTime)
                            temp.append(u.accumulatedTime)
                            u.timeline.append(temp)
                            
                        if tempRouter is not None and goThruAP == False:
                            goThruAP = True

                        if idsStatus == True and goThruAP == True: 
                            triggerAlert1 = False
                            if targetFound == True:
                                if SSStatus == True:
                                    triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", u.nextTargetNode[1].IPv4Add, u.nextTargetNode[2], u.content[0], u.scanTime], logType, self.saveSimDir)
                                    port = u.nextTargetNode[2]
                                    vtarget = u.nextTargetNode[1]
                                else:
                                    triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", u.nextTargetNode[0].IPv4Add, vport, u.content[0], u.scanTime], logType, self.saveSimDir)
                                    port = vport
                                    vtarget = u.nextTargetNode[0]
                            else:
                                # for failed scan
                                triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", "any", "any", u.content[0], u.scanTime], logType, self.saveSimDir)
                                port = None
                                vtarget = None

                            if triggerAlert1 == True:
                                self.createNewRule(u, fw, vtarget, port)

                    ###############################################
                    elif u.status == 2: # status = '2' = ACCESSING Phase
                        errorStatus = False
                        goThruAP = False
                        if len(u.nextTargetNode) > 0:
                            targetBlockedFW2 = False
                            targetBlockedIPS2 = False
                            tempTarget = None
                            tempTargetIP = None
                            tempTargetPort = None
                            tempRouter = None
                            success = False
                            data = ""
                            portNum = ""

                            if len(u.nextTargetNode) == 3:
                                tempTarget = u.nextTargetNode[0]
                                tempTargetPort = u.nextTargetNode[1]
                                tempRouter = u.nextTargetNode[2]
                            elif len(u.nextTargetNode) == 4:
                                tempTarget = u.nextTargetNode[1]
                                tempTargetPort = u.nextTargetNode[2]
                                tempRouter = u.nextTargetNode[3]
                            else:
                                errorStatus = True
                                print("Error!!", len(u.nextTargetNode), u.nextTargetNode)
                            
                            textR = tempRouter.name.split('-')
                            if 'ag_router' in textR or 'router' in textR:
                                pass
                            else:
                                tempRouter = None

                            if errorStatus == False:
                                tempTargetIP = tempTarget.IPv4Add

                            if firewallStatus == True and 'ag_attacker' in text:
                                targetBlockedFW2 = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, tempTargetPort, tempTargetIP, tempTargetPort])

                            ## IPS is deployed before the access process
                            if ipsStatus == True and 'ag_attacker' in text:
                                targetBlockedIPS2, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], self.saveSimDir)
                                    
                            if targetBlockedIPS2 == True or targetBlockedFW2 == True:
                                success = False
                                if targetBlockedIPS2 == True:
                                    print("Access has been blocked by IPS!")
                                    pass

                                if targetBlockedFW2 == True:
                                    print("Access has been denied by firewall!")
                                    pass
                            else:
                                if errorStatus == False:
                                    success, portNum, data = self.bruteForceAttackForCredential(u, tempTarget, fw)
                                    goThruAP = True

                            ## IDS is deployed after the access process
                            if goThruAP == True and idsStatus == True: 
                                triggerAlert2 = False
                                triggerAlert2 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], logType, self.saveSimDir)

                                if triggerAlert2 == True:
                                    self.createNewRule(u, fw, tempTarget, tempTargetPort)

                            if success == True:
                                tempAttackData = []
                                u.accumulatedTime += u.accessTime
                                attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                u.status = 3
                                temp.append("AS")
                                temp.append(u.accessTime)
                                temp.append(u.accumulatedTime)
                                u.timeline.append(temp)
                                tempAttackData.append(u)
                                tempAttackData.append(tempTarget)
                                tempAttackData.append(success)
                                tempAttackData.append(portNum)
                                tempAttackData.append(data)
                                tempAttackData.append(u.content)
                                tempAttackData.append(tempRouter)
                                u.attackData = tempAttackData
                            else:
                                u.accumulatedTime += u.accessTime
                                attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                u.status = 1
                                temp.append("AF")
                                temp.append(u.accessTime)
                                temp.append(u.accumulatedTime)
                                u.timeline.append(temp)

                                tempFP = []
                                tempFP.append("AF")
                                tempFP.append(self.simplifyNodeName(u.name)[0])
                                tempFP.append(self.simplifyNodeName(tempTarget.name)[0])
                                tempFP.append(u.accumulatedTime)

                                self.failProcess.append(tempFP)

                                #To avoid infinite scanning & accessing
                                if 'ag_attacker' in text:
                                    for y in attackerDict:
                                        if str(y) == u.name:
                                            attackerDict[y]["attempt"] += 1
                                            
                                            if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
                                                u.status = 0
                                                
                                            break
                                    if u.mode == "global":
                                        if len(targetDict[u.name]["targets"]) > 0:
                                            self.changeListOrder(targetDict[u.name]["targets"])
                                else:
                                    temp = 0
                                    stopScan = False
                                    if len(u.timeline) >= 25:
                                        for i in range(1, len(u.timeline)):
                                            if u.timeline[0-i][0] == "AF":
                                                temp+=1
                                            if temp > 5:
                                                stopScan = True
                                                break
                                    if stopScan == True:
                                        if tempTarget.name in u.CNCNode[0].avoidList:
                                            if portNum in u.CNCNode[0].avoidList[tempTarget.name]["port"]:
                                                if u.CNCNode[0].avoidList[tempTarget.name]["num"] >= len(tempTarget.realPort):
                                                    u.CNCNode[0].avoidList[tempTarget.name]["avoid"] = True
                                                else:
                                                    u.CNCNode[0].avoidList[tempTarget.name]["num"] += 1
                                            else:
                                                u.CNCNode[0].avoidList[tempTarget.name]["port"].append(portNum)
                                                u.CNCNode[0].avoidList[tempTarget.name]["num"] += 1
                                                if u.CNCNode[0].avoidList[tempTarget.name]["num"] >= len(tempTarget.realPort):
                                                    u.CNCNode[0].avoidList[tempTarget.name]["avoid"] = True
                                        else:
                                            u.CNCNode[0].avoidList[tempTarget.name] = {"port" : [str(portNum)], "num" : 1, "avoid" : False}
                            u.nextTargetNode.clear()
                            u.targetPort.clear()
                        else:
                            print("No target found!!2")

                    ###############################################
                    elif u.status == 3: # status = '3' = REPORT Phase
                        
                        targetBlocked2 = False
                        
                        if targetBlocked2 == True:
                            u.accumulatedTime += u.reportTime#/2
                            attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                            
                            u.status = 1
                            temp.append("RF")
                            temp.append(u.reportTime)
                            temp.append(u.accumulatedTime)
                            u.timeline.append(temp)
                        else:
                            if len(u.attackData) > 0:
                                self.reportToCNCServer(u.attackData, u.CNCNode)
                                u.accumulatedTime += u.reportTime
                                attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                temp1 = [u.CNCNode[0], u.attackData]
                                
                                if 'ag_attacker' in text:
                                    u.status = 0 #Proceed to 0 for ag_attacker (1st time)
                                else:
                                    u.status = 1
                                temp.append("RS")
                                temp.append(u.reportTime)

                                temp.append(u.accumulatedTime)
                                u.timeline.append(temp)

                                tempAttackers = []
                                tempAttackers.append(u.name)

                                if len(u.signature) > 0:
                                    tempLog = u.signature
                                else:
                                    tempLog = u.log

                                tempcncInstallDict = {'startTime': u.accumulatedTime, 'cncNodeNData': temp1, 'atkerSign': tempLog}

                                temp1cncInstallDict = dict(zip(tempAttackers, [tempcncInstallDict]))
                                
                                self.cncInstallDict.update(temp1cncInstallDict)

        ###############################################
        lastTime = int(self.time)

        if len(self.cncInstallDict) > 1 and "CNCX" in self.cncInstallDict:
            self.cncInstallDict.pop("CNCX")

        if len(self.cncInstallDict) > 1:
            self.cncInstallDict = self.sortDict2(self.cncInstallDict)

        # status = '4' = INSTALL Phase (DOWNLOAD BINARY INSTALL MALWARE)
        if "CNCX" not in self.cncInstallDict:
            for a in self.cncInstallDict:
                botISpatched = None
                x = self.cncInstallDict[a]['cncNodeNData'][0]
                if len(self.cncInstallDict[a]['cncNodeNData'][1]) > 0:
                    y = self.cncInstallDict[a]['cncNodeNData'][1].copy()
                    temp = []
                    u = y[0]
                    v = y[1]
                    portNum = y[3]
                    content = y[5]
                    tempAP = y[6]
                    tempPath = []
                    lastCheck = False
                    targetBlockedFW3 = False
                    targetBlockedIPS3 = False

                    ## Firewall is deployed before CNC to target node
                    if firewallStatus == True:
                        targetBlockedFW3 = fw.firewall(tempAP, [x.protocol, x.IPv4Add, portNum, v.IPv4Add, portNum])

                    ## IPS is deployed before CNC to target node
                    if ipsStatus == True:
                        targetBlockedIPS3, replyMsg = fw.intrusionPreventionSystem([u.protocol, x.IPv4Add, portNum, "->", v.IPv4Add, portNum, content[2], u.infectionTime], self.saveSimDir)

                    if targetBlockedFW3 == True or targetBlockedIPS3 == True:
                        self.changeScanPortOrder(u.scanPort)
                        if v.name in x.CNCMemory:
                            x.CNCMemory[v.name] += 1
                        else:
                            x.CNCMemory[v.name] = 1 
                    else:
                        if v.realPort[portNum]["open"] == True:
                            if v.healthy == True:
                                if v in x.listofBots:
                                    lastCheck = False
                                else:
                                    lastCheck = True
                            else:
                                if u.group == v.group:
                                    lastCheck = False
                                else:
                                    lastCheck = True
                        else:
                            lastCheck = False

                    if len(u.signature) > 0:
                        tempText = "ag_" + str(u.signature[1])
                    elif len(u.log) > 0 and u.propagation == True:
                        tempText = "ag_" + str(u.log[1])
                    elif len(self.cncInstallDict[a]['atkerSign']) > 0:
                        tempText = "ag_" + str(self.cncInstallDict[a]['atkerSign'][1])
                        print(u.name, " was patched! ", u.accumulatedTime, u.infectionTime)
                        botISpatched = tempText
                    else:
                        print(u.name, " was patched! Attack failed.")
                        lastCheck = False

                    if lastCheck == True:
                        tempPath = self.downloadBinaryInstallMalware(u, v, portNum, x, tempPath, fw, botISpatched)
                        if tempPath is not None:
                            self.tempLongPath.append(tempPath)
                            tempPath2.append(tempPath)
                            
                        v.accumulatedTime = u.accumulatedTime + u.infectionTime
                        temp.append("IS")
                        temp.append(u.infectionTime)
                        temp.append(v.accumulatedTime)
                        v.timeline.append(temp)
                        tempT = u.timeline[-3]
                        
                        if str(v.name) in targetDict[tempText]["onHold"]:
                            targetDict[tempText]["onHold"].remove(str(v.name))
                            if v.name in targetDict[tempText]["compromised"]:
                                pass
                            else:
                                targetDict[tempText]["compromised"].append(str(v.name))

                        self.timelineDict['startNode'].append(u.name)
                        self.timelineDict['endNode'].append(v.name)
                        temp1 = []
                        temp1.append(v)
                        temp1.append(portNum)
                        startTime = tempT[2] - tempT[1]

                        self.timelineDict['startTime'].append(startTime)
                        self.timelineDict['endTime'].append(v.accumulatedTime)
                        text2 = v.name.split('+')
                        tempData = ""
                        if 'ag_decoy' in text2 or 'decoy' in text2:
                            if len(u.signature) > 0:
                                self.timelineDict['compBy'].append(u.signature[1])
                                tempData = u.signature[1]
                            elif len(u.log) > 0:
                                self.timelineDict['compBy'].append(u.log[1])
                                tempData = u.log[1]
                            else:
                                self.timelineDict['compBy'].append(botISpatched)
                                tempData = botISpatched
                        else:
                            self.timelineDict['compBy'].append(v.log[1])
                            tempData = v.log[1]

                        if tempPath is not None:
                            x.attackData.remove(y)
                            for z in attackerDict:
                                text = z.split("_") 
                                if str(tempData) in text:
                                    attackerDict[z]["path"].append(tempPath)
                                    attackerDict[z]["path"].append(v.accumulatedTime)
                        text = u.name.split("-")
                        if 'ag_attacker' in text:
                            disconnectTwoWays(u, v)

                        self.time += 1
                        createGraph(self, "propagation {}".format(str(self.time)), self.saveSimDir)
                    else:
                        temp.append("IF")
                        temp.append(u.name)
                        temp.append(v.name)
                        temp.append(u.accumulatedTime)
                        x.timeline.append(temp)
                        x.attackData.remove(y)

                        tempFP = []
                        tempFP.append("IF")
                        tempFP.append(self.simplifyNodeName(u.name)[0])
                        tempFP.append(self.simplifyNodeName(v.name)[0])
                        tempFP.append(u.accumulatedTime + u.infectionTime)

                        self.failProcess.append(tempFP)

                        #check if it is the initial target or not
                        text = u.name.split("-")
                        
                        if str(v.name) in targetDict[tempText]["onHold"]:
                            targetDict[tempText]["remaining"] = [v.name] + targetDict[tempText]["remaining"]
                            targetDict[tempText]["onHold"].remove(str(v.name))

                        #To avoid infinite scanning
                        if 'ag_attacker' in text: 
                            for y in attackerDict:
                                if str(y) == u.name:
                                    attackerDict[y]["attempt"] += 1
                                    if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
                                        u.status = 0
                                        print("6666666666666")
                                    else:
                                        u.status = 1
                        else:
                            self.changeScanPortOrder(u.scanPort)

                        if len(x.CNCMemory) > 0:
                            if x.IPv4Add in x.CNCMemory:
                                if x.CNCMemory[x.IPv4Add]["attempt"] >= 20: #200
                                    u.status = 0

                            if v.name in x.CNCMemory:
                                if x.CNCMemory[v.name] >= 5:
                                    if len(u.signature) > 0:
                                        tempText = "ag_" + str(u.signature[1])
                                    else:
                                        tempText = "ag_" + str(u.log[1])
                                    if u.mode == "global":
                                        if v.name in targetDict[tempText]["remaining"]:
                                            targetDict[tempText]["remaining"].remove(str(v.name))
                                            
                        if v.name in x.avoidList:
                            if portNum in x.avoidList[v.name]["port"]:
                                if x.avoidList[v.name]["num"] >= len(v.realPort):
                                    x.avoidList[v.name]["avoid"] = True
                                else:
                                    x.avoidList[v.name]["num"] += 1
                            else:
                                x.avoidList[v.name]["port"].append(portNum)
                                x.avoidList[v.name]["num"] += 1
                                if x.avoidList[v.name]["num"] >= len(v.realPort):
                                    x.avoidList[v.name]["avoid"] = True
                        else:
                            x.avoidList[v.name] = {"port" : [str(portNum)], "num" : 1, "avoid" : False}

                    ## IPS is deployed after CNC to target node
                    if idsStatus == True:
                        triggerAlert3 = False
                        triggerAlert3 = fw.intrusionDetectionSystem([u.protocol, x.IPv4Add, portNum, "->", v.IPv4Add, portNum, content[2], u.infectionTime], logType, self.saveSimDir)
                        if triggerAlert3 == True:
                            self.createNewRule(x, fw, v, portNum)

        #Check goal method
        for x in CNC:
            for y in x.goal:
                m = 0
                if y[2] == False:
                    for z in self.nodes:
                        text = z.name.split("-")
                        if 'ag_attacker' in text or 'ag_CNC' in text:
                            pass
                        else:
                            if len(z.log) > 0:
                                if str(z.log[1]) == str(y[0]):
                                    m += 1
                    if m >= y[1]:
                        allGoal -= 1
                        for a in self.nodes:
                            if len(a.log) > 0:
                                if str(a.log[1]) == str(y[0]):
                                    a.status = 0
                else:
                    allGoal -= 1
        # need to update the attacker pool if new infection found
        tempDict = {}

        for u in self.nodes:
            if u.status > 0:
                tempAttackers = []
                tempAttackers.append(u.name)
                temp = None
                if len(u.signature) > 0:
                    temp = u.signature
                else:
                    temp = u.log
                tempAttacksdict = dict(attackerNode = [u], accumulatedTime = u.accumulatedTime, timeline = u.timeline, meanTime = u.meanTime, ownBy = temp)

                if len(tempDict) == 0:
                    tempDict = dict(zip(tempAttackers, [tempAttacksdict]))
                else:
                    temp = dict(zip(tempAttackers, [tempAttacksdict]))
                    tempDict.update(temp)

        if tempDict is not None:
            attacksDict = tempDict

        ## repeat the process
        self.initialCNC = ["CNCX"]
        self.tempcncInstallDict = {'startTime': None, 'cncNodeNData': [], 'atkerSign': None}
        self.cncInstallDict = dict(zip(self.initialCNC, [self.tempcncInstallDict]))

        self.longPath.append(tempPath2)
        tempNo = computeNumberOfCompromisedNodes(self)

        percentage = computePercentageOfCompromisedNodes(self)

        #check if want to terminate propagation
        if percentage < 100:
            if len(attacksDict) == 0:
                allGoal = 0
        
        if allGoal > 0 and percentage < 100:
            val += self.simAtk(attacksDict, attackerDict, targetDict, hopValueDict, fw)
        else:
            self.allpath.append(self.path[:])
        
        self.path.pop() if self.path else None #can remove null instead of error

        return val

    def initAtk(self): 
        """
        Initiate attack
        """
        self.allpath = []
        #Start to traverse from start point
        
        #added by KO Chee

        attacksdict = {}
        attackerdict = {}
        hopValueDict = {}
        targetDict = {}

        for a in self.atk:
            for b in a:
                tempName = []
                tempName2 = ""
                attackers = []
                exploits = []
                paths = []
                targetName = []
                cnc = None
                if len(b.nextTargetNode) > 1:
                    for a in b.nextTargetNode:
                        temp = "ag_" + str(a)
                        tempName.append(temp)
                elif len(b.nextTargetNode) == 1:
                    temp = "ag_" + str(b.nextTargetNode[0])
                    tempName.append(temp)
                else:
                    temp = None
                    tempName.append(temp)
                tempName2 = "ag_" + str(b.CNCNode[0])

                attackers.append(b.name)
                paths.append([b.name])
                for c in b.carryExploit:
                    exploits.append(c)
                b.nextTargetNode.clear()
                b.CNCNode.clear()
                if len(tempName) > 0:
                    for u in tempName:
                        for v in self.nodes:
                            if v.name == str(u):
                                targetName.append(v.name)
                else:
                    temp = None
                    targetName.append("No target")
                    b.nextTargetNode.append(temp)
                for u in self.nodes:
                    if u.name == tempName2:
                        u.cncAtkerList.append(b)
                        b.CNCNode.append(u)
                        cnc = u

                tempAttacksdict = dict(attackerNode = [b], accumulatedTime = b.accumulatedTime, timeline = b.timeline, meanTime = b.meanTime)
                tempAttackerdict = dict(attempt = 0, path = paths)
                tempTargetdict = dict(targets = targetName, remaining = [], compromised = [], next = [], onHold = [])
                tempHValueDict = dict(Node = [], Time = [], HopValue = [])
                
                if len(attacksdict) == 0:
                    attacksdict = dict(zip(attackers, [tempAttacksdict]))
                    attackerdict = dict(zip(attackers, [tempAttackerdict]))
                    targetDict = dict(zip(attackers, [tempTargetdict]))
                    hopValueDict = dict(zip(attackers, [tempHValueDict]))
                else:
                    temp = dict(zip(attackers, [tempAttacksdict]))
                    attacksdict.update(temp)
                    temp2 = dict(zip(attackers, [tempHValueDict]))
                    hopValueDict.update(temp2)
                    temp3 = dict(zip(attackers, [tempAttackerdict]))
                    attackerdict.update(temp3)
                    temp5 = dict(zip(attackers, [tempTargetdict]))
                    targetDict.update(temp5)

                if b.coop == True:
                    cnc.atkInfoDict = attacksdict
                else:
                    cnc.atkInfoDict = dict(zip([b.name], [tempAttacksdict]))

        self.atkerList = self.atk
        self.tgtList = self.tgt
        self.path = []

        createVulnerableHostPercentageChart(self, self.saveSimDir)
        fw = defenceMethods()

        mtdStatus = False
        
        if self.defMode["MTD"]["operational"] == True:
            mtdStatus = True
            mtdMode = self.defMode["MTD"]["mode"]

        

        val = self.simAtk(attacksdict, attackerdict, targetDict, hopValueDict, fw) #The value records recursion times  

        treeGraphFilename = []

        orderedList = createLollipopPlot(self.timelineDict, self.saveSimDir)
        calculateSecMetrics(self, self.timelineDict, self.saveSimDir, self.saveFolder)
        createFullTimelineChart(self, orderedList, self.saveSimDir)
        createGraph(self, "Final", self.saveSimDir)
        createNetworkCompromisePercentageChart(self, self.saveSimDir, self.saveFolder)

        t=0
        color = ['#33FFFF', '#9FE34A', '#ffb833', '#ff33cf', '#faff9c']
        for id, info in attackerdict.items():
            treeGraphFilename = createTreeGraph2(id, info, treeGraphFilename, color[t], self.saveSimDir)
            t+=1
        
        if len(treeGraphFilename) > 0:
            combineImage(treeGraphFilename, "Combined Tree Graph", self.saveSimDir)

        return val
    
    def scanForInitialTarget(self, mode, atkNode, targetList, toTarget, fw, firewallStatus, ipsStatus):
        """
        Scanning for first target from external attacker
        """
        u = atkNode
        alldone = False
        nodelist = []
        routerList = []
        targetFound = False
        uport = ""
        vport = ""
        limitedEntryPoint = False
        tempRouter = None

        
        if len(self.entryPointNode) > 0:
            limitedEntryPoint = True

        for x in self.nodes:
            text = x.name.split("-")
            if 'ag_router' in text or 'router' in text:
                routerList.append(x)

            if x.canBeCompromised == False:
                pass
            else:
                nodelist.append(x)

        if mode == "global":
            tempList = targetList.copy()

            for a in tempList:
                b = None
                proceed = False
                if len(routerList) > 0:
                    for x in routerList:
                        for y in x.con:
                            targetName = y.name
                            text2 = y.name.split("+")
                            if 'ag_decoy' in text2 or 'decoy' in text2:
                                targetName = "ag_"+str(text2[1])
                            if a == targetName:
                                tempRouter = x
                                b = y
                                proceed = True
                else:
                    tempRouter = None
                    for x in nodelist:
                        targetName = x.name
                        text2 = x.name.split("+")
                        if 'ag_decoy' in text2 or 'decoy' in text2:
                            targetName = "ag_"+str(text2[1])
                        if a == targetName:
                            b = x
                            proceed = True

                if proceed == True:
                    for p in u.scanPort: 
                        firewallProceed = True
                        ipsProceed = True
                        targetBlocked = False
                        if firewallStatus == True:
                            targetBlocked = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, p, b.IPv4Add, p])

                            if targetBlocked == True:
                                firewallProceed = False

                        if ipsStatus == True:
                            if self.defMode["IPS"]["rule"] is not None:
                                targetBlocked, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, p, "->", b.IPv4Add, p, u.content[0], u.scanTime], self.saveSimDir)
                                                            
                            if targetBlocked == True:
                                ipsProceed = False

                        if firewallProceed == True and ipsProceed == True:
                            for q in b.realPort:
                                if str(p) == str(q):
                                    if b.realPort[q]["open"] == True:
                                        if b.healthy == True:
                                            uport = p
                                            vport = q
                                            targetFound = True
                                            toTarget.append(b)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            b.isTarget = True
                                            break
                                        else:
                                            if u.group == b.group:
                                                pass
                                            else:
                                                uport = p
                                                vport = q
                                                targetFound = True
                                                toTarget.append(b)
                                                toTarget.append(str(p))
                                                toTarget.append(tempRouter)
                                                b.isTarget = True
                                                break
                                    else:
                                        targetList.remove(a)
                        if targetFound == True:
                            break
                if targetFound == True:
                    break
        else: #local
            while len(nodelist) > 0 and targetFound == False:
                if len(routerList) > 0:
                    tempRouter = choice(routerList)
                else:
                    tempRouter = None

                newNodeList = []
                
                if tempRouter is not None:
                    for x in tempRouter.con:
                        if x.canBeCompromised == False:
                            pass
                        else:
                            if x in nodelist:
                                newNodeList.append(x)
                else:
                    newNodeList = nodelist

                if len(newNodeList) == 0:
                    break
                else:
                    temp = choice(newNodeList)
                proceed = False

                if limitedEntryPoint == True:
                    text1, text2, text3 = self.simplifyNodeName(temp.name) #text1 is the exact node (eg. router-1) #text2 is the node type (eg. router)
                    if text2 in self.entryPointNode or text1 in self.entryPointNode:
                        proceed = True
                else:
                    proceed = True

                #not networking device (e.g. router)
                text = temp.name.split("-")
                if temp.canBeCompromised == False:
                    proceed = False

                if proceed == True:
                    for p in u.scanPort: 
                        firewallProceed = True
                        ipsProceed = True
                        targetBlocked = False
                        if firewallStatus == True:
                            targetBlocked = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, p, temp.IPv4Add, p])

                            if targetBlocked == True:
                                firewallProceed = False
                        
                        if ipsStatus == True:
                            if self.defMode["IPS"]["rule"] is not None:
                                targetBlocked, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, p, "->", temp.IPv4Add, p, u.content[0], u.scanTime], self.saveSimDir)

                            if targetBlocked == True:
                                ipsProceed = False

                        if firewallProceed == True and ipsProceed == True:
                            for q in temp.realPort:
                                if str(p) == str(q):
                                    if temp.realPort[q]["open"] == True:

                                        if temp.healthy == True:
                                            uport = p
                                            vport = q
                                            targetFound = True
                                            toTarget.append(temp)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            temp.isTarget = True
                                            break
                                        else:
                                            if u.group == temp.group:
                                                pass
                                            else:
                                                uport = p
                                                vport = q
                                                targetFound = True
                                                toTarget.append(temp)
                                                toTarget.append(str(p))
                                                toTarget.append(tempRouter)
                                                temp.isTarget = True
                                                break
                        if targetFound == True:
                            break
                nodelist.remove(temp)

        if targetFound == False:
            print("Initial target not found!")
            temp = []
            toTarget.append(temp)

        if len(toTarget) > 0:
            for x in toTarget:
                text = (str(x)).split("+")
                if 'ag_decoy' in text or 'decoy' in text:
                    self.dReport(u, x, fw, "Scanning", 0)
                    
        return tempRouter, targetFound, uport, vport
    
    def scanForSubsequentTarget(self, mode, atkNode, targetList, toTarget, fw):
        """
        Scanning for subsequent target from bot
        """
        u = atkNode
        targetFound = False
        targetIsCompromised = False
        if toTarget is not None:
            for x in toTarget:
                print("here: ", x)
        SSStatus = None
        uport = ""
        vport = ""

        if u.scanMethod == "d2d":
            toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, None, [], toTarget, SSStatus, uport, vport)
        elif u.scanMethod == "random":
            toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.randomScanning(mode, targetList, u, toTarget, targetFound, SSStatus, uport, vport)
        else:
            print("Error!! Scanning method not found!")

        if len(toTarget) > 0:
            for x in toTarget:
                text = (str(x)).split("+")
                if 'ag_decoy' in text or 'decoy' in text:
                    self.dReport(u, x, fw, "Scanning", 0)

        return targetFound, SSStatus, uport, vport, goThruAP

    def d2dScanning(self, mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport):
        """
        Device-to-Device Scanning method
        """
        targetFound = False
        targetIsCompromised = False
        APavailable = False
        goThruAP = False
        mainNode = None
        if APnode is not None:
            mainNode = APnode
        else:
            mainNode = u

        if mode == "global":
            if len(targetList) > 0:
                tempList = targetList.copy() 
                for a in tempList:
                    decoyCheck = False
                    for v in mainNode.con: #check for same name in direct connection
                        text = v.name.split("-")
                        text2 = v.name.split("+")
                        proceed = True
                        if 'ag_CNC' in text or 'ag_attacker' in text:
                            proceed == False
                        elif 'ag_router' in text:
                            proceed == False
                            if v.name in APList:
                                pass
                            else:
                                APavailable = True
                                APnode = v
                                APList.append(v.name)
                        elif v.name in u.CNCNode[0].avoidList:
                            if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
                                proceed == False
                        else:
                            pass
                            
                        if proceed == True:
                            #Check for decoy node: if the decoy was compromised previously, it will not proceed or otherwise.
                            if 'ag_decoy' in text2 or 'decoy' in text2:
                                if u.log in v.dataCollection:
                                    SSStatus = False 
                                    decoyCheck = True
                                    targetIsCompromised = True
                                else:
                                    #should not be able to go thru here
                                    if v.healthy == False:
                                        SSStatus = False 
                                        decoyCheck = True
                                        

                            if decoyCheck == False:
                                nodeName = v.name
                                if 'ag_decoy' in text2 or 'decoy' in text2:
                                    nodeName = "ag_"+str(text2[1])
                                    
                                if str(a) == nodeName:
                                    tempNum = len(v.realPort)*len(u.scanPort)
                                    for p in u.scanPort: 
                                        for q in v.realPort:
                                            if str(p) == str(q):
                                                if v.realPort[q]["open"] == True:
                                                    if v.healthy == True:
                                                        uport = p
                                                        vport = q
                                                        v.setTarget()
                                                        toTarget.append(v)
                                                        toTarget.append(str(p))
                                                        toTarget.append(mainNode)
                                                        targetFound = True
                                                        break
                                                    else:
                                                        if u.group == v.group:
                                                            targetIsCompromised = True
                                                            break
                                                        else:
                                                            uport = p
                                                            vport = q
                                                            v.setTarget()
                                                            toTarget.append(v)
                                                            toTarget.append(str(p))
                                                            toTarget.append(mainNode)
                                                            targetFound = True
                                                            break
                                                else:
                                                    if v.healthy == False and u.group == v.group:
                                                        targetIsCompromised = True
                                                        SSStatus = False
                                                        if a in targetList:
                                                            targetList.remove(a)
                                                        break
                                                    if tempNum > 0:
                                                        tempNum -= 1
                                                    
                                                    if tempNum == 0:
                                                        targetIsCompromised = True
                                                        SSStatus = False
                                                        if a in targetList:
                                                            targetList.remove(a)
                                                        break

                                        if targetFound == True or targetIsCompromised == True:
                                            break
                                    if targetFound == True or targetIsCompromised == True:
                                        if targetIsCompromised == True:
                                            SSStatus = False
                                            if a in targetList:
                                                targetList.remove(a)
                                        break
                            else:
                                if a in targetList:
                                    targetList.remove(a)
                                    break
                    if targetFound == True:
                        break
                    # if target still not found, check using stepping stone.
                    elif targetFound == False and targetIsCompromised == False:
                        for v in mainNode.con:
                            text = v.name.split("-")
                            text2 = v.name.split("+")
                            proceed2 = True
                            if 'ag_CNC' in text or 'ag_attacker' in text:
                                proceed2 = False
                            elif 'ag_router' in text:
                                proceed2 = False
                                if v.name in APList:
                                    pass
                                else:
                                    APavailable = True
                                    APnode = v
                                    APList.append(v.name)
                            elif v.name in u.CNCNode[0].avoidList:
                                if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
                                    proceed2 = False
                            else:
                                pass
                                
                            if proceed2 == True:
                                if (u.botCoop == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
                                    SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, a, True, u.CNCNode, None, None) #(target, nextTarget, cooperation, cncNode, attackerPort, ssPort)
                                    if SSStatus == True:
                                        if newTarget in toTarget:
                                            pass
                                        else:
                                            tempNum = len(newTarget.realPort)*len(u.scanPort)
                                            for p in u.scanPort: 
                                                for q in newTarget.realPort:
                                                    if str(p) == str(q):
                                                        if newTarget.realPort[q]["open"] == True:
                                                            if newTarget.healthy == True:
                                                                uport = p
                                                                vport = q
                                                                newTarget.setTarget()
                                                                toTarget.append(SSStatus)
                                                                toTarget.append(newTarget)
                                                                toTarget.append(str(q))
                                                                toTarget.append(stepstone)
                                                                targetFound = True
                                                                break
                                                            else:
                                                                if u.group == newTarget.group:
                                                                    targetIsCompromised = True
                                                                    break
                                                                else:
                                                                    uport = p
                                                                    vport = q
                                                                    newTarget.setTarget()
                                                                    toTarget.append(SSStatus)
                                                                    toTarget.append(newTarget)
                                                                    toTarget.append(str(q))
                                                                    toTarget.append(stepstone)
                                                                    targetFound = True
                                                                    break
                                                        else:
                                                            if newTarget.healthy == False and u.group == newTarget.group:
                                                                targetIsCompromised = True
                                                                SSStatus = False
                                                                if a in targetList:
                                                                    targetList.remove(a)
                                                                break
                                                            if tempNum > 0:
                                                                tempNum -= 1
                                                            
                                                            if tempNum == 0:
                                                                #target node is compromised and no open port
                                                                SSStatus = False
                                                                targetIsCompromised = True
                                                                if a in targetList:
                                                                    targetList.remove(a)
                                                                break
                                                    else:
                                                        if tempNum > 0:
                                                            tempNum -= 1
                                                        
                                                        if tempNum == 0:
                                                            #target node is compromised and no open port
                                                            SSStatus = False
                                                            targetIsCompromised = True
                                                            if a in targetList:
                                                                targetList.remove(a)
                                                            break
                                                    if targetFound == True or targetIsCompromised == True:
                                                        break
                                                if targetFound == True or targetIsCompromised == True:
                                                    if targetIsCompromised == True:
                                                        SSStatus = False
                                                        if a in targetList:
                                                            targetList.remove(a)
                                                    break
                                    else:
                                        pass
                            if targetFound == True or targetIsCompromised == True:
                                break
                        if targetFound == False and targetIsCompromised == False:
                            if APavailable == True:
                                toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport)
                        if targetFound == True:
                            break
                    if targetFound == True or targetIsCompromised == True:
                        break
            else:
                print("No more target!!")
        else: # local
            for v in mainNode.con: #check for same name in direct connection
                text = v.name.split("-")
                text2 = v.name.split("+")
                proceed3 = True
                if 'ag_CNC' in text or 'ag_attacker' in text:
                    proceed3 = False
                elif v.name in u.CNCNode[0].avoidList:
                    if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
                        proceed3 = False
                elif 'ag_router' in text:
                    proceed3 = False
                    if v.name in APList:
                        pass
                    else:
                        APavailable = True
                        APnode = v
                        APList.append(v.name)
                else:
                    pass

                if proceed3 == True:
                    #Check for decoy node: if the decoy was compromised previously, it will not proceed or otherwise.
                    decoyCheck = False
                    if 'ag_decoy' in text2 or 'decoy' in text2:
                        if u.log in v.dataCollection:
                            SSStatus = False 
                            decoyCheck = True
                        else:
                            if v.healthy == False:
                                SSStatus = False 
                                decoyCheck = True
                            else:
                                pass

                    if decoyCheck == False:
                        for p in u.scanPort: 
                            for q in v.realPort:
                                if str(p) == str(q):
                                    if v.realPort[q]["open"] == True:
                                        if v.healthy == True:
                                            if v in toTarget:
                                                pass
                                            else:
                                                uport = p
                                                vport = q
                                                v.setTarget()
                                                toTarget.append(v)
                                                toTarget.append(str(p))
                                                toTarget.append(mainNode)
                                            targetFound = True
                                            break
                                        else:
                                            if u.group == v.group:
                                                pass
                                            else:
                                                if v in toTarget:
                                                    pass
                                                else:
                                                    uport = p
                                                    vport = q
                                                    v.setTarget()
                                                    toTarget.append(v)
                                                    toTarget.append(str(p))
                                                    toTarget.append(mainNode)
                                                targetFound = True
                                                break
                                        
                                    elif v.realPort[q]["open"] == False and v.healthy == False:
                                        if (u.botCoop == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
                                            SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, None, True, u.CNCNode, p, q)#u.targetPort)
                                            if SSStatus == True:
                                                if newTarget in toTarget:
                                                    pass
                                                else:
                                                    uport = p
                                                    vport = q
                                                    newTarget.setTarget()
                                                    toTarget.append(SSStatus)
                                                    toTarget.append(newTarget)
                                                    toTarget.append(newTargetPort)
                                                    toTarget.append(stepstone)
                                                targetFound = True
                                                break
                                        else:
                                            SSStatus = False
                                    else:
                                        pass
                            if targetFound == True:
                                break
                if targetFound == True:
                    break
            if targetFound == True:
                pass
            else:
                if APavailable == True:
                    toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport)
                    goThruAP = True
                
        return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    def randomScanning(self, mode, targetList, u, toTarget, targetFound, SSStatus, uport, vport):
        """
        Random Scanning method
        """
        targetIsCompromised = False
        nodelist = []
        routerList = []
        tempRouter = None
        goThruAP = False

        for x in self.nodes:
            text = x.name.split("-")
            if 'ag_router' in text or 'router' in text:
                routerList.append(x)

            if x.canBeCompromised == False:
                pass
            else:
                nodelist.append(x)

        if mode == "global":
            tempList = targetList.copy()
            for a in tempList:
                b = None
                proceed4 = False
                if len(routerList) > 0:
                    for x in routerList:
                        for y in x.con:
                            targetName = y.name
                            text2 = y.name.split("+")
                            if 'ag_decoy' in text2 or 'decoy' in text2:
                                targetName = "ag_"+str(text2[1])
                            if a == targetName:
                                tempRouter = x
                                b = y
                                proceed4 = True
                else:
                    tempRouter = None
                    for x in nodelist:
                        targetName = x.name
                        text2 = x.name.split("+")
                        if 'ag_decoy' in text2 or 'decoy' in text2:
                            targetName = "ag_"+str(text2[1])
                        if a == targetName:
                            b = x
                            proceed4 = True

                if b.name in u.CNCNode[0].avoidList:
                    if u.CNCNode[0].avoidList[b.name]["avoid"] == True:
                        proceed4 = False
                        targetList.remove(a)


                if proceed4 == True:
                    for p in u.scanPort: 
                        for q in b.realPort:
                            if str(p) == str(q):
                                if b.realPort[q]["open"] == True:
                                    if b.healthy == True:
                                        uport = p
                                        vport = q
                                        targetFound = True
                                        toTarget.append(b)
                                        toTarget.append(str(p))
                                        toTarget.append(tempRouter)
                                        b.isTarget = True
                                        break
                                    else:
                                        if u.group == b.group:
                                            pass
                                        else:
                                            uport = p
                                            vport = q
                                            targetFound = True
                                            toTarget.append(b)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            b.isTarget = True
                                            break
                                else:
                                    targetList.remove(a)
                        if targetFound == True:
                            break
                if targetFound == True:
                    break
        else: #local
            while len(nodelist) > 0 and targetFound == False:
                if len(routerList) > 0:
                    tempRouter = choice(routerList)
                else:
                    tempRouter = None
                newNodeList = []
                if tempRouter is not None:
                    for x in tempRouter.con:
                        if x.canBeCompromised == False:
                            pass
                        else:
                            if x in nodelist:
                                newNodeList.append(x)
                else:
                    newNodeList = nodelist
                if len(newNodeList) == 0:
                    break
                else:
                    temp = choice(newNodeList)

                proceed5 = True
                if temp.name in u.CNCNode[0].avoidList:
                    if u.CNCNode[0].avoidList[temp.name]["avoid"] == True:
                        proceed5 = False
                        nodelist.remove(temp)

                if proceed5 == True:
                    for p in u.scanPort: 
                        for q in temp.realPort:
                            if str(p) == str(q):
                                if temp.realPort[q]["open"] == True:
                                    if temp.healthy == True:
                                        uport = p
                                        vport = q
                                        targetFound = True
                                        toTarget.append(temp)
                                        toTarget.append(str(p))
                                        toTarget.append(tempRouter)
                                        temp.isTarget = True
                                        break
                                    else:
                                        if u.group == temp.group:
                                            pass
                                        else:
                                            uport = p
                                            vport = q
                                            targetFound = True
                                            toTarget.append(temp)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            temp.isTarget = True
                                            break
                        if targetFound == True:
                            break
                    nodelist.remove(temp)
        if tempRouter is not None:
            goThruAP = True

        return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    def bruteForceAttackForCredential(self, u, v, fw):
        """
        Brute force attack - Emulation only
        """
        success = False
        credentialData = ""
        portNum = ""

        for p in u.scanPort: 
            for q in v.realPort:
                if str(p) == str(q):
                    if v.realPort[q]["open"] == True:
                        if v.vuls is not None:
                            for x in u.carryExploit:
                                for y in v.realPort[q]["Vuln"]:
                                    for z in v.vuls: #check if it is patched
                                        if str(x) == str(y) == str(z):
                                            success = True
                                            portNum = str(q)
                                            credentialData = str(x)
                                            break
                                if success == True:
                                    break
                        else:
                            print("Target has no vulnerability.")
                    else:
                        pass
                if success == True:
                    break
            if success == True:
                break

        text = v.name.split("+")
        if 'ag_decoy' in text or 'decoy' in text:
            self.dReport(u, v, fw, "Unauthorised Accessing", 1)
        return success, portNum, credentialData

    def reportToCNCServer(self, attackData, CNCNode):
        """
        Send credential information to CNC 
        """
        CNC = CNCNode[0]
        CNC.attackData.append(attackData)

        return None

    def downloadBinaryInstallMalware(self, u, v, portNo, cnc, tempPath, fw, botISpatched):
        """
        Infect the target node & turn target node into a bot
        """
        tempList = []
        tempName = None
        if botISpatched is not None:
            for x in cnc.con:
                if x.name == botISpatched:
                    tempName = u.name
                    u = x

        for id, info in v.realPort.items():
            temp = []
            temp.append(str(id))
            for key in info:
                if key == 'open':
                    if info[key] == True:
                        temp.append("Open")
                    else:
                        temp.append("Closed")
            tempList.append(temp)

        if len(v.log) > 0: #Log if competition/take over happens
            filename = os.path.join(self.saveSimDir, "Competition.txt")
            createRecord("\nNode: {}".format(str(v.name)), filename)
            createRecord("Old owner: {}".format(str(v.log[1])), filename)
            createRecord("Port Status: {}".format(str(tempList)), filename)
            if len(u.log) == 0:
                createRecord("New owner: {}".format(str(u.signature[1])), filename)
            elif len(u.log) > 0:
                createRecord("New owner: {}".format(str(u.log[1])), filename)
            else:
                createRecord("New owner: {}".format(str(botISpatched)), filename)
            
            ##remove previous CNC connection
            for x in v.con:
                text = x.name.split('-')
                if 'ag_CNC' in text or 'CNC' in text:
                    disconnectTwoWays(v, x)
                    x.listofBots.remove(v)
                    v.CNCNode.clear()
                    break
        #works differently if the node is a decoy node
        text = v.name.split("+")
        smartDecoys = False

        if 'ag_decoy' in text or 'decoy' in text:
            if len(u.signature) > 0:
                sign = u.signature
            elif len(u.log) > 0:
                sign = u.log
            else:
                sign = botISpatched
            
            self.dReport(u, v, fw, "Malware Installation/Infection", 2)
            if sign in v.dataCollection:
                u.status = 0 #stop infinite loop
                pass
            else:
                v.dataCollection.append(sign)

            if v.model == "smart":
                smartDecoys = True
            else:
                v.realPort[portNo]["open"] = False
                v.scanPort = u.scanPort
                v.scanMethod = u.scanMethod
                v.healthy = False
                v.comp = True
                v.propagation = False
                v.isCompBy = u.name
                v.group = u.group
                v.protocol = u.protocol
                v.content = u.content
                if len(u.signature) > 0:
                    v.log = u.signature
                elif len(u.log) > 0:
                    v.log = u.log
                else:
                    v.log = botISpatched
                v.compromisedPort.append(portNo)
                v.status = 0
                self.totalInfectedNodes += 1
        
        else:
            v.carryExploit = u.carryExploit
            v.realPort[portNo]["open"] = False
            v.scanPort = u.scanPort
            v.scanMethod = u.scanMethod
            v.healthy = False
            v.comp = True
            v.propagation = True
            v.isCompBy = u.name
            v.group = u.group
            v.protocol = u.protocol
            v.content = u.content
            if len(u.signature) > 0:
                v.log = u.signature
            else:
                v.log = u.log

            v.coop = u.coop
            v.botCoop = u.botCoop
            v.meanTime = u.meanTime
            v.mode = u.mode
            v.compromisedPort.append(portNo)
            v.status = 1
            v.setFromTargetToAttacker()
            connectTwoWays(v, cnc)
            cnc.listofBots.append(v)
            v.CNCNode.append(cnc)
            self.totalInfectedNodes += 1
            #self.disguise()
            #self.terminateEnemy()

        self.path.append(v)
        if botISpatched is not None:
            tempPath.append(tempName)
        else:
            tempPath.append(u.name)
        tempPath.append(v.name)
        return tempPath

    def getTime(self, u, processName):
        """
        Get time value randomly for different phase 
        """
        time = 0
        dataAccepted = False
        
        for x in self.AtkerTimeDataDict:
            text1 = u.name.split("_")
            text2 = str(x).split("_")
            tempText = ""
            if len(u.signature) > 0:
                tempText = u.signature[1]
            elif len(u.log) > 0:
                tempText = u.log[1]

            if str(x) in text1 or tempText in text2:
                while(dataAccepted == False):
                    time = choice(self.AtkerTimeDataDict[x][processName]["timeData"])
                    if time >= self.AtkerTimeDataDict[x][processName]["parameterX"][0] and time <= self.AtkerTimeDataDict[x][processName]["parameterX"][1]:
                        dataAccepted = True
                        break
            if dataAccepted == True:
                break
        return time

    def generatePhaseTime(self, attacksDict):
        """
        Get time value for different phases
        """
        compareAT = []
        getAvgTime = []
        for x in attacksDict:
            compareAT.append(attacksDict[x]["accumulatedTime"])
            for u in attacksDict[x]["attackerNode"]:
                if u.status == 1: #get new value if the node is in scanning mode
                    u.scanTime = self.getTime(u, "scan")
                    u.accessTime = self.getTime(u, "access")
                    u.reportTime = self.getTime(u, "report")
                    u.infectionTime = self.getTime(u, "install")
                else:   #get new value for new node
                    if u.scanTime == 0:
                        u.scanTime = self.getTime(u, "scan")
                    if u.accessTime == 0:
                        u.accessTime = self.getTime(u, "access")
                    if u.reportTime == 0:
                        u.reportTime = self.getTime(u, "report")
                    if u.infectionTime == 0:
                        u.infectionTime = self.getTime(u, "install")
                tempAT = (u.scanTime + u.accessTime + u.reportTime + u.infectionTime)/4
            getAvgTime.append(tempAT)

        return compareAT, getAvgTime

    def createNewRuleName(self, rules):
        """
        Set new rule's name
        """
        newrulename = ""
        tempList = []

        for x in rules:
            tempList.append(int(x))
        
        newrulename = str(int(max(tempList)) + 1)

        return newrulename

    def checkForSteppingStone(self, target, nextTarget, cooperation, cncNode, attackerPort, ssPort): 
        """
        Check whether it is possible for attacker to use compromised node as stepping stone to attack further target
        """
        status = False
        stepStone = None
        newTarget = None
        newTargetPort = ""
        #Global
        if nextTarget is not None:
            if cooperation == True:
                for x in cncNode:
                    for y in x.listofBots:
                        text2 = y.name.split("+")
                        if 'ag_decoy' in text2 or 'decoy' in text2:
                            pass
                        else:
                            if str(y.name) == str(target.name):
                                for z in y.con:
                                    text = z.name.split("-")
                                    proceed5 = True
                                    if z.canBeCompromised == False:
                                        proceed5 = False
                                    elif z.name in x.avoidList:
                                        if x.avoidList[z.name]["avoid"] == True:
                                            proceed5 = False
                                    else:
                                        pass
                                    if proceed5 == True:
                                        targetName = ""
                                        if type(nextTarget) is str:
                                            targetName = nextTarget
                                        elif type(nextTarget.name) is str:
                                            targetName = nextTarget.name
                                        else:
                                            print("No string found!! Error!!")
                                        
                                        nodeName = z.name
                                        text3 = z.name.split("+")
                                        if 'ag_decoy' in text3 or 'decoy' in text3:
                                            nodeName = "ag_"+str(text3[1])
                                        if nodeName == targetName:
                                            status = True
                                            stepStone = y
                                            newTarget = z
                                        if status == True:
                                            break
                        if status == True:
                            break
                    if status == True:
                        break
        #Local
        elif target is not None:
            if cooperation == True:
                for x in cncNode:
                    for y in x.listofBots:
                        if str(y.name) == str(target.name):
                            for z in y.con:
                                
                                text = z.name.split("-")
                                text2 = z.name.split("+")
                                proceed6 = True
                                if z.canBeCompromised == False:
                                    proceed6 = False
                                elif z.name in x.avoidList:
                                    if x.avoidList[z.name]["avoid"] == True:
                                        proceed6 = False
                                else:
                                    pass
                                if proceed6 == True:
                                    decoyCheck = False
                                    if 'ag_decoy' in text2 or 'decoy' in text2:
                                        if y.log in z.dataCollection:
                                            decoyCheck = True
                                        else:
                                            if z.healthy == False:
                                                decoyCheck = True
                                            else:
                                                pass

                                    if decoyCheck == False:
                                        for q in z.realPort:
                                            if q == attackerPort and q == ssPort: 
                                                if z.realPort[q]["open"] == True:
                                                    if z.healthy == True:
                                                        stepStone = y
                                                        newTarget = z
                                                        newTargetPort = str(q)
                                                        status = True
                                                        break
                                                    else:
                                                        if y.group == z.group:
                                                            pass
                                                        else:
                                                            stepStone = y
                                                            newTarget = z
                                                            newTargetPort = str(q)
                                                            status = True
                                                            break
                                if status == True:
                                    break
                        if status == True:
                            break
                    if status == True:
                        break
        return status, stepStone, newTarget, newTargetPort

    def sortDict(self, oldDict):
        """
        Sort attackers dict according to scanTime for the 1st time then accumulatedTime for the rest
        """
        i = 0
        for x in oldDict:
            if oldDict[x]["accumulatedTime"] > 0:
                i += 1

        if i > 0:
            return dict(sorted(oldDict.items(), key= lambda x: getitem(x[1], 'accumulatedTime'))) # maybe need to sort by multiple keys
        else:
            return dict(sorted(oldDict.items(), key= lambda x: getitem(x[1], 'meanTime')))

    def sortDict2(self, oldDict):
        """
        Sort CNC dict according to startTime
        """
        i = 0
        for x in oldDict:
            if oldDict[x]["startTime"] > 0:
                i += 1

        if i > 0:
            return dict(sorted(oldDict.items(), key= lambda x: getitem(x[1], 'startTime')))
        else:
            return oldDict

    def dReport(self, u, v, fw, actionName, num):
        """
        Create decoy report
        """
        exploit = ""
        vulnerability = ""
        sign = None
        for x in u.carryExploit:
            for y in v.vuls:
                if str(x) == str(y):
                    exploit = str(x)
                    vulnerability = str(y)
                    break
            if len(exploit) > 0:
                break
        if len(u.signature) > 0:
            sign = u.signature
        else:
            sign = u.log
        cnc = u.CNCNode[0]

        for p in u.scanPort: # u.targetPort:
            for q in v.realPort:
                if str(p) == str(q):
                    portNo = p
        fw.decoyReports([u.protocol, u.IPv4Add, portNo, u.name, sign, exploit, vulnerability, u.content[num], cnc], [actionName], self.saveSimDir)

        return None

    def simplifyNodeName(self, data):
        """
        Simplify name string
        example data: "ag_router-1"
        """
        text = data.split("_")
        text2 = text[1].split("-")
        return text[1], text2[0], text2[1]

    def changeScanPortOrder(self, scanPort):
        """
        Swap scanning port's order
        """
        for i in range(0, len(scanPort)-1):
            scanPort[i], scanPort[i+1] = scanPort[i+1], scanPort[i]
        return None

    def changeListOrder(self, tlist):
        """
        Change a list's order
        """
        for i in range(0, len(tlist)-1):
            tlist[i], tlist[i+1] = tlist[i+1], tlist[i]
        return None

    def createNewRule(self, x, fw, v, portNum):
        """
        Create new rule for defence technique
        """

        if len(self.defMode["IDS"]["addNewRule"]) > 0:
            for w in self.defMode["IDS"]["addNewRule"]:
                if w == "firewall":
                    newRuleName = self.createNewRuleName(self.defMode["Firewall"]["rule"])
                    newdict = {newRuleName : {"Action" : "block",
                                            "Protocol" : "any",
                                            "SourceIP" : x.IPv4Add,
                                            "SourcePort" : "any",
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "any",
                                            "msg" : "block ip address " + str(x.IPv4Add),
                                            "where" : ["all"]
                                            }
                                }
                    updateDict = True
                    for y in self.defMode["Firewall"]["rule"]:
                        if self.defMode["Firewall"]["rule"][y] == newdict[newRuleName]:
                            updateDict = False
                            break
                    if updateDict == True:
                        self.defMode["Firewall"]["rule"].update(newdict)

                if w == "ips":
                    newRuleName = self.createNewRuleName(self.defMode["IPS"]["rule"])
                    newdict = {newRuleName : {"Action" : "reject",
                                                "Protocol" : "any",
                                                "SourceIP" : x.IPv4Add,
                                                "SourcePort" : "any",
                                                "FlowDirection" : "->",
                                                "DestinationIP" : "any",
                                                "DestinationPort" : "any",
                                                "msg" : "block ip address " + str(x.IPv4Add),
                                                "content" : "any",
                                                "rev" : 1,
                                                "priority" : 10
                                                }
                                }
                    updateDict = True
                    for y in self.defMode["IPS"]["rule"]:
                        if self.defMode["IPS"]["rule"][y] == newdict[newRuleName]:
                            updateDict = False
                            break
                    if updateDict == True:
                        self.defMode["IPS"]["rule"].update(newdict)
                    
        if v is not None and portNum is not None:
            if self.defMode["Patching"]["operational"] == True and self.defMode["Patching"]["mode"] == 3:
                fw.patchVulnerability(self.defMode["Patching"]["mode"], self.defMode["Patching"]["vulnerability"], v.name, portNum, self.nodes)

        return None

    def calcPath(self):
        """
        Trigger attack
        """
        return self.initAtk()