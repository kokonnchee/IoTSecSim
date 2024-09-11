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
from Defence import *
from WordlistGen import *
  
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
        self.collude = False
        self.botCollude = False
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
        self.binaryName = []
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

        self.loginUsername = ""
        self.loginPassword = ""
        self.credentialExploitationList = []
        self.credentialExploitationWordListName = []
        self.exploitType = []
        self.credentialPort = []
        self.propagationType = None

        self.resourceMeterAll = 0
        self.resourceMeterCurrent = 0
        self.resourceMeterBreakLimit = 0
        self.resourceConsumptionNLimit = []
        
        self.filelist = []
        self.folderlist = []
        self.cronFolder = []
        self.initFolder = []
        self.processlist = []
        self.binaryfile = []

        self.commandFromCNC = ""
        self.commandCurrent = ""
        self.commandList = []
        self.conditionChoice = []
        self.isRebooting = None
        self.chanceToReboot = 0
        self.respondToReboot = ""
        self.resideLocation = []
        self.rebootable = []
        self.conditionNow = ""
        self.botTaskList = []
        self.botActionList = []
        self.nextAction = 0
        self.botAttackList = []
        self.bufferCurrent = 0

        self.killerBlackList = []
        self.fortificationList = []
        self.evasionList = []

        self.buffer = 0
        self.resource = 0
        self.connectionList = []
        self.defendCommand = []
        self.port = None
        self.banList = []
        self.carryCredential = []
        self.networkDataRecord = {}

        self.filesize = 0
        self.resourceConsume = 0
        self.configuration = []
        self.response = None
        self.update = []

        self.decoyrecord = []
        self.shufflelist = []
        self.nodenum = 0
        self.isolationlist = []
        self.shuffletime = 0
        self.lastAP = None
        self.decoy = False
        
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
        self.inOutTrafficTimeline = []
        self.initialCNC = ["CNCX"]
        self.tempcncInstallDict = {'startTime': None, 'cncNodeNData': [], 'atkerSign': None}
        self.cncInstallDict = dict(zip(self.initialCNC, [self.tempcncInstallDict]))
        self.failProcess = []

        #Instantiate nodes in attack graph using network info
        for u in [network.s, network.e] + network.nodes:
            if u != None:   
                #For vulnerability
                if type(u) == vulNode:
                    gn = gVulNode('ag_' + str(u.name))
                    gn.privilege = u.privilege
                    gn.val = u.val

                elif type(u) == CommandNControl:
                    gn = gnode('ag_' + str(u.name))
                    gn.id = u.id
                    gn.cncAtkerList = u.cncAtkerList
                    gn.atkInfoDict = u.atkInfoDict
                    gn.group = u.group
                    gn.timeline = u.timeline
                    gn.attackData = u.attackData
                    gn.status = u.status
                    gn.goal = u.goal
                    gn.binaryName = u.binaryName
                    gn.IPv4Add = u.IPv4Add
                    gn.scanPort = u.scanPort
                    gn.content = u.content
                    gn.CNCMemory = u.CNCMemory
                    gn.position = u.position
                    gn.avoidList = u.avoidList
                    gn.canBeCompromised = u.canBeCompromised
                    gn.propagationType = u.propagationType
                    gn.commandFromCNC = u.commandFromCNC
                    gn.commandCurrent = u.commandCurrent
                    gn.commandList = u.commandList
                    gn.resideLocation = u.resideLocation
                    gn.respondToReboot = u.respondToReboot
                    gn.botTaskList = u.botTaskList
                    gn.killerBlackList = u.killerBlackList
                    gn.fortificationList = u.fortificationList
                    gn.evasionList = u.evasionList
                    gn.botActionList = u.botActionList
                    gn.networkDataRecord = u.networkDataRecord
                    gn.binaryfile = u.binaryfile

                elif type(u) == Server:
                    gn = gnode('ag_' + str(u.name))
                    gn.id = u.id
                    gn.IPv4Add = u.IPv4Add
                    gn.buffer = u.buffer
                    gn.bufferCurrent = u.bufferCurrent
                    gn.resource = u.resource
                    gn.connectionList = u.connectionList
                    gn.defendCommand = u.defendCommand
                    gn.content = u.content
                    gn.port = u.port
                    gn.timeline = u.timeline
                    gn.status = u.status
                    gn.banList = u.banList
                    gn.canBeCompromised = u.canBeCompromised
                                
                elif type(u) == intelligenceCenter:
                    gn = gnode(str(u.name))
                    gn.configuration = u.configuration
                    gn.response = u.response
                    gn.update = u.update
                    gn.decoyrecord = u.decoyrecord

                elif type(u) == sdnSwitch:
                    gn = gnode(str(u.name))
                    gn.shufflelist = u.shufflelist
                    gn.nodenum = u.nodenum
                    gn.isolationlist = u.isolationlist
                    gn.shuffletime = u.shuffletime
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
                        gn.carryCredential = u.carryCredential
                        gn.CNCNode = u.CNCNode
                        gn.nextTargetNode = u.nextTargetNode
                        gn.goal = u.goal
                        gn.collude = u.collude
                        gn.botCollude = u.botCollude
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
                        gn.binaryName = u.binaryName
                        gn.meanTime = u.meanTime
                        gn.targetPort = u.targetPort
                        gn.IPv4Add = u.IPv4Add
                        gn.scanPort = u.scanPort
                        gn.protocol = u.protocol
                        gn.content = u.content
                        gn.scanMethod = u.scanMethod

                        gn.credentialExploitationList = u.credentialExploitationList
                        gn.credentialExploitationWordListName = u.credentialExploitationWordListName
                        gn.exploitType = u.exploitType
                        gn.propagationType = u.propagationType
                        gn.respondToReboot = u.respondToReboot
                        gn.resideLocation = u.resideLocation
                        gn.commandFromCNC = u.commandFromCNC
                        gn.commandCurrent = u.commandCurrent
                        gn.commandList = u.commandList
                        gn.botTaskList = u.botTaskList
                        gn.killerBlackList = u.killerBlackList
                        gn.fortificationList = u.fortificationList
                        gn.evasionList = u.evasionList
                        gn.botActionList = u.botActionList
                        gn.binaryfile = u.binaryfile
                    else:
                        if type(u) != CommandNControl and type(u) != attacker:
                            gn.vuls = u.vul.nodes.copy()
                            self.totalVulnerableNodes += 1
                            gn.hopValue = u.hopValue
                            gn.isCompBy = u.isCompBy
                            gn.group = u.group
                            gn.botCollude = u.botCollude
                            gn.status = u.status
                            gn.attackData = u.attackData
                            gn.timeline = u.timeline
                            gn.nextTargetNode = u.nextTargetNode
                            gn.collude = u.collude
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

                            gn.loginUsername = u.loginUsername
                            gn.loginPassword = u.loginPassword
                            
                            gn.credentialPort = u.credentialPort
                            gn.propagationType = u.propagationType

                            gn.filelist = u.filelist
                            gn.folderlist = u.folderlist
                            gn.cronFolder = u.cronFolder
                            gn.initFolder = u.initFolder
                            gn.processlist = u.processlist

                            gn.conditionChoice = u.conditionChoice
                            gn.isRebooting = u.isRebooting
                            gn.chanceToReboot = u.chanceToReboot
                            gn.resourceMeterAll = u.resourceMeterAll
                            gn.resourceMeterCurrent = u.resourceMeterCurrent
                            gn.resourceMeterBreakLimit = u.resourceMeterBreakLimit
                            gn.resourceConsumptionNLimit = u.resourceConsumptionNLimit
                            gn.rebootable = u.rebootable
                            gn.conditionNow = u.conditionNow
                            gn.nextAction = u.nextAction
                            gn.botAttackList = u.botAttackList
                            gn.binaryfile = u.binaryfile

                            if type(u) != routerNode:
                                gn.model = u.model

                            if type(u) == realNode:
                                gn.lastAP = u.lastAP
                                gn.decoy = u.decoy

                            if type(u) == decoyNode:
                                gn.dataCollection = u.dataCollection
                                # gn.model = u.model

                    if u != network.s and u != network.e:
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
                if len(arg) == 0:
                    for t in self.nodes:
                        if t.n.name == v.name:
                            u.con.append(t)
                #For lower layer
                else:
                    if arg[0] >= v.privilege:
                        for t in self.nodes:
                            if t.n == v:
                                u.con.append(t) 
        
        #Initialize start and end in attack graph   
        for u in self.nodes:
            if u.n == network.s:
                self.s = u    
            if u.n == network.e:
                self.e = u
            if [u.n] in network.atk:
                self.atk.append([u])
            if [u.n] in network.tgt:
                self.tgt.append([u])
        
        #Remove start and end from nodes in attack graph      
        if self.s != None:
            self.nodes.remove(self.s)
        if self.e != None:
            self.nodes.remove(self.e)           


## added and modified by KO Chee----------------------------------------------
    # def simAtk(self, attacksDict, attackerDict, targetDict, hopValueDict, fw):
    #     """
    #     Simulate attack on IoT network
    #     """
    #     val = 0
        
    #     allGoal = len(attackerDict)
    #     goalAchieved = False

    #     tempPath = []
    #     tempPath2 = []

    #     CNC = []
    #     for x in self.nodes:
    #         text = x.name.split("-")
    #         if 'ag_CNC' in text:
    #             CNC.append(x)

    #     attacksDict = self.sortDict(attacksDict)

    #     attacksDict = self.checkForRebootedDevice(attacksDict)

    #     firewallStatus = False
    #     if self.defMode["Firewall"]["operational"] == True:
    #         firewallStatus = True
    #         if self.defMode["Firewall"]["rule"] != None:
    #             for id, info in self.defMode["Firewall"]["rule"].items():
    #                 fw.createNewRuleset("firewall", str(id), self.defMode["Firewall"]["rule"][id])

    #     idsStatus = False
    #     if self.defMode["IDS"]["operational"] == True:
    #         if self.defMode["IDS"]["mode"] == 1:
    #             logType = ["all", "alert"]
    #         idsStatus = True
    #         if self.defMode["IDS"]["rule"] != None:
    #             for id, info in self.defMode["IDS"]["rule"].items():
    #                 fw.createNewRuleset("ids", str(id), self.defMode["IDS"]["rule"][id])

    #     ipsStatus = False
    #     if self.defMode["IPS"]["operational"] == True:
    #         ipsStatus = True
    #         if self.defMode["IPS"]["rule"] != None:
    #             for id, info in self.defMode["IPS"]["rule"].items():
    #                 fw.createNewRuleset("ips", str(id), self.defMode["IPS"]["rule"][id])

    #     decoyStatus = False
    #     if self.defMode["Deception"]["operational"] == True:
    #         decoyStatus = True

    #     for x in attacksDict:
    #         text0 = x.split('-')
    #         compareAT = 0
    #         getAvgTime = 0
    #         maxAT = 0
    #         maxCAT = 0

    #         if 'DBF' not in text0 and 'SDN' not in text0:
    #             compareAT, getAvgTime = self.generatePhaseTime(attacksDict)
    #             maxAT = max(getAvgTime)
    #             maxCAT = max(compareAT)

    #         for u in attacksDict[x]["attackerNode"]:
    #             temp = []
    #             csvFilename = os.path.join(self.saveSimDir, "NodeSARIInfo.csv")
    #             createCSVFile([u.name, u.scanTime, u.accessTime, u.reportTime, u.infectionTime], ['Node', 'scanTime', 'accessTime', 'reportTime', 'infectionTime'], csvFilename)
    #             tempAvgTime = (u.scanTime + u.accessTime + u.reportTime + u.infectionTime)/4

    #             text = u.name.split("-")
    #             if (u.accumulatedTime + tempAvgTime) < (maxCAT + maxAT) or len(compareAT) == 1: 

    #                 ###############################################
    #                 if u.status == 1: # status = '1' = SCANNING Phase
    #                     targetFound = False
    #                     tempRouter = None
    #                     goThruAP = False
    #                     targetBlockedFW1 = False
    #                     targetBlockedIPS1 = False
    #                     replyMsg = ""
    #                     SSStatus = None
    #                     if len(u.signature) > 0:
    #                         tempText = "ag_" + str(u.signature[1])
    #                     else:
    #                         tempText = "ag_" + str(u.log[1])
    #                     uport = ""
    #                     vport = ""
                        
    #                     if u.mode == "global":
    #                         if u.accumulatedTime == 0 or 'ag_attacker' in text:
    #                             if len(targetDict[tempText]["targets"]) > 0:
    #                                 targetDict[tempText]["remaining"] = targetDict[tempText]["targets"].copy()

    #                         if len(targetDict[tempText]["remaining"]) > 0:
    #                             tempList = targetDict[tempText]["remaining"]
    #                             if u.accumulatedTime == 0 or 'ag_attacker' in text:
    #                                 tempRouter, targetFound, uport, vport = self.scanForInitialTarget(u.mode, u, tempList, u.nextTargetNode, fw, firewallStatus, ipsStatus)
    #                             else:
    #                                 u.nextTargetNode.clear()
    #                                 targetFound, SSStatus, uport, vport, goThruAP  = self.scanForSubsequentTarget(u.mode, u, tempList, u.nextTargetNode, fw)
    #                         else:
    #                             print("No target found!!1")
    #                             pass
    #                         if targetFound == True:
    #                             if len(u.nextTargetNode) == 3:
    #                                 if str(u.nextTargetNode[0].name) in targetDict[tempText]["remaining"]:
    #                                     targetDict[tempText]["remaining"].remove(str(u.nextTargetNode[0].name))
    #                                 targetDict[tempText]["onHold"].append(str(u.nextTargetNode[0].name))
    #                             elif len(u.nextTargetNode) == 4:
    #                                 if str(u.nextTargetNode[1].name) in targetDict[tempText]["remaining"]:
    #                                     targetDict[tempText]["remaining"].remove(str(u.nextTargetNode[1].name))
    #                                 targetDict[tempText]["onHold"].append(str(u.nextTargetNode[1].name))
    #                     else: #for local learning
    #                         if u.accumulatedTime == 0 or 'ag_attacker' in text:
    #                             tempRouter, targetFound, uport, vport  = self.scanForInitialTarget(u.mode, u, None, u.nextTargetNode, fw, firewallStatus, ipsStatus)
    #                         else:
    #                             u.nextTargetNode.clear()
    #                             targetFound, SSStatus, uport, vport, goThruAP  = self.scanForSubsequentTarget(u.mode, u, None, u.nextTargetNode, fw)

    #                     if targetFound == True:
    #                         u.accumulatedTime += u.scanTime
    #                         attacksDict[x]["accumulatedTime"] = u.accumulatedTime
    #                         u.status = 2
    #                         temp.append("SS")
    #                         temp.append(u.scanTime)
    #                         temp.append(u.accumulatedTime)
    #                         u.timeline.append(temp)
    #                     else:
    #                         u.accumulatedTime += u.scanTime/2
    #                         attacksDict[x]["accumulatedTime"] = u.accumulatedTime
    #                         if SSStatus == False:
    #                             u.status = 0
    #                         else:
    #                             if 'ag_attacker' in text: #initial scanning
    #                                 for y in attackerDict:
    #                                     if str(y) == u.name:
    #                                         attackerDict[y]["attempt"] += 1
    #                                         if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
    #                                             u.status = 0
    #                                         break
    #                             else:
    #                                 if SSStatus == None:
    #                                     u.status = 0
                                        
    #                         temp.append("SF")
    #                         temp.append(u.scanTime)
    #                         temp.append(u.accumulatedTime)
    #                         u.timeline.append(temp)
                            
    #                     if tempRouter != None and goThruAP == False:
    #                         goThruAP = True

    #                     if idsStatus == True and goThruAP == True: 
    #                         triggerAlert1 = False
    #                         if targetFound == True:
    #                             if SSStatus == True:
    #                                 triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", u.nextTargetNode[1].IPv4Add, u.nextTargetNode[2], u.content[0], u.scanTime], logType, self.saveSimDir)
    #                                 port = u.nextTargetNode[2]
    #                                 vtarget = u.nextTargetNode[1]
    #                             else:
    #                                 triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", u.nextTargetNode[0].IPv4Add, vport, u.content[0], u.scanTime], logType, self.saveSimDir)
    #                                 port = vport
    #                                 vtarget = u.nextTargetNode[0]
    #                         else:
    #                             # for failed scan
    #                             triggerAlert1 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, uport, "->", "any", "any", u.content[0], u.scanTime], logType, self.saveSimDir)
    #                             port = None
    #                             vtarget = None

    #                         if triggerAlert1 == True:
    #                             self.createNewRule(u, fw, vtarget, port)

    #                 ###############################################
    #                 elif u.status == 2: # status = '2' = ACCESSING Phase
    #                     errorStatus = False
    #                     goThruAP = False
    #                     if len(u.nextTargetNode) > 0:
    #                         targetBlockedFW2 = False
    #                         targetBlockedIPS2 = False
    #                         tempTarget = None
    #                         tempTargetIP = None
    #                         tempTargetPort = None
    #                         tempRouter = None
    #                         success = False
    #                         data = ""
    #                         portNum = ""

    #                         if len(u.nextTargetNode) == 3:
    #                             tempTarget = u.nextTargetNode[0]
    #                             tempTargetPort = u.nextTargetNode[1]
    #                             tempRouter = u.nextTargetNode[2]
    #                         elif len(u.nextTargetNode) == 4:
    #                             tempTarget = u.nextTargetNode[1]
    #                             tempTargetPort = u.nextTargetNode[2]
    #                             tempRouter = u.nextTargetNode[3]
    #                         else:
    #                             errorStatus = True
    #                             print("Error!!", len(u.nextTargetNode), u.nextTargetNode)
                            
    #                         textR = tempRouter.name.split('-')
    #                         if 'ag_router' in textR or 'router' in textR:
    #                             pass
    #                         else:
    #                             tempRouter = None

    #                         if errorStatus == False:
    #                             tempTargetIP = tempTarget.IPv4Add

    #                         if firewallStatus == True and 'ag_attacker' in text:
    #                             targetBlockedFW2 = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, tempTargetPort, tempTargetIP, tempTargetPort])

    #                         ## IPS is deployed before the access process
    #                         if ipsStatus == True and 'ag_attacker' in text:
    #                             targetBlockedIPS2, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], self.saveSimDir)
                                    
    #                         if targetBlockedIPS2 == True or targetBlockedFW2 == True:
    #                             success = False
    #                             if targetBlockedIPS2 == True:
    #                                 print("Access has been blocked by IPS!")
    #                                 pass

    #                             if targetBlockedFW2 == True:
    #                                 print("Access has been denied by firewall!")
    #                                 pass
    #                         else:
    #                             if errorStatus == False:
    #                                 success, portNum, data = self.bruteForceAttackForCredential(u, tempTarget, fw)
    #                                 goThruAP = True

    #                         ## IDS is deployed after the access process
    #                         if goThruAP == True and idsStatus == True: 
    #                             triggerAlert2 = False
    #                             triggerAlert2 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], logType, self.saveSimDir)

    #                             if triggerAlert2 == True:
    #                                 self.createNewRule(u, fw, tempTarget, tempTargetPort)

    #                         if success == True:
    #                             tempAttackData = []
    #                             u.accumulatedTime += u.accessTime
    #                             attacksDict[x]["accumulatedTime"] = u.accumulatedTime
    #                             u.status = 3
    #                             temp.append("AS")
    #                             temp.append(u.accessTime)
    #                             temp.append(u.accumulatedTime)
    #                             u.timeline.append(temp)
    #                             tempAttackData.append(u)
    #                             tempAttackData.append(tempTarget)
    #                             tempAttackData.append(success)
    #                             tempAttackData.append(portNum)
    #                             tempAttackData.append(data)
    #                             tempAttackData.append(u.content)
    #                             tempAttackData.append(tempRouter)
    #                             u.attackData = tempAttackData
    #                         else:
    #                             u.accumulatedTime += u.accessTime
    #                             attacksDict[x]["accumulatedTime"] = u.accumulatedTime
    #                             u.status = 1
    #                             temp.append("AF")
    #                             temp.append(u.accessTime)
    #                             temp.append(u.accumulatedTime)
    #                             u.timeline.append(temp)

    #                             tempFP = []
    #                             tempFP.append("AF")
    #                             tempFP.append(self.simplifyNodeName(u.name)[0])
    #                             tempFP.append(self.simplifyNodeName(tempTarget.name)[0])
    #                             tempFP.append(u.accumulatedTime)

    #                             self.failProcess.append(tempFP)

    #                             #To avoid infinite scanning & accessing
    #                             if 'ag_attacker' in text:
    #                                 for y in attackerDict:
    #                                     if str(y) == u.name:
    #                                         attackerDict[y]["attempt"] += 1
                                            
    #                                         if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
    #                                             u.status = 0
                                                
    #                                         break
    #                                 if u.mode == "global":
    #                                     if len(targetDict[u.name]["targets"]) > 0:
    #                                         self.changeListOrder(targetDict[u.name]["targets"])
    #                             else:
    #                                 temp = 0
    #                                 stopScan = False
    #                                 if len(u.timeline) >= 25:
    #                                     for i in range(1, len(u.timeline)):
    #                                         if u.timeline[0-i][0] == "AF":
    #                                             temp+=1
    #                                         if temp > 5:
    #                                             stopScan = True
    #                                             break
    #                                 if stopScan == True:
    #                                     if tempTarget.name in u.CNCNode[0].avoidList:
    #                                         if portNum in u.CNCNode[0].avoidList[tempTarget.name]["port"]:
    #                                             if u.CNCNode[0].avoidList[tempTarget.name]["num"] >= len(tempTarget.realPort):
    #                                                 u.CNCNode[0].avoidList[tempTarget.name]["avoid"] = True
    #                                             else:
    #                                                 u.CNCNode[0].avoidList[tempTarget.name]["num"] += 1
    #                                         else:
    #                                             u.CNCNode[0].avoidList[tempTarget.name]["port"].append(portNum)
    #                                             u.CNCNode[0].avoidList[tempTarget.name]["num"] += 1
    #                                             if u.CNCNode[0].avoidList[tempTarget.name]["num"] >= len(tempTarget.realPort):
    #                                                 u.CNCNode[0].avoidList[tempTarget.name]["avoid"] = True
    #                                     else:
    #                                         u.CNCNode[0].avoidList[tempTarget.name] = {"port" : [str(portNum)], "num" : 1, "avoid" : False}
    #                         u.nextTargetNode.clear()
    #                         u.targetPort.clear()
    #                     else:
    #                         print("No target found!!2")

    #                 ###############################################
    #                 elif u.status == 3: # status = '3' = REPORT Phase
                        
    #                     targetBlocked2 = False
                        
    #                     if targetBlocked2 == True:
    #                         u.accumulatedTime += u.reportTime#/2
    #                         attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                            
    #                         u.status = 1
    #                         temp.append("RF")
    #                         temp.append(u.reportTime)
    #                         temp.append(u.accumulatedTime)
    #                         u.timeline.append(temp)
    #                     else:
    #                         if len(u.attackData) > 0:
    #                             self.reportToCNCServer(u.attackData, u.CNCNode)
    #                             u.accumulatedTime += u.reportTime
    #                             attacksDict[x]["accumulatedTime"] = u.accumulatedTime
    #                             temp1 = [u.CNCNode[0], u.attackData]
                                
    #                             if 'ag_attacker' in text:
    #                                 u.status = 0 #Proceed to 0 for ag_attacker (1st time)
    #                             else:
    #                                 u.status = 1
    #                             temp.append("RS")
    #                             temp.append(u.reportTime)

    #                             temp.append(u.accumulatedTime)
    #                             u.timeline.append(temp)

    #                             tempAttackers = []
    #                             tempAttackers.append(u.name)

    #                             if len(u.signature) > 0:
    #                                 tempLog = u.signature
    #                             else:
    #                                 tempLog = u.log

    #                             tempcncInstallDict = {'startTime': u.accumulatedTime, 'cncNodeNData': temp1, 'atkerSign': tempLog}

    #                             temp1cncInstallDict = dict(zip(tempAttackers, [tempcncInstallDict]))
                                
    #                             self.cncInstallDict.update(temp1cncInstallDict)

    #     ###############################################
    #     lastTime = int(self.time)

    #     if len(self.cncInstallDict) > 1 and "CNCX" in self.cncInstallDict:
    #         self.cncInstallDict.pop("CNCX")

    #     if len(self.cncInstallDict) > 1:
    #         self.cncInstallDict = self.sortDict2(self.cncInstallDict)

    #     # status = '4' = INSTALL Phase (DOWNLOAD BINARY INSTALL MALWARE)
    #     if "CNCX" not in self.cncInstallDict:
    #         for a in self.cncInstallDict:
    #             botISpatched = None
    #             x = self.cncInstallDict[a]['cncNodeNData'][0]
    #             if len(self.cncInstallDict[a]['cncNodeNData'][1]) > 0:
    #                 y = self.cncInstallDict[a]['cncNodeNData'][1].copy()
    #                 temp = []
    #                 u = y[0]
    #                 v = y[1]
    #                 portNum = y[3]
    #                 content = y[5]
    #                 tempAP = y[6]
    #                 tempPath = []
    #                 lastCheck = False
    #                 targetBlockedFW3 = False
    #                 targetBlockedIPS3 = False

    #                 ## Firewall is deployed before CNC to target node
    #                 if firewallStatus == True:
    #                     targetBlockedFW3 = fw.firewall(tempAP, [x.protocol, x.IPv4Add, portNum, v.IPv4Add, portNum])

    #                 ## IPS is deployed before CNC to target node
    #                 if ipsStatus == True:
    #                     targetBlockedIPS3, replyMsg = fw.intrusionPreventionSystem([u.protocol, x.IPv4Add, portNum, "->", v.IPv4Add, portNum, content[2], u.infectionTime], self.saveSimDir)

    #                 if targetBlockedFW3 == True or targetBlockedIPS3 == True:
    #                     self.changeScanPortOrder(u.scanPort)
    #                     if v.name in x.CNCMemory:
    #                         x.CNCMemory[v.name] += 1
    #                     else:
    #                         x.CNCMemory[v.name] = 1 
    #                 else:
    #                     if v.realPort[portNum]["open"] == True:
    #                         if v.healthy == True:
    #                             if v in x.listofBots:
    #                                 lastCheck = False
    #                             else:
    #                                 lastCheck = True
    #                         else:
    #                             if u.group == v.group:
    #                                 lastCheck = False
    #                             else:
    #                                 lastCheck = True
    #                     else:
    #                         lastCheck = False

    #                 if len(u.signature) > 0:
    #                     tempText = "ag_" + str(u.signature[1])
    #                 elif len(u.log) > 0 and u.propagation == True:
    #                     tempText = "ag_" + str(u.log[1])
    #                 elif len(self.cncInstallDict[a]['atkerSign']) > 0:
    #                     tempText = "ag_" + str(self.cncInstallDict[a]['atkerSign'][1])
    #                     print(u.name, " was patched! ", u.accumulatedTime, u.infectionTime)
    #                     botISpatched = tempText
    #                 else:
    #                     print(u.name, " was patched! Attack failed.")
    #                     lastCheck = False

    #                 if lastCheck == True:
    #                     tempPath = self.downloadBinaryInstallMalware(u, v, portNum, x, tempPath, fw, botISpatched)
    #                     if tempPath != None:
    #                         self.tempLongPath.append(tempPath)
    #                         tempPath2.append(tempPath)
                            
    #                     v.accumulatedTime = u.accumulatedTime + u.infectionTime
    #                     temp.append("IS")
    #                     temp.append(u.infectionTime)
    #                     temp.append(v.accumulatedTime)
    #                     v.timeline.append(temp)
    #                     tempT = u.timeline[-3]
                        
    #                     if str(v.name) in targetDict[tempText]["onHold"]:
    #                         targetDict[tempText]["onHold"].remove(str(v.name))
    #                         if v.name in targetDict[tempText]["compromised"]:
    #                             pass
    #                         else:
    #                             targetDict[tempText]["compromised"].append(str(v.name))

    #                     self.timelineDict['startNode'].append(u.name)
    #                     self.timelineDict['endNode'].append(v.name)
    #                     temp1 = []
    #                     temp1.append(v)
    #                     temp1.append(portNum)
    #                     startTime = tempT[2] - tempT[1]

    #                     self.timelineDict['startTime'].append(startTime)
    #                     self.timelineDict['endTime'].append(v.accumulatedTime)
    #                     text2 = v.name.split('+')
    #                     tempData = ""
    #                     if 'ag_decoy' in text2 or 'decoy' in text2:
    #                         if len(u.signature) > 0:
    #                             self.timelineDict['compBy'].append(u.signature[1])
    #                             tempData = u.signature[1]
    #                         elif len(u.log) > 0:
    #                             self.timelineDict['compBy'].append(u.log[1])
    #                             tempData = u.log[1]
    #                         else:
    #                             self.timelineDict['compBy'].append(botISpatched)
    #                             tempData = botISpatched
    #                     else:
    #                         self.timelineDict['compBy'].append(v.log[1])
    #                         tempData = v.log[1]

    #                     if tempPath != None:
    #                         x.attackData.remove(y)
    #                         for z in attackerDict:
    #                             text = z.split("_") 
    #                             if str(tempData) in text:
    #                                 attackerDict[z]["path"].append(tempPath)
    #                                 attackerDict[z]["path"].append(v.accumulatedTime)
    #                     text = u.name.split("-")
    #                     if 'ag_attacker' in text:
    #                         disconnectTwoWays(u, v)

    #                     self.time += 1
    #                     createGraph(self, "propagation {}".format(str(self.time)), self.saveSimDir)
    #                 else:
    #                     temp.append("IF")
    #                     temp.append(u.name)
    #                     temp.append(v.name)
    #                     temp.append(u.accumulatedTime)
    #                     x.timeline.append(temp)
    #                     x.attackData.remove(y)

    #                     tempFP = []
    #                     tempFP.append("IF")
    #                     tempFP.append(self.simplifyNodeName(u.name)[0])
    #                     tempFP.append(self.simplifyNodeName(v.name)[0])
    #                     tempFP.append(u.accumulatedTime + u.infectionTime)

    #                     self.failProcess.append(tempFP)

    #                     #check if it is the initial target or not
    #                     text = u.name.split("-")
                        
    #                     if str(v.name) in targetDict[tempText]["onHold"]:
    #                         targetDict[tempText]["remaining"] = [v.name] + targetDict[tempText]["remaining"]
    #                         targetDict[tempText]["onHold"].remove(str(v.name))

    #                     #To avoid infinite scanning
    #                     if 'ag_attacker' in text: 
    #                         for y in attackerDict:
    #                             if str(y) == u.name:
    #                                 attackerDict[y]["attempt"] += 1
    #                                 if attackerDict[y]["attempt"] > 50: #if attempt is more than 50, stop the scanning.
    #                                     u.status = 0
    #                                     print("6666666666666")
    #                                 else:
    #                                     u.status = 1
    #                     else:
    #                         self.changeScanPortOrder(u.scanPort)

    #                     if len(x.CNCMemory) > 0:
    #                         if x.IPv4Add in x.CNCMemory:
    #                             if x.CNCMemory[x.IPv4Add]["attempt"] >= 20: #200
    #                                 u.status = 0

    #                         if v.name in x.CNCMemory:
    #                             if x.CNCMemory[v.name] >= 5:
    #                                 if len(u.signature) > 0:
    #                                     tempText = "ag_" + str(u.signature[1])
    #                                 else:
    #                                     tempText = "ag_" + str(u.log[1])
    #                                 if u.mode == "global":
    #                                     if v.name in targetDict[tempText]["remaining"]:
    #                                         targetDict[tempText]["remaining"].remove(str(v.name))
                                            
    #                     if v.name in x.avoidList:
    #                         if portNum in x.avoidList[v.name]["port"]:
    #                             if x.avoidList[v.name]["num"] >= len(v.realPort):
    #                                 x.avoidList[v.name]["avoid"] = True
    #                             else:
    #                                 x.avoidList[v.name]["num"] += 1
    #                         else:
    #                             x.avoidList[v.name]["port"].append(portNum)
    #                             x.avoidList[v.name]["num"] += 1
    #                             if x.avoidList[v.name]["num"] >= len(v.realPort):
    #                                 x.avoidList[v.name]["avoid"] = True
    #                     else:
    #                         x.avoidList[v.name] = {"port" : [str(portNum)], "num" : 1, "avoid" : False}

    #                 ## IPS is deployed after CNC to target node
    #                 if idsStatus == True:
    #                     triggerAlert3 = False
    #                     triggerAlert3 = fw.intrusionDetectionSystem([u.protocol, x.IPv4Add, portNum, "->", v.IPv4Add, portNum, content[2], u.infectionTime], logType, self.saveSimDir)
    #                     if triggerAlert3 == True:
    #                         self.createNewRule(x, fw, v, portNum)

    #     #Check goal method
    #     for x in CNC:
    #         for y in x.goal:
    #             m = 0
    #             if y[2] == False:
    #                 for z in self.nodes:
    #                     text = z.name.split("-")
    #                     if 'ag_attacker' in text or 'ag_CNC' in text:
    #                         pass
    #                     else:
    #                         if len(z.log) > 0:
    #                             if str(z.log[1]) == str(y[0]):
    #                                 m += 1
    #                 if m >= y[1]:
    #                     allGoal -= 1
    #                     for a in self.nodes:
    #                         if len(a.log) > 0:
    #                             if str(a.log[1]) == str(y[0]):
    #                                 a.status = 0
    #             else:
    #                 allGoal -= 1
    #     # need to update the attacker pool if new infection found
    #     tempDict = {}

    #     for u in self.nodes:
    #         if u.status > 0:
    #             tempAttackers = []
    #             tempAttackers.append(u.name)
    #             temp = None
    #             if len(u.signature) > 0:
    #                 temp = u.signature
    #             else:
    #                 temp = u.log
    #             tempAttacksdict = dict(attackerNode = [u], accumulatedTime = u.accumulatedTime, timeline = u.timeline, meanTime = u.meanTime, ownBy = temp)

    #             if len(tempDict) == 0:
    #                 tempDict = dict(zip(tempAttackers, [tempAttacksdict]))
    #             else:
    #                 temp = dict(zip(tempAttackers, [tempAttacksdict]))
    #                 tempDict.update(temp)

    #     if tempDict != None:
    #         attacksDict = tempDict

    #     ## repeat the process
    #     self.initialCNC = ["CNCX"]
    #     self.tempcncInstallDict = {'startTime': None, 'cncNodeNData': [], 'atkerSign': None}
    #     self.cncInstallDict = dict(zip(self.initialCNC, [self.tempcncInstallDict]))

    #     self.longPath.append(tempPath2)
    #     tempNo = computeNumberOfCompromisedNodes(self)

    #     percentage = computePercentageOfCompromisedNodes(self)

    #     #check if want to terminate propagation
    #     if percentage < 100:
    #         if len(attacksDict) == 0:
    #             allGoal = 0
        
    #     if allGoal > 0 and percentage < 100:
    #         val += self.simAtk(attacksDict, attackerDict, targetDict, hopValueDict, fw)
    #     else:
    #         self.allpath.append(self.path[:])
        
    #     self.path.pop() if self.path else None #can remove null instead of error

    #     return val

    def simAtk(self, attacksDict, attackerDict, targetDict, hopValueDict, fw, wlg): #file, file2,
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

        attacksDict = self.checkForRebootedDevice(attacksDict)

        firewallStatus = False
        if self.defMode["Firewall"]["operational"] == True:
            firewallStatus = True
            if self.defMode["Firewall"]["rule"] != None:
                for id, info in self.defMode["Firewall"]["rule"].items():
                    fw.createNewRuleset("firewall", str(id), self.defMode["Firewall"]["rule"][id])

        idsStatus = False
        if self.defMode["IDS"]["operational"] == True:
            if self.defMode["IDS"]["mode"] == 1:
                logType = ["all", "alert"]
            idsStatus = True
            if self.defMode["IDS"]["rule"] != None:
                for id, info in self.defMode["IDS"]["rule"].items():
                    fw.createNewRuleset("ids", str(id), self.defMode["IDS"]["rule"][id])

        ipsStatus = False
        if self.defMode["IPS"]["operational"] == True:
            ipsStatus = True
            if self.defMode["IPS"]["rule"] != None:
                for id, info in self.defMode["IPS"]["rule"].items():
                    fw.createNewRuleset("ips", str(id), self.defMode["IPS"]["rule"][id])

        decoyStatus = False
        if self.defMode["Deception"]["operational"] == True:
            decoyStatus = True

        for x in attacksDict:
            text0 = x.split('-')
            compareAT = 0
            getAvgTime = 0
            maxAT = 0
            maxCAT = 0

            if 'DBF' not in text0 and 'SDN' not in text0:
                compareAT, getAvgTime = self.generatePhaseTime(attacksDict)
                maxAT = max(getAvgTime)
                maxCAT = max(compareAT)

            for u in attacksDict[x]["attackerNode"]:
                text00 = u.name.split('-')
                if u.name != 'Intelligence Center' and u.name != 'SDN switch' and u.status > 0:
                    if u.conditionNow != "rebooting":
                        temp = []

                        csvFilename = os.path.join(self.saveSimDir, "NodeSARIInfo.csv")
                        createCSVFile([u.name, u.scanTime, u.accessTime, u.reportTime, u.infectionTime], ['Node', 'scanTime', 'accessTime', 'reportTime', 'infectionTime'], csvFilename)
                        tempAvgTime = self.getTempAvgTime(u.scanTime, u.accessTime, u.reportTime, u.infectionTime)

                        text = u.name.split("-")
                        if (u.accumulatedTime + tempAvgTime) < (maxCAT + maxAT) or len(compareAT) == 1:

                            ###############################################
                            if u.status == 1: # status = '1' = SCANNING
                                targetFound = False
                                tempRouter = None
                                goThruAP = False
                                targetBlockedFW1 = False
                                targetBlockedIPS1 = False
                                replyMsg = ""
                                SSStatus = None
                                if len(u.binaryName) > 0:
                                    tempText = "ag_" + str(u.binaryName[1])
                                else:
                                    tempText = "ag_" + str(u.log[1])
                                uport = ""
                                vport = ""
                                tempDN1 = ""
                                
                                #for global learning
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
                                        if str(u.nextTargetNode[0].name) in targetDict[tempText]["remaining"]:
                                            targetDict[tempText]["remaining"].remove(str(u.nextTargetNode[0].name))
                                        targetDict[tempText]["onHold"].append(str(u.nextTargetNode[0].name))

                                else: #for local learning
                                    if u.accumulatedTime == 0 or 'ag_attacker' in text:
                                        tempRouter, targetFound, uport, vport  = self.scanForInitialTarget(u.mode, u, None, u.nextTargetNode, fw, firewallStatus, ipsStatus)

                                    else:
                                        u.nextTargetNode.clear()
                                        targetFound, SSStatus, uport, vport, goThruAP  = self.scanForSubsequentTarget(u.mode, u, None, u.nextTargetNode, fw)

                                tempDN = self.deviceRebootPeriodically(u.accumulatedTime)

                                if len(u.nextTargetNode) > 0:
                                    tempDN1 = u.nextTargetNode[0]

                                else:
                                    tempDN1 = None

                                templistInOut = []
                                if 'ag_attacker' in text and tempDN1 != None and type(tempDN1) != list:

                                    templistInOut.append("IN")
                                    templistInOut.append(u.name)
                                    templistInOut.append(tempDN1.name)
                                    templistInOut.append(u.accumulatedTime)
                                    templistInOut.append(u.binaryName[1])
                                    self.inOutTrafficTimeline.append(templistInOut)

                                if u.name in tempDN:
                                    targetFound = False
                                    print("yes. found. reboot1", u.name)

                                if targetFound == True and u.conditionNow != "rebooting" and tempDN1.conditionNow != "rebooting":
                                    u.accumulatedTime += u.scanTime
                                    attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                    u.status = 2
                                    temp.append("SS")
                                    temp.append(u.scanTime)
                                    temp.append(u.accumulatedTime)
                                    temp.append(tempDN1.name)
                                    u.timeline.append(temp)
                                else:
                                    if u.conditionNow != "rebooting":
                                        u.accumulatedTime += u.scanTime/2
                                        attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                        temp.append("SF")
                                        temp.append(u.scanTime)
                                        temp.append(u.accumulatedTime)
                                        if tempDN1 != None:
                                            temp.append(tempDN1.name)
                                        else:
                                            temp.append(tempDN1)
                                        u.timeline.append(temp)

                                    if SSStatus == False:
                                        u.status = 0
                                    else:
                                        #To avoid infinite scanning ## for port not found
                                        if 'ag_attacker' in text: #initial scanning
                                            for y in attackerDict:
                                                if str(y) == u.name:
                                                    attackerDict[y]["attempt"] += 1
                                                    if attackerDict[y]["attempt"] > 250: #>50: #if attempt == more than 50, stop the scanning.
                                                        u.status = 0
                                                    break
                                        else:
                                            if SSStatus == None:
                                                u.status = 0

                                    if u.status == 0 and u.nextAction > 0 and 'ag_attacker' not in text and u.nextAction != 66:
                                        u.status = u.nextAction
                                    
                                if tempRouter != None and goThruAP == False:
                                    goThruAP = True

                                if idsStatus == True and goThruAP == True: 
                                    triggerAlert1 = False
                                    if targetFound == True:
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
                            elif u.status == 2: # status = '2' = ACCESSING
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
                                    redo = False

                                    tempTarget = u.nextTargetNode[0]
                                    tempTargetPort = u.nextTargetNode[1]
                                    tempRouter = u.nextTargetNode[2]

                                    textR = tempRouter.name.split('-')
                                    if 'ag_router' in textR or 'router' in textR:
                                        pass
                                    else:
                                        tempRouter = None

                                    if errorStatus == False:
                                        tempTargetIP = tempTarget.IPv4Add

                                    ## Firewall is deployed before the access process
                                    if firewallStatus == True and 'ag_attacker' in text:
                                        targetBlockedFW2 = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, tempTargetPort, tempTargetIP, tempTargetPort])

                                    ## IPS is deployed before the access process
                                    if ipsStatus == True and 'ag_attacker' in text:
                                        targetBlockedIPS2, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], self.saveSimDir)
                                            
                                    if targetBlockedIPS2 == True or targetBlockedFW2 == True:
                                        success = False
                                        if targetBlockedIPS2 == True:
                                            print("Access has been blocked by IPS!") #, u.name, tempTarget.name)
                                            pass

                                        if targetBlockedFW2 == True:
                                            print("Access has been denied by firewall!")
                                            pass
                                    else:
                                        if errorStatus == False:
                                            success, portNum, data, redo, changeMethod = self.bruteForceAttackForCredentialExploitation(u, tempTarget, tempTargetPort, u.exploitType, fw)
                                            goThruAP = True

                                    ## IDS is deployed after the access process
                                    if goThruAP == True and idsStatus == True: #success == True
                                        triggerAlert2 = False
                                        triggerAlert2 = fw.intrusionDetectionSystem([u.protocol, u.IPv4Add, tempTargetPort, "->", tempTargetIP, tempTargetPort, u.content[1], u.accessTime], logType, self.saveSimDir)
                                        
                                        if triggerAlert2 == True:
                                            self.createNewRule(u, fw, tempTarget, tempTargetPort)
                                    
                                    tempDN = self.deviceRebootPeriodically(u.accumulatedTime)
                                    if u.name in tempDN or tempTarget.name in tempDN:
                                        success = False
                                        print("yes. found. reboot2", u.name, tempTarget.name)
                                        if redo == True:
                                            redo = False

                                    templistInOut1 = []
                                    if 'ag_attacker' in text:
                                        templistInOut1.append("INOUT")
                                        templistInOut1.append(u.name)
                                        templistInOut1.append(tempTarget.name)
                                        templistInOut1.append(u.accumulatedTime)
                                        templistInOut1.append(u.binaryName[1])
                                        self.inOutTrafficTimeline.append(templistInOut1)

                                    if success == True and u.conditionNow != "rebooting" and tempTarget.conditionNow != "rebooting":
                                        tempAttackData = []
                                        u.accumulatedTime += u.accessTime
                                        attacksDict[x]["accumulatedTime"] = u.accumulatedTime

                                        if u.propagationType == "async" or u.propagationType == "sync2":
                                            u.status = 3
                                        elif u.propagationType == "sync1":
                                            u.status = 5
                                        else:
                                            print("Invalid status!", u.status, u.propagationType)

                                        temp.append("AS")
                                        temp.append(u.accessTime)
                                        temp.append(u.accumulatedTime)
                                        temp.append(tempTarget.name)
                                        u.timeline.append(temp)
                                        tempAttackData.append(u)
                                        tempAttackData.append(tempTarget)
                                        tempAttackData.append(success)
                                        tempAttackData.append(portNum)
                                        tempAttackData.append(data)
                                        tempAttackData.append(u.content)
                                        tempAttackData.append(tempRouter)
                                        u.attackData = tempAttackData

                                        if success == True and u.exploitType[0] == "mixed-c":
                                            u.exploitType[0] = "mixed-v"
                                        
                                    else:
                                        if u.conditionNow != "rebooting":
                                            
                                            u.accumulatedTime += u.accessTime#/2
                                            attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                            
                                            temp.append("AF")
                                            temp.append(u.accessTime)
                                            temp.append(u.accumulatedTime)
                                            temp.append(tempTarget.name)
                                            u.timeline.append(temp)

                                            tempFP = []
                                            tempFP.append("AF")
                                            tempFP.append(self.simplifyNodeName(u.name)[0])
                                            tempFP.append(self.simplifyNodeName(tempTarget.name)[0])
                                            tempFP.append(u.accumulatedTime)

                                            self.failProcess.append(tempFP)

                                            if redo == True:
                                                u.carryCredential = wlg.attackerWordList(u.exploitType[1], u.exploitType[2])
                                            u.status = 1

                                            #To avoid infinite scanning & accessing
                                            if 'ag_attacker' in text:
                                                for y in attackerDict:
                                                    if str(y) == u.name:
                                                        attackerDict[y]["attempt"] += 1
                                                        
                                                        if attackerDict[y]["attempt"] > 250: #>50: #if attempt is more than 50, stop the scanning.
                                                            u.status = 0
                                                            print("4444444444444")
                                                        break
                                                if u.mode == "global":
                                                    if len(targetDict[u.name]["targets"]) > 0:
                                                        self.changeListOrder(targetDict[u.name]["targets"])
                                            else:
                                                stopScan = False

                                                if len(u.timeline) >= 5:
                                                    tempNameAF = None
                                                    tempNumAF = 0
                                                    for i in range(1, len(u.timeline)):
                                                        if u.timeline[0-i][0] == "AF":
                                                            if tempNameAF == None:
                                                                tempNameAF = u.timeline[0-i][3]
                                                            else:
                                                                if u.timeline[0-i][3] == tempNameAF:
                                                                    tempNumAF += 1
                                                                else:
                                                                    break
                                                        if u.exploitType[0] == "general":
                                                            if tempNumAF > 5:
                                                                stopScan = True
                                                                print("break 1")
                                                                break
                                                        elif u.exploitType[0] == "vuln":
                                                            if tempNumAF > len(u.scanPort):
                                                                stopScan = True
                                                                print("break 2")
                                                                break
                                                            else:
                                                                self.changeScanPortOrder(u.scanPort)
                                                        elif u.exploitType[0] == "mixed-v":
                                                            if tempNumAF > len(u.scanPort):
                                                                u.exploitType[0] = "mixed-c"
                                                                print("break 3")
                                                                break
                                                        elif u.exploitType[0] == "dc" or u.exploitType[0] == "mixed-c":
                                                            wordlistlen = wlg.getWordListLen(u.exploitType[2])
                                                            if tempNumAF > (wordlistlen*0.5):
                                                                stopScan = True
                                                                print("break 4")
                                                                break
                                                        else:
                                                            print("not found!")

                                                if stopScan == True:
                                                    if tempTarget.name in u.CNCNode[0].avoidList:
                                                        if str(tempTargetPort) in u.CNCNode[0].avoidList[tempTarget.name]:
                                                            if u.CNCNode[0].avoidList[tempTarget.name][tempTargetPort]["num"] >= len(tempTarget.realPort):
                                                                u.CNCNode[0].avoidList[tempTarget.name][tempTargetPort]["avoid"] = True
                                                            else:
                                                                u.CNCNode[0].avoidList[tempTarget.name][tempTargetPort]["num"] += 1
                                                        else:
                                                            tempNewDict = {tempTargetPort : {'num': 1, 'avoid': False}}
                                                            u.CNCNode[0].avoidList[tempTarget.name].update(tempNewDict)
                                                            
                                                    else:
                                                        tempnewdict = {tempTarget.name : {tempTargetPort : {"num" : 1, "avoid" : False}}}
                                                        u.CNCNode[0].avoidList.update(tempnewdict)

                                            if u.status == 0 and u.nextAction > 0 and 'ag_attacker' not in text and u.nextAction != 66:
                                                u.status = u.nextAction
                                        else:
                                            u.status = 0

                                    u.nextTargetNode.clear()
                                    u.targetPort.clear()
                                else:
                                    pass

                            ###############################################
                            elif u.status == 3: # status = '3' = REPORT TO CNC
                                
                                targetBlocked2 = False
                                text1 = u.name.split("-")

                                templistInOut2 = []

                                if 'ag_attacker' in text:
                                    pass
                                else:
                                    templistInOut2.append("OUT")
                                    templistInOut2.append(u.name)
                                    templistInOut2.append(u.CNCNode[0].name)
                                    templistInOut2.append(u.accumulatedTime)
                                    templistInOut2.append(u.log[1])
                                    self.inOutTrafficTimeline.append(templistInOut2)

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
                                        self.reportToCNCServer(u.attackData, u.CNCNode, u.propagationType)
                                        u.accumulatedTime += u.reportTime
                                        attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                        
                                        temp.append("RS")
                                        temp.append(u.reportTime)

                                        temp.append(u.accumulatedTime)

                                        u.timeline.append(temp)

                                        if u.propagationType == "async":
                                            if 'ag_attacker' in text1:
                                                u.status = 0 #Proceed to 0 for ag_attacker (1st time)
                                            else:
                                                if u.nextAction == 0:
                                                    u.status = 1
                                                else:
                                                    u.status = u.nextAction
                                            tempAttackers = []
                                            tempAttackers.append(u.name)
                                            temp1 = [u.CNCNode[0], u.attackData]
                                            if len(u.binaryName) > 0:
                                                tempLog = u.binaryName
                                            else:
                                                tempLog = u.log

                                            tempcncInstallDict = {'startTime': u.accumulatedTime, 'cncNodeNData': temp1, 'atkerSign': tempLog}
                                            temp1cncInstallDict = dict(zip(tempAttackers, [tempcncInstallDict]))
                                            self.cncInstallDict.update(temp1cncInstallDict)

                                        elif u.propagationType == "sync2": # or u.propagationType == "sync1":
                                            u.status = 5
                                        else:
                                            print("Something is wrong here!!")

                            ###############################################
                            elif u.status == 5: # status = '5' = DOWNLOAD BINARY INSTALL MALWARE via Bot (Synchronous Propagation)

                                v = u.attackData[1]
                                text1 = u.name.split("-")
                                botISpatched = None
                                proceed5 = True
                                tempDN = self.deviceRebootPeriodically(u.accumulatedTime)

                                if u.name in tempDN or v.name in tempDN:
                                    proceed5 = False
                                    print("yes. found. reboot3", u.name, v.name)

                                if v.credentialPort[1] == True and proceed5 == True and u.conditionNow != "rebooting" and v.conditionNow != "rebooting":
                                    portNum = u.attackData[3]
                                    tempPath = []
                                    deviceReboot, surviveFromReboot, tempName = self.downloadBinaryInstallMalware(u, v, portNum, u.CNCNode[0], fw, botISpatched)
                                    
                                    templistInOut3 = []
                                    if 'ag_attacker' in text1:
                                        templistInOut3.append("INOUT")
                                        templistInOut3.append(u.name)
                                        templistInOut3.append(v.name)
                                        templistInOut3.append(u.accumulatedTime)
                                        templistInOut3.append(u.binaryName[1])
                                        self.inOutTrafficTimeline.append(templistInOut3)
                                    
                                    if deviceReboot == True:
                                        v.accumulatedTime = u.accumulatedTime + u.infectionTime + 0.5
                                        temp.append("RB")
                                        tempTime = u.infectionTime + 0.5
                                        temp.append(tempTime)
                                        temp.append(v.accumulatedTime)
                                        v.timeline.append(temp)
                                        text = u.name.split("-")
                                        if 'ag_attacker' in text:
                                            for y in attackerDict:
                                                if str(y) == u.name:
                                                    attackerDict[y]["attempt"] += 1
                                                    if attackerDict[y]["attempt"] > 250: #>50: #if attempt is more than 50, stop the scanning.
                                                        u.status = 0
                                                        print("66666666666662")
                                                    else:
                                                        u.status = 1
                                    
                                    if deviceReboot == True and surviveFromReboot[0] == True:
                                        self.malwareInstallation(u, v, u.CNCNode[0], portNum)
                                        self.afterInstallation(u, v, surviveFromReboot, u.CNCNode[0])
                                        v.conditionNow = "busy"
                                        templistInOut4 = []
                                        if 'ag_attacker' in text1:
                                            templistInOut4.append("INOUT")
                                            templistInOut4.append(u.name)
                                            templistInOut4.append(v.name)
                                            templistInOut4.append(u.accumulatedTime)
                                            templistInOut4.append(u.binaryName[1])
                                            self.inOutTrafficTimeline.append(templistInOut4)

                                    if deviceReboot == False or (deviceReboot == True and surviveFromReboot[0] == True):
                                        u.accumulatedTime += u.infectionTime
                                        attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                        v.accumulatedTime = u.accumulatedTime
                                        if 'ag_attacker' in text1:
                                            u.status = 0 #Proceed to 0 for ag_attacker (1st time)
                                        else:
                                            if u.nextAction == 0:
                                                u.status = 1
                                            else:
                                                u.status = u.nextAction

                                        temp.append("IS")
                                        temp.append(u.infectionTime)
                                        temp.append(u.accumulatedTime)
                                        temp.append(v.name)
                                        if u.propagationType == "sync1":
                                            tempT = u.timeline[-2]
                                        else:
                                            tempT = u.timeline[-3]
                                        u.timeline.append(temp)
                                        
                                        if len(u.binaryName) > 0:
                                            tempText = "ag_" + str(u.binaryName[1])
                                        elif len(u.log) > 0 and u.propagation == True:
                                            tempText = "ag_" + str(u.log[1])
                                        else:
                                            print("wrong")
                                            tempText = ""

                                        if tempText == "":
                                            pass
                                        else:
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
                                        self.timelineDict['endTime'].append(u.accumulatedTime)
                                        text2 = v.name.split('+')
                                        tempData = ""
                                        if 'ag_decoy' in text2 or 'decoy' in text2:
                                            if len(u.binaryName) > 0:
                                                self.timelineDict['compBy'].append(u.binaryName[1])
                                                tempData = u.binaryName[1]
                                            elif len(u.log) > 0:
                                                self.timelineDict['compBy'].append(u.log[1])
                                                tempData = u.log[1]
                                            else:
                                                self.timelineDict['compBy'].append(botISpatched)
                                                tempData = botISpatched
                                        else:
                                            self.timelineDict['compBy'].append(v.log[1])
                                            tempData = v.log[1]

                                        if 'ag_attacker' in text1:
                                            disconnectTwoWays(u, v)
                                    

                                    if v.comp == True:
                                        tempPath = self.setupTempPath(u, v, botISpatched, tempName, tempPath)

                                    if tempPath != None:
                                        self.tempLongPath.append(tempPath)
                                        tempPath2.append(tempPath)

                                    if tempPath != None:
                                        for z in attackerDict:
                                            text3 = z.split("_") 
                                            if str(tempData) in text3:
                                                attackerDict[z]["path"].append(tempPath)
                                                attackerDict[z]["path"].append(u.accumulatedTime)

                                    self.time += 1

                                    if self.time <= 120: # limit the generation of picture
                                        createGraph(self, "propagation {}".format(str(self.time)), self.saveSimDir)
                                else:
                                    if u.conditionNow != "rebooting" and v.conditionNow != "rebooting":
                                        u.accumulatedTime += u.infectionTime
                                        attacksDict[x]["accumulatedTime"] = u.accumulatedTime
                                        
                                        
                                        temp.append("IF")
                                        temp.append(u.infectionTime)
                                        temp.append(u.accumulatedTime)
                                        temp.append(v.name)
                                        u.timeline.append(temp)
                                        
                                    if u.nextAction == 0:
                                        u.status = 1
                                    else:
                                        u.status = u.nextAction
                                    #To avoid infinite scanning
                                    if 'ag_attacker' in text1: 
                                        for y in attackerDict:
                                            if str(y) == u.name:
                                                attackerDict[y]["attempt"] += 1
                                                if attackerDict[y]["attempt"] > 250: #>50: #if attempt is more than 50, stop the scanning.
                                                    u.status = 0
                                                    print("66666666666661")
                                                else:
                                                    u.status = 1
                                    else:
                                        if len(u.scanPort) > 1 and (u.exploitType[0] == 'general' or u.exploitType[0] == 'vuln' or u.exploitType[0] == 'mixed-v'):
                                            self.changeScanPortOrder(u.scanPort)

                            ###############################################
                            elif u.status == 66: # status = '66' = DDoS Attack

                                if u.CNCNode[0].botActionList[3] != None and u.CNCNode[0].botActionList[4] != 0:
                                    u.botAttackList.append(u.CNCNode[0].botActionList[3])
                                    u.botAttackList.append(u.CNCNode[0].botActionList[4])

                                attackSuccess, targetDDoSNode = self.ddosAttackStart(u, u.CNCNode[0])
                                deviceReboot = False
                                
                                if attackSuccess == True:
                                    for a in u.CNCNode[0].botTaskList:
                                        if a[0] == "ddos":
                                            u.resourceMeterCurrent += int(a[2])
                                            break

                                    deviceReboot, surviveFromReboot, cncN = self.deviceReboot(u, 0)
                                
                                if attackSuccess == True and deviceReboot == True:
                                    u.accumulatedTime = u.accumulatedTime + float(u.rebootable[3])#0.5

                                    self.ddosAttackFail(u, targetDDoSNode)

                                    temp.append("RB")
                                    print("RB4", u.name)
                                    tempTime = float(u.rebootable[3])
                                    temp.append(tempTime)
                                    temp.append(u.accumulatedTime)
                                    u.timeline.append(temp)

                                elif attackSuccess == True and deviceReboot == False:
                                    
                                    templistInOut66 = []

                                    templistInOut66.append("OUT")
                                    templistInOut66.append(u.name)
                                    templistInOut66.append(targetDDoSNode.name)
                                    templistInOut66.append(u.accumulatedTime)
                                    templistInOut66.append(u.log[1])
                                    self.inOutTrafficTimeline.append(templistInOut66)

                                    targetDDoSNode.timeline.append(u)
                                    targetDDoSNode.timeline.append("DDoS")
                                    targetDDoSNode.timeline.append(u.accumulatedTime)
                                    targetDDoSNode.timeline.append(float(u.botAttackList[1]))

                                    u.accumulatedTime += float(u.botAttackList[1])
                                    targetDDoSNode.timeline.append(u.accumulatedTime)
                                    temp.append("DS")
                                    temp.append(float(u.botAttackList[1]))
                                    temp.append(u.accumulatedTime)
                                    
                                    u.timeline.append(temp)

                                    # return the resourcemeter to normal numbers after ddos attack
                                    for b in u.CNCNode[0].botTaskList:
                                        if b[0] == "ddos":
                                            u.resourceMeterCurrent -= int(b[2])
                                            break

                                    u.nextAction = 0
                                    u.status = 1
                                else:
                                    u.accumulatedTime += 1.0 
                                
                                    temp.append("DF")
                                    temp.append(1.0)
                                    temp.append(u.accumulatedTime)
                                    u.timeline.append(temp)
                                        
                                    u.nextAction = 0
                                    u.status = 1

                            ###############################################
                            elif u.status == 77: # status = '77' = PDoS Attack
                                self.pdosAttack(u) 
                                u.accumulatedTime += 1.0
                                temp.append("PDoS")
                                temp.append(1.0)
                                temp.append(u.accumulatedTime)
                                u.timeline.append(temp)
                                u.nextAction = 0
                                u.status = 0
                                
                            ###############################################
                            elif u.status == 88: # status = '88' = Data Exfiltration
                                self.dataExfiltration(u, u.CNCNode[0])
                                u.accumulatedTime += 1.0
                                templistInOut66 = []

                                templistInOut66.append("OUT")
                                templistInOut66.append(u.name)
                                templistInOut66.append(u.CNCNode[0].name)
                                templistInOut66.append(u.accumulatedTime)
                                templistInOut66.append(u.log[1])
                                self.inOutTrafficTimeline.append(templistInOut66)

                                temp.append("DEx")
                                temp.append(1.0)
                                temp.append(u.accumulatedTime)
                                u.timeline.append(temp)

                                u.nextAction = 0
                                u.status = 1

                            else:
                                print(u.name, "no status found!!")
                else:                
                    if u.name == 'Intelligence Center':
                        fw.DBFIntelligenceCenter(self, u, "check", attacksDict[x]["targetDBFNode"], self.saveSimDir)
                        print("DBF check")
                        attacksDict[x]["accumulatedTime"] += attacksDict[x]["meanTime"]
                    elif u.name == 'SDN switch':
                        fw.movingTargetDefence(self, self.defMode["MTD"]["mode"], 0, attacksDict[x]["nodenum"], attacksDict[x]["shufflelist"], attacksDict[x]["isolationlist"], attacksDict[x]["resetlist"], attacksDict[x]["restorelist"])
                        print("MTD shuffling -- ", attacksDict[x]["accumulatedTime"])
                        attacksDict[x]["accumulatedTime"] += attacksDict[x]["meanTime"]

                        if len(self.defMode["MTD"]["restorelist"]) > 0:
                            print("MTD restoring -- ")
                            print(self.defMode["MTD"]["restorelist"])
                            fw.movingTargetDefence(self, 6, 0, 0, None, None, None, self.defMode["MTD"]["restorelist"])
                            self.defMode["MTD"]["restorelist"] = []
                            print(self.defMode["MTD"]["restorelist"])

                        if len(self.defMode["MTD"]["resetlist"]) > 0:
                            print("MTD reseting node -- ")
                            print(self.defMode["MTD"]["resetlist"])
                            fw.movingTargetDefence(self, 5, 0, 0, None, None, self.defMode["MTD"]["resetlist"], None)
                            self.defMode["MTD"]["resetlist"] = []
                            print(self.defMode["MTD"]["resetlist"])

                        if len(self.defMode["MTD"]["isolationlist"]) > 0:
                            print("MTD isolating -- ")
                            print(self.defMode["MTD"]["isolationlist"])
                            fw.movingTargetDefence(self, 4, 0, 0, None, self.defMode["MTD"]["isolationlist"], self.defMode["MTD"]["resetlist"], self.defMode["MTD"]["restorelist"])
                            self.defMode["MTD"]["isolationlist"] = []
                            print(self.defMode["MTD"]["isolationlist"])

        ###############################################
        lastTime = int(self.time)

        if len(self.cncInstallDict) > 1 and "CNCX" in self.cncInstallDict:
            self.cncInstallDict.pop("CNCX")

        if len(self.cncInstallDict) > 1:
            self.cncInstallDict = self.sortDict2(self.cncInstallDict)

        # status = '4' = DOWNLOAD BINARY INSTALL MALWARE via CNC (Asynchronous Propagation)
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
                            x.CNCMemory[v.name] = 1 #= {v.name : 1}

                    else:
                        if portNum == "p0":
                            if v.credentialPort[1] == True:
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

                    if len(u.binaryName) > 0:
                        tempText = "ag_" + str(u.binaryName[1])
                    elif len(u.log) > 0 and u.propagation == True:
                        tempText = "ag_" + str(u.log[1])
                    elif len(self.cncInstallDict[a]['atkerSign']) > 0:
                        if u.conditionNow == "rebooting":
                            print(u.name, " (bot) is rebooting...")
                            lastCheck = False
                        elif v.conditionNow == "rebooting":
                            print(v.name, " (target) is rebooting...")
                            lastCheck = False
                        else:
                            tempText = "ag_" + str(self.cncInstallDict[a]['atkerSign'][1])
                            print(u.name, " was patched! ", u.accumulatedTime, u.infectionTime)
                            botISpatched = tempText
                            lastCheck = False
                    else:
                        print(u.name, " was patched! Attack failed.")
                        lastCheck = False

                    tempDN = self.deviceRebootPeriodically(u.accumulatedTime)
                    if u.name in tempDN or v.name in tempDN:
                        lastCheck = False
                        print("yes. found. reboot4", u.name, v.name)

                    if lastCheck == True and u.conditionNow != "rebooting" and v.conditionNow != "rebooting":
                        surviveFromReboot = [False]
                        deviceReboot, surviveFromReboot, tempName = self.downloadBinaryInstallMalware(u, v, portNum, x, fw, botISpatched)
                        tempData = ""
                        templistInOut5 = []
                        templistInOut5.append("IN")
                        templistInOut5.append(x.name)
                        templistInOut5.append(v.name)
                        templistInOut5.append(u.accumulatedTime)
                        templistInOut5.append(x.binaryName[1])
                        self.inOutTrafficTimeline.append(templistInOut5)
                            
                        if deviceReboot == True:
                            v.accumulatedTime = u.accumulatedTime + u.infectionTime + 0.5
                            temp.append("RB")
                            print("RB")
                            tempTime = u.infectionTime + 0.5
                            temp.append(tempTime)
                            temp.append(v.accumulatedTime)
                            v.timeline.append(temp)
                            text = u.name.split("-")
                            if 'ag_attacker' in text:
                                for y in attackerDict:
                                    if str(y) == u.name:
                                        attackerDict[y]["attempt"] += 1
                                        if attackerDict[y]["attempt"] > 250: #>50: #if attempt is more than 50, stop the scanning.
                                            u.status = 0
                                            print("66666666666661")
                                        else:
                                            u.status = 1
                            
                        if deviceReboot == True and surviveFromReboot[0] == True:
                            self.malwareInstallation(u, v, x, portNum)

                            self.afterInstallation(u, v, surviveFromReboot, x)
                            v.conditionNow = "busy"
                            templistInOut6 = []
                            templistInOut6.append("INOUT")
                            templistInOut6.append(v.name)
                            templistInOut6.append(x.name)
                            templistInOut6.append(v.accumulatedTime)
                            templistInOut6.append(v.log[1])
                            self.inOutTrafficTimeline.append(templistInOut6)

                        if deviceReboot == False or (deviceReboot == True and surviveFromReboot[0] == True):
                            v.accumulatedTime = u.accumulatedTime + u.infectionTime
                            temp.append("IS")
                            temp.append(u.infectionTime)
                            temp.append(v.accumulatedTime)
                            temp.append(v.name)
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
                            startTime = tempT[2] - tempT[1]
                            self.timelineDict['startTime'].append(startTime)
                            self.timelineDict['endTime'].append(v.accumulatedTime)
                            text2 = v.name.split('+')
                            
                            if 'ag_decoy' in text2 or 'decoy' in text2:
                                if len(u.binaryName) > 0:
                                    self.timelineDict['compBy'].append(u.binaryName[1])
                                    tempData = u.binaryName[1]
                                elif len(u.log) > 0:
                                    self.timelineDict['compBy'].append(u.log[1])
                                    tempData = u.log[1]
                                else:
                                    self.timelineDict['compBy'].append(botISpatched)
                                    tempData = botISpatched
                            else:
                                self.timelineDict['compBy'].append(v.log[1])
                                tempData = v.log[1]

                            text = u.name.split("-")
                            if 'ag_attacker' in text:
                                disconnectTwoWays(u, v)

                        if v.comp == True:
                            tempPath = self.setupTempPath(u, v, botISpatched, tempName, tempPath)

                        if tempPath != None:
                            self.tempLongPath.append(tempPath)
                            tempPath2.append(tempPath)
                        
                            if y in x.attackData:
                                x.attackData.remove(y)

                            for z in attackerDict:
                                text = z.split("_") 
                                if str(tempData) in text:
                                    attackerDict[z]["path"].append(tempPath)
                                    attackerDict[z]["path"].append(v.accumulatedTime)

                        self.time += 1

                        if self.time <= 120: # limit the generation of picture
                            createGraph(self, "propagation {}".format(str(self.time)), self.saveSimDir)
                    else:
                        if u.conditionNow != "rebooting" and v.conditionNow != "rebooting":
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
                            
                            
                            if str(v.name) in targetDict[tempText]["onHold"]:
                                targetDict[tempText]["remaining"] = [v.name] + targetDict[tempText]["remaining"]
                                targetDict[tempText]["onHold"].remove(str(v.name))
                        else:
                            if y in x.attackData:
                                x.attackData.remove(y)

                        #To avoid infinite scanning
                        text = u.name.split("-")
                        if 'ag_attacker' in text: 
                            for y in attackerDict:
                                if str(y) == u.name:
                                    attackerDict[y]["attempt"] += 1
                                    if attackerDict[y]["attempt"] > 250: #>50: #if attempt is more than 50, stop the scanning.
                                        u.status = 0
                                        print("6666666666666")
                                    else:
                                        u.status = 1
                        else:
                            if len(u.scanPort) > 1:
                                self.changeScanPortOrder(u.scanPort)

                        if len(x.CNCMemory) > 0:
                            if x.IPv4Add in x.CNCMemory:
                                if x.CNCMemory[x.IPv4Add]["attempt"] >= 20: #200: changed to 10 to save space
                                    u.status = 0
                                    print("7777777777")

                            if v.name in x.CNCMemory:
                                if x.CNCMemory[v.name] >= 5:
                                    print("888888888888")
                                    if len(u.binaryName) > 0:
                                        tempText = "ag_" + str(u.binaryName[1])
                                    else:
                                        tempText = "ag_" + str(u.log[1])
                                    if u.mode == "global":
                                        if v.name in targetDict[tempText]["remaining"]:
                                            targetDict[tempText]["remaining"].remove(str(v.name))
                                            

                        if v.name in x.avoidList:
                            if portNum in x.avoidList[v.name]:
                                if x.avoidList[v.name][portNum]["num"] >= len(v.realPort):
                                    x.avoidList[v.name][portNum]["avoid"] = True
                                else:
                                    x.avoidList[v.name][portNum]["num"] += 1
                            else:
                                tempNewDict = {portNum : {'num': 1, 'avoid': False}}
                                x.avoidList[v.name].update(tempNewDict)
                        else:
                            tempnewdict2 = {v.name : {portNum : {'num' : 1, 'avoid' : False}}}
                            x.avoidList.update(tempnewdict2)

                    ## IPS is deployed after CNC to target node
                    if idsStatus == True:
                        triggerAlert3 = False
                        triggerAlert3 = fw.intrusionDetectionSystem([u.protocol, x.IPv4Add, portNum, "->", v.IPv4Add, portNum, content[2], u.infectionTime], logType, self.saveSimDir)
                        if triggerAlert3 == True:
                            print("Trig 3 : ", triggerAlert3)
                            self.createNewRule(x, fw, v, portNum)
                            
                        
        #Check for ddos attack
        attacksDict = self.sortDict(attacksDict)
        accumulatedTimeNow = None
        for x in attacksDict:
            temptext = x.split('-')
            if 'DBF' not in temptext and 'SDN' not in temptext:
                accumulatedTimeNow = attacksDict[x]["accumulatedTime"]
                break
        for x in CNC:
            if len(x.botActionList) > 0:
                if x.botActionList[0] == "ddos":
                    if len(x.listofBots) >= int(x.botActionList[1]):
                        tempNum = len(x.listofBots)
                        for y in x.listofBots:

                            y.nextAction = 66
                            tempNum -= 1
                            
                            templistInOut7 = []
                            templistInOut7.append("IN")
                            templistInOut7.append(x.name)
                            templistInOut7.append(y.name)
                            templistInOut7.append(accumulatedTimeNow)
                            templistInOut7.append(y.log[1])

                            self.inOutTrafficTimeline.append(templistInOut7)

                            if tempNum <= int(x.botActionList[2]):
                                break

                        if x.botActionList[3] == "random":
                            tempDDoSTargets = []
                            for z in self.nodes:
                                text = z.name.split("-")
                                if 'ag_server' in text or 'server' in text:
                                    tempDDoSTargets.append(z)
                            newDDoSTarget = choice(tempDDoSTargets)

                            x.botActionList[3] = newDDoSTarget.IPv4Add

                elif x.botActionList[0] == "pdos":
                    if len(x.listofBots) >= int(x.botActionList[1]):
                        tempNum = len(x.listofBots)
                        for y in x.listofBots:
                            tempNodeCount = 0

                            for z in y.con:
                                if z.healthy == True and z.canBeCompromised == True:
                                    tempNodeCount += 1

                            if tempNodeCount <= 1:
                                y.nextAction = 77
                                tempNum -= 1

                                templistInOut7 = []
                                templistInOut7.append("IN")
                                templistInOut7.append(x.name)
                                templistInOut7.append(y.name)
                                templistInOut7.append(accumulatedTimeNow)
                                templistInOut7.append(y.log[1])

                                self.inOutTrafficTimeline.append(templistInOut7)

                elif x.botActionList[0] == "exfiltrate data":
                    for y in x.listofBots:

                        if y.name not in x.networkDataRecord:
                            y.nextAction = 88

                            templistInOut7 = []
                            templistInOut7.append("IN")
                            templistInOut7.append(x.name)
                            templistInOut7.append(y.name)
                            templistInOut7.append(accumulatedTimeNow)
                            templistInOut7.append(y.log[1])

                            self.inOutTrafficTimeline.append(templistInOut7)

        #Check goal method
        for x in CNC:
            for y in x.goal:
                m = 0
                if y[2] == False:
                    for z in self.nodes:
                        text = z.name.split("-")
                        if 'ag_attacker' in text or 'ag_CNC' in text or 'ag_server' in text:
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
            if u.name != 'Intelligence Center' and u.name != 'SDN switch':
                if u.status > 0 and u.conditionNow != "rebooting":
                    tempAttackers = []
                    tempAttackers.append(u.name)
                    temp = None
                    if len(u.binaryName) > 0:
                        temp = u.binaryName
                    else:
                        temp = u.log #wrong
                    tempAttacksdict = dict(attackerNode = [u], accumulatedTime = u.accumulatedTime, timeline = u.timeline, meanTime = u.meanTime, ownBy = temp)

                    if len(tempDict) == 0:
                        tempDict = dict(zip(tempAttackers, [tempAttacksdict]))
                    else:
                        temp = dict(zip(tempAttackers, [tempAttacksdict]))
                        tempDict.update(temp)

        tempDBFdict = {}

        tempSDNdict = {}
        if self.defMode["MTD"]["operational"] == True:
            for x in attacksDict:
                temptext = x.split('-')
                if 'SDN' in temptext:
                    if len(tempSDNdict) == 0:
                        tempSDNdict = {x: {'attackerNode' : attacksDict[x]['attackerNode'], 'accumulatedTime' : attacksDict[x]['accumulatedTime'], 'timeline' : attacksDict[x]['timeline'], 'meanTime' : attacksDict[x]['meanTime'], 'shufflelist' : attacksDict[x]["shufflelist"], 'nodenum' : attacksDict[x]["nodenum"], 'isolationlist' : attacksDict[x]["isolationlist"], 'resetlist' : attacksDict[x]["resetlist"], 'restorelist' : attacksDict[x]["restorelist"]}}
                    else:
                        temp = {x: {'attackerNode' : attacksDict[x]['attackerNode'], 'accumulatedTime' : attacksDict[x]['accumulatedTime'], 'timeline' : attacksDict[x]['timeline'], 'meanTime' : attacksDict[x]['meanTime'], 'shufflelist' : attacksDict[x]["shufflelist"], 'nodenum' : attacksDict[x]["nodenum"], 'isolationlist' : attacksDict[x]["isolationlist"], 'resetlist' : attacksDict[x]["resetlist"], 'restorelist' : attacksDict[x]["restorelist"]}}
                        tempSDNdict.update(temp)

        if tempDict != None:
            attacksDict = tempDict
            if len(tempDBFdict) > 0:
                attacksDict.update(tempDBFdict)
            if len(tempSDNdict) > 0:
                attacksDict.update(tempSDNdict)

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
            elif len(attacksDict) == 1:
                for x in attacksDict:
                    text = x.split('-')
                    if 'DBF' in text or 'SDN' in text:
                        allGoal = 0
        
        if allGoal > 0 and percentage < 100:
            val += self.simAtk(attacksDict, attackerDict, targetDict, hopValueDict, fw, wlg)  
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

                if b.collude == True:
                    cnc.atkInfoDict = attacksdict
                else:
                    cnc.atkInfoDict = dict(zip([b.name], [tempAttacksdict]))

        self.atkerList = self.atk
        self.tgtList = self.tgt
        self.path = []

        createVulnerableHostPercentageChart(self, self.saveSimDir)
        fw = defenceMethods()
        wlg = wordlistGen()

        mtdStatus = False
        
        MTDdict = {}
        if self.defMode["MTD"]["operational"] == True:
            for x in self.nodes:
                text = x.name.split(' ')
                if 'SDN' in text: 

                    tempName = str(text[0]) + '-' + str(text[-1])
                    if len(MTDdict) == 0:
                        MTDdict = {tempName: {'attackerNode' : [x], 'accumulatedTime' : self.defMode["MTD"]["shuffletime"], 'timeline' : [], 'meanTime' : self.defMode["MTD"]["shuffletime"], 'shufflelist' : self.defMode["MTD"]["shufflelist"], 'nodenum' : self.defMode["MTD"]["nodenum"], 'isolationlist' : self.defMode["MTD"]["isolationlist"], 'resetlist' : self.defMode["MTD"]["resetlist"], 'restorelist' : self.defMode["MTD"]["restorelist"]}}
                    else:
                        tempDict = {tempName: {'attackerNode' : [x], 'accumulatedTime' : self.defMode["MTD"]["shuffletime"], 'timeline' : [], 'meanTime' : self.defMode["MTD"]["shuffletime"], 'shufflelist' : self.defMode["MTD"]["shufflelist"], 'nodenum' : self.defMode["MTD"]["nodenum"], 'isolationlist' : self.defMode["MTD"]["isolationlist"], 'resetlist' : self.defMode["MTD"]["resetlist"], 'restorelist' : self.defMode["MTD"]["restorelist"]}}
                        MTDdict.update(tempDict)
                    
            attacksdict.update(MTDdict)

        val = self.simAtk(attacksdict, attackerdict, targetDict, hopValueDict, fw, wlg) #The value records recursion times  

        treeGraphFilename = []

        createInOutTrafficTimelineCSV(self.inOutTrafficTimeline, self.saveSimDir)
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

                if b.conditionNow == "disable" or b.conditionNow == "crashed":
                    proceed = False
                elif b.conditionNow == "rebooting":
                    if u.accumulatedTime > b.accumulatedTime:
                        proceed = True
                        b.conditionNow = "enable"
                        b.isRebooting = False
                    else:
                        proceed = False
                else:
                    pass

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
                            if self.defMode["IPS"]["rule"] != None:
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
                
                if tempRouter != None:
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

                if temp.conditionNow == "disable" or temp.conditionNow == "crashed":
                    proceed = False
                elif temp.conditionNow == "rebooting":
                    if u.accumulatedTime > temp.accumulatedTime:
                        proceed = True
                        temp.conditionNow = "enable"
                        temp.isRebooting = False
                    else:
                        proceed = False
                else:
                    pass

                if proceed == True:

                    if u.exploitType[0] == "general" or (u.exploitType[0] == "vuln" and u.exploitType[3] != "authenticationbypass") or (u.exploitType[0] == "mixed-v" and u.exploitType[3] != "authenticationbypass"):# or u.exploitType[0] == "mixed-v":
                        for p in u.scanPort: 
                            firewallProceed = True
                            ipsProceed = True
                            targetBlocked = False
                            if firewallStatus == True:
                                targetBlocked = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, p, temp.IPv4Add, p])

                                if targetBlocked == True:
                                    firewallProceed = False
                            
                            if ipsStatus == True:
                                if self.defMode["IPS"]["rule"] != None:
                                    targetBlocked, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, p, "->", temp.IPv4Add, p, u.content[0], u.scanTime], self.saveSimDir)

                                if targetBlocked == True:
                                    ipsProceed = False

                            if firewallProceed == True and ipsProceed == True:
                                if p == temp.credentialPort[0] and temp.credentialPort[1] == True and u.exploitType[3] == "authenticationbypass":
                                    if temp.healthy == True:
                                        uport = p
                                        vport = p
                                        targetFound = True
                                        
                                        toTarget.append(temp)
                                        toTarget.append(str(p))
                                        toTarget.append(tempRouter)
                                        temp.isTarget = True

                                    else:
                                        if u.group == temp.group:
                                            pass
                                        else:
                                            uport = p
                                            vport = p
                                            targetFound = True
                                            
                                            toTarget.append(temp)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            temp.isTarget = True

                                else:
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
                    elif u.exploitType[0] == "dc" or u.exploitType[0] == "mixed-c" or (u.exploitType[0] == "vuln" and u.exploitType[3] == "authenticationbypass") or (u.exploitType[0] == "mixed-v" and u.exploitType[3] == "authenticationbypass"): # or u.exploitType[0] == "wp":
                        p = 'p0'
                        firewallProceed = True
                        ipsProceed = True
                        targetBlocked = False

                        if firewallStatus == True:
                            targetBlocked = fw.firewall(tempRouter, [u.protocol, u.IPv4Add, p, temp.IPv4Add, p])
                            if targetBlocked == True:
                                firewallProceed = False

                        if ipsStatus == True:
                            if self.defMode["IPS"]["rule"] != None:
                                targetBlocked, replyMsg = fw.intrusionPreventionSystem([u.protocol, u.IPv4Add, p, "->", temp.IPv4Add, p, u.content[0], u.scanTime], self.saveSimDir)

                            if targetBlocked == True:
                                ipsProceed = False

                        if firewallProceed == True and ipsProceed == True:
                            if temp.credentialPort[0] == p:
                                if temp.credentialPort[1] == True:
                                    if temp.healthy == True:
                                        uport = p
                                        vport = p
                                        targetFound = True
                                        
                                        toTarget.append(temp)
                                        toTarget.append(str(p))
                                        toTarget.append(tempRouter)
                                        temp.isTarget = True
                                    else:
                                        if u.group == temp.group:
                                            pass
                                        else:
                                            uport = p
                                            vport = p
                                            targetFound = True
                                            
                                            toTarget.append(temp)
                                            toTarget.append(str(p))
                                            toTarget.append(tempRouter)
                                            temp.isTarget = True

                    else:
                        pass
                nodelist.remove(temp)

        nodeReset = False
        if len(toTarget) > 0:
            for x in toTarget:
                text = (str(x)).split("+")
                if 'ag_decoy' in text or 'decoy' in text:
                    nodeReset = self.dReport(u, x, fw, "Scanning", 0)
        
        if nodeReset == False:
            pass
        else:
            targetFound = False

        if targetFound == False:
            print("Initial target not found!")
            temp = []
            toTarget.append(temp)
                    
        return tempRouter, targetFound, uport, vport
    
    def scanForSubsequentTarget(self, mode, atkNode, targetList, toTarget, fw):
        """
        Scanning for subsequent target from bot
        """
        u = atkNode
        targetFound = False
        targetIsCompromised = False
        if toTarget != None:
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

        nodeReset = False
        if len(toTarget) > 0:
            for x in toTarget:
                text = (str(x)).split("+")
                if 'ag_decoy' in text or 'decoy' in text:
                    nodeReset = self.dReport(u, x, fw, "Scanning", 0)

        if nodeReset == False:
            pass
        else:
            targetFound = False
            SSStatus = None
            uport = ""
            vport = ""
            goThruAP = False

        return targetFound, SSStatus, uport, vport, goThruAP

    # def d2dScanning(self, mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport):
    #     """
    #     Device-to-Device Scanning method
    #     """
    #     targetFound = False
    #     targetIsCompromised = False
    #     APavailable = False
    #     goThruAP = False
    #     mainNode = None
    #     if APnode != None:
    #         mainNode = APnode
    #     else:
    #         mainNode = u

    #     if mode == "global":
    #         if len(targetList) > 0:
    #             tempList = targetList.copy() 
    #             for a in tempList:
    #                 decoyCheck = False
    #                 for v in mainNode.con: #check for same name in direct connection
    #                     text = v.name.split("-")
    #                     text2 = v.name.split("+")
    #                     proceed = True
    #                     if 'ag_CNC' in text or 'ag_attacker' in text:
    #                         proceed == False
    #                     elif 'ag_router' in text:
    #                         proceed == False
    #                         if v.name in APList:
    #                             pass
    #                         else:
    #                             APavailable = True
    #                             APnode = v
    #                             APList.append(v.name)
    #                     elif v.name in u.CNCNode[0].avoidList:
    #                         if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
    #                             proceed == False
    #                     else:
    #                         pass
                            
    #                     if proceed == True:
    #                         #Check for decoy node: if the decoy was compromised previously, it will not proceed or otherwise.
    #                         if 'ag_decoy' in text2 or 'decoy' in text2:
    #                             if u.log in v.dataCollection:
    #                                 SSStatus = False 
    #                                 decoyCheck = True
    #                                 targetIsCompromised = True
    #                             else:
    #                                 #should not be able to go thru here
    #                                 if v.healthy == False:
    #                                     SSStatus = False 
    #                                     decoyCheck = True
                                        

    #                         if decoyCheck == False:
    #                             nodeName = v.name
    #                             if 'ag_decoy' in text2 or 'decoy' in text2:
    #                                 nodeName = "ag_"+str(text2[1])
                                    
    #                             if str(a) == nodeName:
    #                                 tempNum = len(v.realPort)*len(u.scanPort)
    #                                 for p in u.scanPort: 
    #                                     for q in v.realPort:
    #                                         if str(p) == str(q):
    #                                             if v.realPort[q]["open"] == True:
    #                                                 if v.healthy == True:
    #                                                     uport = p
    #                                                     vport = q
    #                                                     v.setTarget()
    #                                                     toTarget.append(v)
    #                                                     toTarget.append(str(p))
    #                                                     toTarget.append(mainNode)
    #                                                     targetFound = True
    #                                                     break
    #                                                 else:
    #                                                     if u.group == v.group:
    #                                                         targetIsCompromised = True
    #                                                         break
    #                                                     else:
    #                                                         uport = p
    #                                                         vport = q
    #                                                         v.setTarget()
    #                                                         toTarget.append(v)
    #                                                         toTarget.append(str(p))
    #                                                         toTarget.append(mainNode)
    #                                                         targetFound = True
    #                                                         break
    #                                             else:
    #                                                 if v.healthy == False and u.group == v.group:
    #                                                     targetIsCompromised = True
    #                                                     SSStatus = False
    #                                                     if a in targetList:
    #                                                         targetList.remove(a)
    #                                                     break
    #                                                 if tempNum > 0:
    #                                                     tempNum -= 1
                                                    
    #                                                 if tempNum == 0:
    #                                                     targetIsCompromised = True
    #                                                     SSStatus = False
    #                                                     if a in targetList:
    #                                                         targetList.remove(a)
    #                                                     break

    #                                     if targetFound == True or targetIsCompromised == True:
    #                                         break
    #                                 if targetFound == True or targetIsCompromised == True:
    #                                     if targetIsCompromised == True:
    #                                         SSStatus = False
    #                                         if a in targetList:
    #                                             targetList.remove(a)
    #                                     break
    #                         else:
    #                             if a in targetList:
    #                                 targetList.remove(a)
    #                                 break
    #                 if targetFound == True:
    #                     break
    #                 # if target still not found, check using stepping stone.
    #                 elif targetFound == False and targetIsCompromised == False:
    #                     for v in mainNode.con:
    #                         text = v.name.split("-")
    #                         text2 = v.name.split("+")
    #                         proceed2 = True
    #                         if 'ag_CNC' in text or 'ag_attacker' in text:
    #                             proceed2 = False
    #                         elif 'ag_router' in text:
    #                             proceed2 = False
    #                             if v.name in APList:
    #                                 pass
    #                             else:
    #                                 APavailable = True
    #                                 APnode = v
    #                                 APList.append(v.name)
    #                         elif v.name in u.CNCNode[0].avoidList:
    #                             if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
    #                                 proceed2 = False
    #                         else:
    #                             pass
                                
    #                         if proceed2 == True:
    #                             if (u.botCoop == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
    #                                 SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, a, True, u.CNCNode, None, None) #(target, nextTarget, cooperation, cncNode, attackerPort, ssPort)
    #                                 if SSStatus == True:
    #                                     if newTarget in toTarget:
    #                                         pass
    #                                     else:
    #                                         tempNum = len(newTarget.realPort)*len(u.scanPort)
    #                                         for p in u.scanPort: 
    #                                             for q in newTarget.realPort:
    #                                                 if str(p) == str(q):
    #                                                     if newTarget.realPort[q]["open"] == True:
    #                                                         if newTarget.healthy == True:
    #                                                             uport = p
    #                                                             vport = q
    #                                                             newTarget.setTarget()
    #                                                             toTarget.append(SSStatus)
    #                                                             toTarget.append(newTarget)
    #                                                             toTarget.append(str(q))
    #                                                             toTarget.append(stepstone)
    #                                                             targetFound = True
    #                                                             break
    #                                                         else:
    #                                                             if u.group == newTarget.group:
    #                                                                 targetIsCompromised = True
    #                                                                 break
    #                                                             else:
    #                                                                 uport = p
    #                                                                 vport = q
    #                                                                 newTarget.setTarget()
    #                                                                 toTarget.append(SSStatus)
    #                                                                 toTarget.append(newTarget)
    #                                                                 toTarget.append(str(q))
    #                                                                 toTarget.append(stepstone)
    #                                                                 targetFound = True
    #                                                                 break
    #                                                     else:
    #                                                         if newTarget.healthy == False and u.group == newTarget.group:
    #                                                             targetIsCompromised = True
    #                                                             SSStatus = False
    #                                                             if a in targetList:
    #                                                                 targetList.remove(a)
    #                                                             break
    #                                                         if tempNum > 0:
    #                                                             tempNum -= 1
                                                            
    #                                                         if tempNum == 0:
    #                                                             #target node is compromised and no open port
    #                                                             SSStatus = False
    #                                                             targetIsCompromised = True
    #                                                             if a in targetList:
    #                                                                 targetList.remove(a)
    #                                                             break
    #                                                 else:
    #                                                     if tempNum > 0:
    #                                                         tempNum -= 1
                                                        
    #                                                     if tempNum == 0:
    #                                                         #target node is compromised and no open port
    #                                                         SSStatus = False
    #                                                         targetIsCompromised = True
    #                                                         if a in targetList:
    #                                                             targetList.remove(a)
    #                                                         break
    #                                                 if targetFound == True or targetIsCompromised == True:
    #                                                     break
    #                                             if targetFound == True or targetIsCompromised == True:
    #                                                 if targetIsCompromised == True:
    #                                                     SSStatus = False
    #                                                     if a in targetList:
    #                                                         targetList.remove(a)
    #                                                 break
    #                                 else:
    #                                     pass
    #                         if targetFound == True or targetIsCompromised == True:
    #                             break
    #                     if targetFound == False and targetIsCompromised == False:
    #                         if APavailable == True:
    #                             toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport)
    #                     if targetFound == True:
    #                         break
    #                 if targetFound == True or targetIsCompromised == True:
    #                     break
    #         else:
    #             print("No more target!!")
    #     else: # local
    #         for v in mainNode.con: #check for same name in direct connection
    #             text = v.name.split("-")
    #             text2 = v.name.split("+")
    #             proceed3 = True
    #             if 'ag_CNC' in text or 'ag_attacker' in text:
    #                 proceed3 = False
    #             elif v.name in u.CNCNode[0].avoidList:
    #                 if u.CNCNode[0].avoidList[v.name]["avoid"] == True:
    #                     proceed3 = False
    #             elif 'ag_router' in text:
    #                 proceed3 = False
    #                 if v.name in APList:
    #                     pass
    #                 else:
    #                     APavailable = True
    #                     APnode = v
    #                     APList.append(v.name)
    #             else:
    #                 pass

    #             if proceed3 == True:
    #                 #Check for decoy node: if the decoy was compromised previously, it will not proceed or otherwise.
    #                 decoyCheck = False
    #                 if 'ag_decoy' in text2 or 'decoy' in text2:
    #                     if u.log in v.dataCollection:
    #                         SSStatus = False 
    #                         decoyCheck = True
    #                     else:
    #                         if v.healthy == False:
    #                             SSStatus = False 
    #                             decoyCheck = True
    #                         else:
    #                             pass

    #                 if decoyCheck == False:
    #                     for p in u.scanPort: 
    #                         for q in v.realPort:
    #                             if str(p) == str(q):
    #                                 if v.realPort[q]["open"] == True:
    #                                     if v.healthy == True:
    #                                         if v in toTarget:
    #                                             pass
    #                                         else:
    #                                             uport = p
    #                                             vport = q
    #                                             v.setTarget()
    #                                             toTarget.append(v)
    #                                             toTarget.append(str(p))
    #                                             toTarget.append(mainNode)
    #                                         targetFound = True
    #                                         break
    #                                     else:
    #                                         if u.group == v.group:
    #                                             pass
    #                                         else:
    #                                             if v in toTarget:
    #                                                 pass
    #                                             else:
    #                                                 uport = p
    #                                                 vport = q
    #                                                 v.setTarget()
    #                                                 toTarget.append(v)
    #                                                 toTarget.append(str(p))
    #                                                 toTarget.append(mainNode)
    #                                             targetFound = True
    #                                             break
                                        
    #                                 elif v.realPort[q]["open"] == False and v.healthy == False:
    #                                     if (u.botCoop == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
    #                                         SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, None, True, u.CNCNode, p, q)#u.targetPort)
    #                                         if SSStatus == True:
    #                                             if newTarget in toTarget:
    #                                                 pass
    #                                             else:
    #                                                 uport = p
    #                                                 vport = q
    #                                                 newTarget.setTarget()
    #                                                 toTarget.append(SSStatus)
    #                                                 toTarget.append(newTarget)
    #                                                 toTarget.append(newTargetPort)
    #                                                 toTarget.append(stepstone)
    #                                             targetFound = True
    #                                             break
    #                                     else:
    #                                         SSStatus = False
    #                                 else:
    #                                     pass
    #                         if targetFound == True:
    #                             break
    #             if targetFound == True:
    #                 break
    #         if targetFound == True:
    #             pass
    #         else:
    #             if APavailable == True:
    #                 toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport)
    #                 goThruAP = True
                
    #     return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    def d2dScanning(self, mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport):
        """
        Device-to-Device Scanning
        """
        targetFound = False
        targetIsCompromised = False
        APavailable = False
        goThruAP = False
        mainNode = None
        if APnode != None:
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
                        if 'ag_CNC' in text or 'ag_server' in text or 'ag_attacker' in text:
                            proceed == False
                        elif 'ag_router' in text:
                            proceed == False
                            if v.name in APList:
                                pass
                            else:
                                APavailable = True
                                APnode = v
                                APList.append(v.name)
                        else:
                            pass
                            
                        if v.conditionNow == "disable" or v.conditionNow == "crashed":
                            proceed = False
                        elif v.conditionNow == "rebooting":
                            if u.accumulatedTime > v.accumulatedTime:
                                v.conditionNow = "enable"
                                v.isRebooting = False
                            else:
                                proceed = False
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
                                            internalProceed = True
                                            if v.name in u.CNCNode[0].avoidList:
                                                if q in u.CNCNode[0].avoidList[v.name]:
                                                    if u.CNCNode[0].avoidList[v.name][q]["avoid"] == True:
                                                        internalProceed = False
                                            if internalProceed == True:
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
                            if 'ag_CNC' in text or 'ag_server' in text or 'ag_attacker' in text:
                                proceed2 = False
                            elif 'ag_router' in text:
                                proceed2 = False
                                if v.name in APList:
                                    pass
                                else:
                                    APavailable = True
                                    APnode = v
                                    APList.append(v.name)
                            else:
                                pass

                            if v.conditionNow == "disable" or v.conditionNow == "crashed":
                                proceed2 = False
                            elif v.conditionNow == "rebooting":
                                if u.accumulatedTime > v.accumulatedTime:
                                    v.conditionNow = "enable"
                                    v.isRebooting = False
                                else:
                                    proceed2 = False
                            else:
                                pass
                                
                            if proceed2 == True:
                                if (u.botCollude == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
                                    SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, a, True, u.CNCNode, None, None) #(target, nextTarget, collusion, cncNode, attackerPort, ssPort)
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
                                                                toTarget.append(newTarget)
                                                                toTarget.append(str(q))
                                                                toTarget.append(stepstone)
                                                                toTarget.append(SSStatus)
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
                                                                    toTarget.append(newTarget)
                                                                    toTarget.append(str(q))
                                                                    toTarget.append(stepstone)
                                                                    toTarget.append(SSStatus)
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
                if 'ag_CNC' in text or 'ag_server' in text or 'ag_attacker' in text:
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

                if v.conditionNow == "disable" or v.conditionNow == "crashed":
                    proceed3 = False
                elif v.conditionNow == "rebooting":
                    if u.accumulatedTime > v.accumulatedTime:
                        v.conditionNow = "enable"
                        v.isRebooting = False
                    else:
                        proceed3 = False
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

                        if u.exploitType[0] == "general" or (u.exploitType[0] == "vuln" and u.exploitType[3] != "authenticationbypass") or (u.exploitType[0] == "mixed-v" and u.exploitType[3] != "authenticationbypass"): # or u.exploitType[0] == "mixed-v":
                            for p in u.scanPort: 
                                if targetFound == False:
                                    for q in v.realPort:
                                        internalProceed = True
                                        if v.name in u.CNCNode[0].avoidList:
                                            if q in u.CNCNode[0].avoidList[v.name]:
                                                if u.CNCNode[0].avoidList[v.name][q]["avoid"] == True:
                                                    internalProceed = False
                                        if internalProceed == True:
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
                                                    if (u.botCollude == True and u.log == v.log) or (u.log != v.log and v.group == u.group):
                                                        SSStatus, stepstone, newTarget, newTargetPort = self.checkForSteppingStone(v, None, True, u.CNCNode, p, q)#u.targetPort)
                                                        
                                                        if SSStatus == True:
                                                            if newTarget in toTarget:
                                                                pass
                                                            else:
                                                                uport = p
                                                                vport = q
                                                                newTarget.setTarget()
                                                                
                                                                toTarget.append(newTarget)
                                                                toTarget.append(newTargetPort)
                                                                toTarget.append(stepstone)
                                                                toTarget.append(SSStatus)
                                                            targetFound = True
                                                            break
                                                    else:
                                                        SSStatus = False
                                                else:
                                                    pass
                                    if targetFound == True:
                                        break
                        elif u.exploitType[0] == "dc" or u.exploitType[0] == "mixed-c" or (u.exploitType[0] == "vuln" and u.exploitType[3] == "authenticationbypass") or (u.exploitType[0] == "mixed-v" and u.exploitType[3] == "authenticationbypass"): # or u.exploitType[0] == "wp":
                            p = 'p0'
                            internalProceed2 = True
                            if v.name in u.CNCNode[0].avoidList:
                                if p in u.CNCNode[0].avoidList[v.name]:
                                    if u.CNCNode[0].avoidList[v.name][p]["avoid"] == True:
                                        internalProceed2 = False

                            if internalProceed2 == True:
                                if v.credentialPort[0] == p:
                                    if v.credentialPort[1] == True:
                                        if v.healthy == True:
                                            if v in toTarget:
                                                pass
                                            else:
                                                uport = p
                                                vport = p
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
                                                    vport = p
                                                    v.setTarget()
                                                    toTarget.append(v)
                                                    toTarget.append(str(p))
                                                    toTarget.append(mainNode)
                                                targetFound = True
                                                break
                        else:
                            pass
                if targetFound == True:
                    break

            if targetFound == True:
                pass
            else:
                if APavailable == True:
                    toTarget, targetFound, SSStatus, uport, vport, goThruAP = self.d2dScanning(mode, targetList, u, APnode, APList, toTarget, SSStatus, uport, vport)
                    goThruAP = True

        return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    # def randomScanning(self, mode, targetList, u, toTarget, targetFound, SSStatus, uport, vport):
    #     """
    #     Random Scanning method
    #     """
    #     targetIsCompromised = False
    #     nodelist = []
    #     routerList = []
    #     tempRouter = None
    #     goThruAP = False

    #     for x in self.nodes:
    #         text = x.name.split("-")
    #         if 'ag_router' in text or 'router' in text:
    #             routerList.append(x)

    #         if x.canBeCompromised == False:
    #             pass
    #         else:
    #             nodelist.append(x)

    #     if mode == "global":
    #         tempList = targetList.copy()
    #         for a in tempList:
    #             b = None
    #             proceed4 = False
    #             if len(routerList) > 0:
    #                 for x in routerList:
    #                     for y in x.con:
    #                         targetName = y.name
    #                         text2 = y.name.split("+")
    #                         if 'ag_decoy' in text2 or 'decoy' in text2:
    #                             targetName = "ag_"+str(text2[1])
    #                         if a == targetName:
    #                             tempRouter = x
    #                             b = y
    #                             proceed4 = True
    #             else:
    #                 tempRouter = None
    #                 for x in nodelist:
    #                     targetName = x.name
    #                     text2 = x.name.split("+")
    #                     if 'ag_decoy' in text2 or 'decoy' in text2:
    #                         targetName = "ag_"+str(text2[1])
    #                     if a == targetName:
    #                         b = x
    #                         proceed4 = True

    #             if b.name in u.CNCNode[0].avoidList:
    #                 if u.CNCNode[0].avoidList[b.name]["avoid"] == True:
    #                     proceed4 = False
    #                     targetList.remove(a)


    #             if proceed4 == True:
    #                 for p in u.scanPort: 
    #                     for q in b.realPort:
    #                         if str(p) == str(q):
    #                             if b.realPort[q]["open"] == True:
    #                                 if b.healthy == True:
    #                                     uport = p
    #                                     vport = q
    #                                     targetFound = True
    #                                     toTarget.append(b)
    #                                     toTarget.append(str(p))
    #                                     toTarget.append(tempRouter)
    #                                     b.isTarget = True
    #                                     break
    #                                 else:
    #                                     if u.group == b.group:
    #                                         pass
    #                                     else:
    #                                         uport = p
    #                                         vport = q
    #                                         targetFound = True
    #                                         toTarget.append(b)
    #                                         toTarget.append(str(p))
    #                                         toTarget.append(tempRouter)
    #                                         b.isTarget = True
    #                                         break
    #                             else:
    #                                 targetList.remove(a)
    #                     if targetFound == True:
    #                         break
    #             if targetFound == True:
    #                 break
    #     else: #local
    #         while len(nodelist) > 0 and targetFound == False:
    #             if len(routerList) > 0:
    #                 tempRouter = choice(routerList)
    #             else:
    #                 tempRouter = None
    #             newNodeList = []
    #             if tempRouter != None:
    #                 for x in tempRouter.con:
    #                     if x.canBeCompromised == False:
    #                         pass
    #                     else:
    #                         if x in nodelist:
    #                             newNodeList.append(x)
    #             else:
    #                 newNodeList = nodelist
    #             if len(newNodeList) == 0:
    #                 break
    #             else:
    #                 temp = choice(newNodeList)

    #             proceed5 = True
    #             if temp.name in u.CNCNode[0].avoidList:
    #                 if u.CNCNode[0].avoidList[temp.name]["avoid"] == True:
    #                     proceed5 = False
    #                     nodelist.remove(temp)

    #             if proceed5 == True:
    #                 for p in u.scanPort: 
    #                     for q in temp.realPort:
    #                         if str(p) == str(q):
    #                             if temp.realPort[q]["open"] == True:
    #                                 if temp.healthy == True:
    #                                     uport = p
    #                                     vport = q
    #                                     targetFound = True
    #                                     toTarget.append(temp)
    #                                     toTarget.append(str(p))
    #                                     toTarget.append(tempRouter)
    #                                     temp.isTarget = True
    #                                     break
    #                                 else:
    #                                     if u.group == temp.group:
    #                                         pass
    #                                     else:
    #                                         uport = p
    #                                         vport = q
    #                                         targetFound = True
    #                                         toTarget.append(temp)
    #                                         toTarget.append(str(p))
    #                                         toTarget.append(tempRouter)
    #                                         temp.isTarget = True
    #                                         break
    #                     if targetFound == True:
    #                         break
    #                 nodelist.remove(temp)
    #     if tempRouter != None:
    #         goThruAP = True

    #     return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    
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

                if proceed4 == True:
                    for p in u.scanPort: 
                        for q in b.realPort:
                            internalProceed = True
                            if b.name in u.CNCNode[0].avoidList:
                                if q in u.CNCNode[0].avoidList[b.name]:
                                    if u.CNCNode[0].avoidList[b.name][q]["avoid"] == True:
                                        internalProceed = False
                            if internalProceed == True:
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
                
                if tempRouter != None:
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

                if proceed5 == True:
                    for p in u.scanPort: 
                        for q in temp.realPort:
                            internalProceed = True
                            if temp.name in u.CNCNode[0].avoidList:
                                if q in u.CNCNode[0].avoidList[temp.name]:
                                    if u.CNCNode[0].avoidList[temp.name][q]["avoid"] == True:
                                        internalProceed = False

                            if internalProceed == True:
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
        if tempRouter != None:
            goThruAP = True

        return toTarget, targetFound, SSStatus, uport, vport, goThruAP

    # def bruteForceAttackForCredential(self, u, v, fw):
    #     """
    #     Brute force attack - Emulation only
    #     """
    #     success = False
    #     credentialData = ""
    #     portNum = ""

    #     for p in u.scanPort: 
    #         for q in v.realPort:
    #             if str(p) == str(q):
    #                 if v.realPort[q]["open"] == True:
    #                     if v.vuls != None:
    #                         for x in u.carryExploit:
    #                             for y in v.realPort[q]["Vuln"]:
    #                                 for z in v.vuls: #check if it is patched
    #                                     if str(x) == str(y) == str(z):
    #                                         success = True
    #                                         portNum = str(q)
    #                                         credentialData = str(x)
    #                                         break
    #                             if success == True:
    #                                 break
    #                     else:
    #                         print("Target has no vulnerability.")
    #                 else:
    #                     pass
    #             if success == True:
    #                 break
    #         if success == True:
    #             break

    #     text = v.name.split("+")
    #     if 'ag_decoy' in text or 'decoy' in text:
    #         self.dReport(u, v, fw, "Unauthorised Accessing", 1)
    #     return success, portNum, credentialData

    
    def bruteForceAttackForCredentialExploitation(self, atkerNode, targetNode, targetPort, exploitType, fw):
        """
        Brute force attack - Emulation only
        """
        success = False
        credentialData = []
        portNum = ""
        redoCredential = False
        changeMethod = False

        if exploitType[0] == "general" or (exploitType[0] == "vuln" and exploitType[3] != "authenticationbypass") or (exploitType[0] == "mixed-v" and exploitType[3] != "authenticationbypass"):# or exploitType[0] == "mixed-v":
            if targetPort == 'p0' and targetNode.credentialPort[1] == True:
                if exploitType[3] == "authenticationbypass": # maybe need a requirement here eg. login.cgi file has to be present here
                    success = True
                    portNum = str(targetPort)
                    credentialData.append(targetNode.loginUsername)
                    credentialData.append(targetNode.loginPassword)

            if success == False and targetPort != 'p0':
                if targetNode.realPort[targetPort]["open"] == True:
                    if targetNode.vuls != None:
                        for x in atkerNode.carryExploit:
                            for y in targetNode.realPort[targetPort]["Vuln"]:
                                for z in targetNode.vuls: #check if it is patched
                                    if str(x) == str(y) == str(z):
                                        success = True
                                        portNum = str(targetPort)
                                        credentialData.append(str(x))
                                        break
                            if success == True:
                                break
                    else:
                        print("Target has no vulnerability.")

            if success == False and exploitType[0] == "mixed-v":
                exploitType[0] = "mixed-c"

        elif exploitType[0] == "dc" or exploitType[0] == "mixed-c" or (exploitType[0] == "vuln" and exploitType[3] == "authenticationbypass") or (exploitType[0] == "mixed-v" and exploitType[3] == "authenticationbypass"):
            if targetNode.credentialPort[1] == True:
                if exploitType[0] == "vuln" or exploitType[0] == "mixed-v":
                    if exploitType[3] == "authenticationbypass": # maybe need a requirement here eg. login.cgi file has to be present here
                        success = True
                        portNum = str(targetPort)
                        credentialData.append(targetNode.loginUsername)
                        credentialData.append(targetNode.loginPassword)
                if success == False:
                    for x in atkerNode.carryCredential:
                        if targetNode.loginUsername == x[0]:
                            if targetNode.loginPassword == x[1]:
                                success = True
                                portNum = str(targetPort)
                                credentialData.append(x[0])
                                credentialData.append(x[1])
                    if success == False:
                        redoCredential = True
            else:
                changeMethod = True
            if success == True and exploitType[0] == "mixed-c":
                exploitType[0] = "mixed-v"
        else:
            pass
        
        nodeReset = False
        text = targetNode.name.split("+")
        if 'ag_decoy' in text or 'decoy' in text:
            nodeReset = self.dReport(atkerNode, targetNode, fw, "Unauthorised Accessing", 1)

        if nodeReset == False:
            pass
        else:
            if self.defMode["MTD"]["operational"] == True:
                self.defMode["MTD"]["isolationlist"].append(atkerNode.name)
            success = False
            credentialData = []
            portNum = ""
            redoCredential = False
            changeMethod = False

        return success, portNum, credentialData, redoCredential, changeMethod

    def reportToCNCServer(self, attackData, CNCNode, propagationType):
        """
        Send credential information to CNC 
        """
        if propagationType == "async":
            CNC = CNCNode[0]
            CNC.attackData.append(attackData)
        elif propagationType == "sync1":
            pass
        elif propagationType == "sync2":
            pass

        return None

    # def downloadBinaryInstallMalware(self, u, v, portNo, cnc, tempPath, fw, botISpatched):
    #     """
    #     Infect the target node & turn target node into a bot
    #     """
    #     tempList = []
    #     tempName = None
    #     if botISpatched != None:
    #         for x in cnc.con:
    #             if x.name == botISpatched:
    #                 tempName = u.name
    #                 u = x

    #     for id, info in v.realPort.items():
    #         temp = []
    #         temp.append(str(id))
    #         for key in info:
    #             if key == 'open':
    #                 if info[key] == True:
    #                     temp.append("Open")
    #                 else:
    #                     temp.append("Closed")
    #         tempList.append(temp)

    #     if len(v.log) > 0: #Log if competition/take over happens
    #         filename = os.path.join(self.saveSimDir, "Competition.txt")
    #         createRecord("\nNode: {}".format(str(v.name)), filename)
    #         createRecord("Old owner: {}".format(str(v.log[1])), filename)
    #         createRecord("Port Status: {}".format(str(tempList)), filename)
    #         if len(u.log) == 0:
    #             createRecord("New owner: {}".format(str(u.signature[1])), filename)
    #         elif len(u.log) > 0:
    #             createRecord("New owner: {}".format(str(u.log[1])), filename)
    #         else:
    #             createRecord("New owner: {}".format(str(botISpatched)), filename)
            
    #         ##remove previous CNC connection
    #         for x in v.con:
    #             text = x.name.split('-')
    #             if 'ag_CNC' in text or 'CNC' in text:
    #                 disconnectTwoWays(v, x)
    #                 x.listofBots.remove(v)
    #                 v.CNCNode.clear()
    #                 break
    #     #works differently if the node is a decoy node
    #     text = v.name.split("+")
    #     smartDecoys = False

    #     if 'ag_decoy' in text or 'decoy' in text:
    #         if len(u.signature) > 0:
    #             sign = u.signature
    #         elif len(u.log) > 0:
    #             sign = u.log
    #         else:
    #             sign = botISpatched
            
    #         self.dReport(u, v, fw, "Malware Installation/Infection", 2)
    #         if sign in v.dataCollection:
    #             u.status = 0 #stop infinite loop
    #             pass
    #         else:
    #             v.dataCollection.append(sign)

    #         if v.model == "smart":
    #             smartDecoys = True
    #         else:
    #             v.realPort[portNo]["open"] = False
    #             v.scanPort = u.scanPort
    #             v.scanMethod = u.scanMethod
    #             v.healthy = False
    #             v.comp = True
    #             v.propagation = False
    #             v.isCompBy = u.name
    #             v.group = u.group
    #             v.protocol = u.protocol
    #             v.content = u.content
    #             if len(u.signature) > 0:
    #                 v.log = u.signature
    #             elif len(u.log) > 0:
    #                 v.log = u.log
    #             else:
    #                 v.log = botISpatched
    #             v.compromisedPort.append(portNo)
    #             v.status = 0
    #             self.totalInfectedNodes += 1
        
    #     else:
    #         v.carryExploit = u.carryExploit
    #         v.realPort[portNo]["open"] = False
    #         v.scanPort = u.scanPort
    #         v.scanMethod = u.scanMethod
    #         v.healthy = False
    #         v.comp = True
    #         v.propagation = True
    #         v.isCompBy = u.name
    #         v.group = u.group
    #         v.protocol = u.protocol
    #         v.content = u.content
    #         if len(u.signature) > 0:
    #             v.log = u.signature
    #         else:
    #             v.log = u.log

    #         v.coop = u.coop
    #         v.botCoop = u.botCoop
    #         v.meanTime = u.meanTime
    #         v.mode = u.mode
    #         v.compromisedPort.append(portNo)
    #         v.status = 1
    #         v.setFromTargetToAttacker()
    #         connectTwoWays(v, cnc)
    #         cnc.listofBots.append(v)
    #         v.CNCNode.append(cnc)
    #         self.totalInfectedNodes += 1
    #         #self.disguise()
    #         #self.terminateEnemy()

    #     self.path.append(v)
    #     if botISpatched != None:
    #         tempPath.append(tempName)
    #     else:
    #         tempPath.append(u.name)
    #     tempPath.append(v.name)
    #     return tempPath

    
    
    def downloadBinaryInstallMalware(self, u, v, portNo, cnc, fw, botISpatched):
        """
        Infect the target node & turn target node into a bot
        """
        
        tempName = None
        if botISpatched != None:
            for x in cnc.con:
                if x.name == botISpatched:
                    print("botISpatched")
                    tempName = u.name
                    u = x
        
        #works differently if the node is a decoy node
        text = v.name.split("+")
        smartDecoys = False
        surviveFromReboot = []

        if 'ag_decoy' in text or 'decoy' in text:
            
            if len(u.binaryName) > 0:
                sign = u.binaryName
            elif len(u.log) > 0:
                sign = u.log
            else:
                sign = botISpatched

            nodeReset = self.dReport(u, v, fw, "Malware Installation/Infection", 2)
            
            if sign in v.dataCollection:
                u.status = 0 #stop infinite loop
                print("101010101010")
                pass
            else:
                v.dataCollection.append(sign)

            if v.model == "smart":
                smartDecoys = True
            else:
                if u.exploitType[0] == 'general':
                    v.realPort[portNo]["open"] = False
                elif u.exploitType[0] == 'dc' or u.exploitType[0] == 'common' or u.exploitType[0] == 'strong':
                    v.credentialPort[1] = False
                v.exploitType = u.exploitType
                v.propagationType = u.propagationType
                v.scanPort = u.scanPort
                v.scanMethod = u.scanMethod
                v.healthy = False
                v.comp = True
                v.propagation = False
                v.isCompBy = u.name
                v.group = u.group
                v.protocol = u.protocol
                v.content = u.content
                if len(u.binaryName) > 0:
                    v.log = u.binaryName
                elif len(u.log) > 0:
                    v.log = u.log
                else:
                    v.log = botISpatched

                v.compromisedPort.append(portNo)
                v.status = 0
                self.totalInfectedNodes += 1
        
        else:
            surviveFromReboot = [False]
            self.malwareInstallation(u, v, cnc, portNo)
            self.afterInstallation(u, v, surviveFromReboot, cnc)

        return v.isRebooting, surviveFromReboot, tempName

    def deviceReboot(self, v, currentTime):
        """
        How an attacker / bot handles a device reboot decision
        """
        v.isRebooting = self.deviceRebootDecision(v, currentTime)
        surviveFromReboot = [False]
        cncNode = None
        if v.isRebooting == True:
            if v.respondToReboot == "terminated" or v.respondToReboot == "survive":
                if v.respondToReboot == "survive":
                    if str(v.log[0]) in v.cronFolder or str(v.log[0]) in v.initFolder:
                        surviveFromReboot[0] = True
                        surviveFromReboot.append(v.log[1])
                cncNode = self.deviceRebootAction(v)
                surviveFromReboot.append(cncNode)
            elif v.respondToReboot == "prevent":
                v.isRebooting = False
            else:
                pass
        return v.isRebooting, surviveFromReboot, cncNode

    def deviceRebootDecision(self, node, currentTime):
        """
        To check if the device will reboot at that specific time
        """
        reboot = False
        text = node.name.split("+")
        text2 = node.name.split("-")

        if 'ag_decoy' in text or 'decoy' in text or 'ag_attacker' in text2 or 'ag_CNC' in text2 or 'ag_server' in text2 or 'Intelligence Center' in text2  or 'SDN switch' in text2:
            #decoy is not going to reboot unless instructed to do so.
            pass

        else:
            if node.rebootable[0] == "manual" and node.resourceMeterCurrent > node.resourceMeterBreakLimit and node.resourceMeterCurrent < node.resourceMeterAll:
                reboot = self.decision(node.rebootable[1])
            elif node.resourceMeterCurrent >= node.resourceMeterAll:
                reboot = True
            elif node.rebootable[0] == "disable":
                pass
            elif node.rebootable[0] == "auto":
                pass
            elif node.rebootable[0] == "periodic":
                lastRebootTime = 0
                timeDifference = 0
                if len(node.timeline) > 0:
                    for x in reversed(node.timeline):
                        # print(x)
                        if str(x[0]) == "RB":
                            lastRebootTime = x[2]
                            break
                    
                    timeDifference = currentTime - lastRebootTime
                    if timeDifference >= 0:
                        if timeDifference > float(node.rebootable[2]):
                            reboot = True
                        else:
                            node.conditionNow = "enable"
                    else:
                        temp = abs(timeDifference)
                        if temp <= float(node.rebootable[3]):
                            node.conditionNow = "rebooting"

                else:
                    if node.accumulatedTime > float(node.rebootable[2]):
                        reboot = True
            else:
                pass
        return reboot

    def decision(self, probability):
        """
        To decide based on a probability
        """
        return random() < float(probability)

    def deviceRebootAction(self, node):
        """
        Device reboot
        """
        cncNode = None
        for y in node.realPort:
            if node.realPort[y]['open'] == False:
                node.realPort[y]['open'] = True
        for x in node.con:
            text = x.name.split('-')
            if 'ag_CNC' in text or 'CNC' in text:
                disconnectTwoWays(node, x)
                x.listofBots.remove(node)
                node.CNCNode.remove(x)
                cncNode = x
        node.credentialPort[1] = True
        node.carryExploit = []
        node.carryCredential = []
        node.scanPort = []
        node.scanMethod = None
        node.healthy = True
        node.comp = False
        node.propagation = False
        node.isCompBy = None
        node.group = None
        node.protocol = None
        node.content = []
        node.log = []
        node.status = 0
        node.collude = None
        node.botCollude = None
        node.meanTime = None
        node.mode = None
        node.exploitType = []
        node.propagationType = None
        node.compromisedPort = []
        node.resourceMeterCurrent = node.resourceConsumptionNLimit[0]
        node.botTaskList = []
        node.killerBlackList = []
        node.fortificationList = []
        node.evasionList = []
        text = node.name.split('ag_')

        node.conditionNow = "rebooting"
        return cncNode

    def deviceRebootPeriodically(self, accumulatedTimeNow):
        """
        Check if a device reboots periodically
        """

        deviceName = []

        for x in self.nodes:
            text = x.name.split("-")
            text2 = x.name.split("+")
            deviceReboot = False
            cncN = None
            oriAtker = None
            tempPortNo = None
            surviveFromReboot = []
                            
            if 'ag_attacker' in text or 'ag_CNC' in text or 'ag_server' in text or 'Intelligence Center' in text or 'SDN switch' in text:
                pass
            elif 'ag_decoy' in text2 or 'decoy' in text2:
                pass
            else:
                if x.rebootable[0] == "periodic":
                    if x.accumulatedTime < float(x.rebootable[2]):
                        x.accumulatedTime = accumulatedTimeNow
                    else:
                        deviceReboot, surviveFromReboot, cncN = self.deviceReboot(x, accumulatedTimeNow)
                
            temp = []
            if deviceReboot == True:
                deviceName.append(x.name)
                if x.accumulatedTime > accumulatedTimeNow:
                    x.accumulatedTime = x.accumulatedTime + float(x.rebootable[3])#0.5
                else:
                    x.accumulatedTime = accumulatedTimeNow + float(x.rebootable[3])#0.5
                temp.append("RB")
                tempTime = float(x.rebootable[3])
                temp.append(tempTime)
                temp.append(x.accumulatedTime)
                x.timeline.append(temp)
            
            if deviceReboot == True and surviveFromReboot[0] == True:
                for y in surviveFromReboot[2].con:
                    text = y.name.split("ag_")
                    if surviveFromReboot[1] == text[1]:
                        oriAtker = y
                        if oriAtker.exploitType[0] == "general" or (oriAtker.exploitType[0] == "vuln" and oriAtker.exploitType[3] != "authenticationbypass") or (oriAtker.exploitType[0] == "mixed-v" and oriAtker.exploitType[3] != "authenticationbypass"):
                            for a in oriAtker.scanPort:
                                for b in x.realPort:
                                    if str(a) == str(b):
                                        if x.realPort[b]["open"] == True:
                                            tempPortNo = str(a)
                                            break
                        elif oriAtker.exploitType[0] == "dc" or oriAtker.exploitType[0] == "mixed-c" or (oriAtker.exploitType[0] == "vuln" and oriAtker.exploitType[3] == "authenticationbypass") or (oriAtker.exploitType[0] == "mixed-v" and oriAtker.exploitType[3] == "authenticationbypass"):
                            tempPortNo = 'p0'

                self.malwareInstallation(oriAtker, x, surviveFromReboot[2], tempPortNo)
                self.afterInstallation(oriAtker, x, surviveFromReboot, surviveFromReboot[2])
                x.conditionNow = "busy"

                startTime = x.accumulatedTime
                x.accumulatedTime += oriAtker.infectionTime
                endTime = x.accumulatedTime
                temp.append("IS")
                temp.append(oriAtker.infectionTime)
                temp.append(x.accumulatedTime)
                x.timeline.append(temp)

                self.timelineDict['startNode'].append(surviveFromReboot[2].name)
                self.timelineDict['endNode'].append(x.name)
                self.timelineDict['startTime'].append(startTime)
                self.timelineDict['endTime'].append(endTime)
                self.timelineDict['compBy'].append(x.log[1])

        return deviceName

    def setupTempPath(self, u, v, botISpatched, tempName, tempPath):
        """
        Set up a temporary path
        """
        if v.comp == True:
            self.path.append(v)
            if botISpatched != None:
                tempPath.append(tempName)
            else:
                tempPath.append(u.name)
            tempPath.append(v.name)
        return tempPath

    def malwareInstallation(self, u, v, cnc, portNo):
        """
        Install a malware binary
        """
        v.carryExploit = u.carryExploit
        v.scanPort = u.scanPort
        v.scanMethod = u.scanMethod
        v.healthy = False
        v.comp = True
        v.propagation = True
        v.isCompBy = u.name
        v.group = u.group
        v.protocol = u.protocol
        v.content = u.content
        if len(u.binaryName) > 0:
            v.log = u.binaryName
        else:
            v.log = u.log
        v.status = 1
        v.collude = u.collude
        v.botCollude = u.botCollude
        v.meanTime = u.meanTime
        v.mode = u.mode

        v.exploitType = u.exploitType
        v.propagationType = u.propagationType
        v.compromisedPort.append(portNo)
        v.respondToReboot = u.respondToReboot
        v.killerBlackList = u.killerBlackList
        v.fortificationList = u.fortificationList
        v.evasionList = u.evasionList
        v.carryCredential = u.carryCredential

        for x in cnc.botTaskList:
            if x[1] == True:
                v.botTaskList.append(x)

        v.binaryfile.append(u.binaryfile[0])
        
        v.processlist.append(u.binaryfile[0])
        v.filelist.append(u.binaryfile[0])
        if len(cnc.resideLocation) > 0:
            for x in cnc.resideLocation:
                if str(x) == "cron" and "cron" in v.folderlist:
                    v.cronFolder.append(u.binaryfile[0])
                if str(x) == "init" and "init" in v.folderlist:
                    v.initFolder.append(u.binaryfile[0])

        for x in v.botTaskList:
            if x[0] == "propagate":
                v.resourceMeterCurrent += int(x[2])

        return None

    def afterInstallation(self, u, v, surviveFromReboot, cnc):
        """
        After malware binary installation
        """

        v.isRebooting, surviveFromReboot, c = self.deviceReboot(v, 0)

        if v.isRebooting == False:
            v.conditionNow = "busy"
            
            v.setFromTargetToAttacker()

            self.totalInfectedNodes += 1
            if "no evasion" not in v.evasionList:
                self.evasiveManeuver(v)
                
            if u.killerBlackList[0] != "no killer":
                self.terminateCompetitor(u, v)

            if u.fortificationList[0] != "no fortify":
                self.fortifyBot(u, v)

            self.connectCNC(v, cnc)

        else:
            v.conditionNow = "rebooting"

        return None

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
            if len(u.binaryName) > 0:
                tempText = u.binaryName[1]
            elif len(u.log) > 0:
                tempText = u.log[1]

            if str(x) in text1 or tempText in text2:
                existingProcess = []
                for a in self.AtkerTimeDataDict[x]:
                    if str(a).lower() != "averagetime":
                        existingProcess.append(str(a))
                processNotExist = False
                if processName not in existingProcess:
                    processNotExist = True
                
                if processNotExist == False:
                    while(dataAccepted == False):
                        time = choice(self.AtkerTimeDataDict[x][processName]["timeData"])
                        if time >= self.AtkerTimeDataDict[x][processName]["parameterX"][0] and time <= self.AtkerTimeDataDict[x][processName]["parameterX"][1]:
                            dataAccepted = True
                            break
                    if dataAccepted == True:
                        break
                else:
                    time = 0
        return time

    def generatePhaseTime(self, attacksDict):
        """
        Get time value for different phases
        """
        compareAT = []
        getAvgTime = []

        for x in attacksDict:
            temptext = x.split('-')
            if 'DBF' not in temptext and 'SDN' not in temptext:
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
                    tempAT = self.getTempAvgTime(u.scanTime, u.accessTime, u.reportTime, u.infectionTime)
                getAvgTime.append(tempAT)
                if tempAT == 0:
                    u.status = 0

        return compareAT, getAvgTime

    def getTempAvgTime(self, scanTime, accessTime, reportTime, infectionTime):
        """
        Get temporary average time value
        """
        num = 0
        tempAT = 0
        for a in [scanTime, accessTime, reportTime, infectionTime]:
            if a > 0:
                num += 1
        total = scanTime + accessTime + reportTime + infectionTime
        if total > 0 and num > 0:
            tempAT = (total)/num
        return tempAT

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

    def checkForSteppingStone(self, target, nextTarget, collusion, cncNode, attackerPort, ssPort): 
        """
        Check whether it is possible for attacker to use compromised node as stepping stone to attack further target
        """
        status = False
        stepStone = None
        newTarget = None
        newTargetPort = ""
        #Global
        if nextTarget != None:
            if collusion == True:
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
                                    else:
                                        pass
                                    if proceed5 == True:
                                        targetName = ""
                                        if type(nextTarget) == str:
                                            targetName = nextTarget
                                        elif type(nextTarget.name) == str:
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
        elif target != None:
            if collusion == True:
                for x in cncNode:
                    for y in x.listofBots:
                        if str(y.name) == str(target.name):
                            for z in y.con:
                                
                                text = z.name.split("-")
                                text2 = z.name.split("+")
                                proceed6 = True
                                if z.canBeCompromised == False:
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

    def evasiveManeuver(self, v):
        """
        How an attacker evades defender's detection
        """
        
        if "change process name" in v.evasionList:

            for y in [v.processlist, v.filelist, v.cronFolder, v.initFolder]:
                if v.binaryfile[0] in y:
                    for x in y:
                        if type(x) == binaryFile:
                            if x.name == v.binaryfile[0].name:
                                x.name = str(v.log[2])

        if "memory" in v.evasionList:
            for y in [v.filelist, v.cronFolder, v.initFolder]:
                templist = []
                if v.binaryfile[0] in y:
                    for x in y:
                        if type(x) == binaryFile:
                            if x.name == v.binaryfile[0].name:
                                pass
                            else:
                                templist.append(x)
                        else:
                            templist.append(x)
                    y = templist.copy()

        if "single instance" in v.evasionList:
            for y in [v.processlist, v.filelist, v.cronFolder, v.initFolder]:
                templist = []
                if v.binaryfile[0] in y:
                    for x in y:
                        if type(x) == binaryFile:
                            if x.name == v.binaryfile[0].name:
                                pass
                            else:
                                templist.append(x)
                        else:
                            templist.append(x)
                    templist.append(v.binaryfile[0])
                    y = templist.copy()
        return None

    def terminateCompetitor(self, u, v):
        """
        How an attacker searches and kills other competitor malware processes in the device to gain full control of the device
        """

        killSuccessfulList = []
        if u.killerBlackList[1].lower() == "all":
            if u.killerBlackList[2].lower() == "all":
                for x in [v.processlist, v.filelist, v.cronFolder, v.initFolder]:
                    templist = []
                    for y in x:
                        if type(y) == binaryFile:
                            if y == u.binaryfile[0]:
                                templist.append(y)
                            else:
                                if x == v.processlist:
                                    killSuccessfulList.append(y.name)
                                
                        else:
                            templist.append(y)
                    x = templist.copy()
            else:
                for x in [v.processlist, v.filelist, v.cronFolder, v.initFolder]:
                    templist = []
                    for y in x:
                        for i in range(2, len(u.killerBlackList)):
                            if type(y) == binaryFile:
                                if y.name == str(u.killerBlackList[i]).lower():
                                    if x == v.processlist:
                                        killSuccessfulList.append(y.name)
                                else:
                                    if y in templist:
                                        if templist.count(y) < x.count(y):
                                            templist.append(y)
                                        else:
                                            pass
                                    else:
                                        templist.append(y)
                            else:
                                templist.append(y)
                    x = templist.copy()

        if u.killerBlackList[1].lower() == "process":
            if u.killerBlackList[2].lower() == "all":
                templist = []
                for y in v.processlist:
                    if type(y) == binaryFile:
                        if y == u.binaryfile[0]:
                            print("same binary1")
                            templist.append(y)
                        else:
                            killSuccessfulList.append(y.name)
                            
                    else:
                        templist.append(y)
                v.processlist = templist.copy()
            else:
                templist = []
                for y in v.processlist:
                    for i in range(2, len(u.killerBlackList)):
                        if type(y) == binaryFile:
                            if y.name == str(u.killerBlackList[i]).lower():
                                killSuccessfulList.append(y.name)
                            else:
                                if y in templist:
                                    if templist.count(y) < v.processlist.count(y):
                                        templist.append(y)
                                    else:
                                        pass
                                else:
                                    templist.append(y)
                        else:
                            templist.append(y)
                v.processlist = templist.copy()


        if u.killerBlackList[1].lower() == "file":
            if u.killerBlackList[2].lower() == "all":
                templist = []
                for y in v.filelist:
                    if type(y) == binaryFile:
                        if y == u.binaryfile[0]:
                            print("same binary2")
                            templist.append(y)
                        else:
                            killSuccessfulList.append(y.name)
                            
                    else:
                        templist.append(y)
                v.filelist = templist.copy()
            else:
                templist = []
                for y in v.filelist:
                    for i in range(2, len(u.killerBlackList)):
                        if type(y) == binaryFile:
                            if y.name == str(u.killerBlackList[i]).lower():
                                killSuccessfulList.append(y.name)
                            else:
                                if y in templist:
                                    if templist.count(y) < v.filelist.count(y):
                                        templist.append(y)
                                    else:
                                        pass
                                else:
                                    templist.append(y)
                        else:
                            templist.append(y)
                v.filelist = templist.copy()

        if u.killerBlackList[1].lower() == "cron":
            if u.killerBlackList[2].lower() == "all":
                templist = []
                for y in v.cronFolder:
                    if type(y) == binaryFile:
                        if y == u.binaryfile[0]:
                            print("same binary3")
                            templist.append(y)
                        else:
                            killSuccessfulList.append(y.name)
                            
                    else:
                        templist.append(y)
                v.cronFolder = templist.copy()
            else:
                templist = []
                for y in v.cronFolder:
                    for i in range(2, len(u.killerBlackList)):
                        if type(y) == binaryFile:
                            if y.name == str(u.killerBlackList[i]).lower():
                                killSuccessfulList.append(y.name)
                            else:
                                if y in templist:
                                    if templist.count(y) < v.cronFolder.count(y):
                                        templist.append(y)
                                    else:
                                        pass
                                else:
                                    templist.append(y)
                        else:
                            templist.append(y)
                v.cronFolder = templist.copy()

        if u.killerBlackList[1].lower() == "init":
            if u.killerBlackList[2].lower() == "all":
                templist = []
                for y in v.initFolder:
                    if type(y) == binaryFile:
                        if y == u.binaryfile[0]:
                            print("same binary4")
                            templist.append(y)
                        else:
                            killSuccessfulList.append(y.name)
                            
                    else:
                        templist.append(y)
                v.initFolder = templist.copy()
            else:
                templist = []
                for y in v.initFolder:
                    for i in range(2, len(u.killerBlackList)):
                        if type(y) == binaryFile:
                            if y.name == str(u.killerBlackList[i]).lower():
                                killSuccessfulList.append(y.name)
                            else:
                                if y in templist:
                                    if templist.count(y) < v.initFolder.count(y):
                                        templist.append(y)
                                    else:
                                        pass
                                else:
                                    templist.append(y)
                        else:
                            templist.append(y)
                v.initFolder = templist.copy()

        if len(killSuccessfulList) > 0:
            for x in v.con:
                text = x.name.split('-')
                if 'ag_CNC' in text or 'CNC' in text:
                    if x.binaryName[0] in killSuccessfulList:
                        disconnectTwoWays(v, x)
                        x.listofBots.remove(v)
                        v.CNCNode.remove(x)
        return None

    def fortifyBot(self, u, v):
        """
        How an attacker fortifies the compromised device to prevent competitors
        """

        for i in range(1, len(u.fortificationList)):
            if str(u.fortificationList[i]) == "all":
                for x in v.realPort:
                    v.realPort[x]["open"] = False
                v.credentialPort[1] = False
            else:
                if str(u.fortificationList[i]) in v.realPort:
                    v.realPort[str(u.fortificationList[i])]["open"] = False

                if str(u.fortificationList[i]) in v.credentialPort:
                    v.credentialPort[1] = False

        return None

    def ddosAttackStart(self, u, cnc):
        """
        Ultimate goal - DDoS Attack modelling
        """

        attackSuccess = False
        targetIPAddress = cnc.botActionList[3]
        targetNode = None
        for x in self.nodes:
            if x.IPv4Add == targetIPAddress:
                connectOneWay(u, x)
                x.connectionList.append(u.name)
                x.bufferCurrent += 1
                x.resource += 1
                attackSuccess = True
                targetNode = x

        return attackSuccess, targetNode

    def ddosAttackFail(self, u, targetNode):
        """
        Ultimate goal - DDoS Attack Fail
        """
        disconnectOneWay(u, targetNode)
        targetNode.connectionList.remove(u.name)
        targetNode.bufferCurrent -= 1
        targetNode.resource -= 1

        return None

    def pdosAttack(self, u):
        """
        Ultimate goal - PDoS Attack modelling
        """

        tempNodelist = u.con.copy()

        for x in tempNodelist:
            disconnectTwoWays(u, x)

        u.conditionNow = "disable"
        u.status = 0

        return None

    def dataExfiltration(self, u, cnc):
        """
        Ultimate goal - Data exfiltration modelling
        """

        nodeName = u.name
        nodeCon = []
        for x in u.con:
            nodeCon.append(x.name)

        nodeCredential = []
        if u.loginUsername != None and u.loginPassword != None:
            nodeCredential.append(u.loginUsername)
            nodeCredential.append(u.loginPassword)
        
        nodeprocesslist = []
        if u.processlist != None:
            nodeprocesslist = u.processlist

        nodeFolderList = []
        if u.folderlist != None:
            nodeFolderList = u.folderlist

        nodeFileList = []
        if u.filelist != None:
            nodeFileList = u.filelist

        nodeVul = []
        for x in u.vuls:
            nodeVul.append(str(x))

        nodeIP = u.IPv4Add

        nodeResource = u.resourceMeterCurrent

        nodeCondition = u.conditionNow

        nodePort = []

        if u.credentialPort[0] != None:
            temp = []
            temp.append(u.credentialPort[0])
            temp.append(u.credentialPort[1])
            nodePort.append(temp)

        for x in u.realPort: #[portNo]["open"] = False
            temp = []
            if u.realPort[x]["open"] == True:
                temp.append(x)
                temp.append(True)
            else:
                temp.append(x)
                temp.append(False)
            nodePort.append(temp)

        tempDict = {nodeName : {"port" : nodePort, 
                    "connection" : nodeCon, 
                    "credential" : nodeCredential, 
                    "processlist" : nodeprocesslist, 
                    "filelist" : nodeFileList, 
                    "folderlist" : nodeFolderList, 
                    "vulnerability" : nodeVul, 
                    "ipaddress" : nodeIP, 
                    "resourceLevel" : nodeResource, 
                    "condition" : nodeCondition, 
                    "anySpecialData" : None
                    }
                    }
        cnc.networkDataRecord.update(tempDict)

        return None

    def connectCNC(self, v, cnc):
        """
        Connecting CNC node
        """
        connectTwoWays(v, cnc)
        cnc.listofBots.append(v)
        v.CNCNode.append(cnc)

        templistInOut7 = []
        templistInOut7.append("INOUT")
        templistInOut7.append(v.name)
        templistInOut7.append(cnc.name)
        templistInOut7.append(v.accumulatedTime)
        templistInOut7.append(v.log[1])
        self.inOutTrafficTimeline.append(templistInOut7)

        return None

    def antiMalwareScanning(self, fw, mode, checkLocation, content):
        """
        Anti-malware scanning modelling
        """

        infectedList = []
        suspiciousList = []
        healthyList = []
        for x in self.nodes:
            text = x.name.split("-")
            if "ag_attacker" in text or "attacker" in text or "ag_CNC" in text or "CNC" in text or "ag_server" in text or "server" in text:
                pass
            elif x.canBeCompromised == False:
                pass
            else:
                malwareDetected, suspicionDetected, suspicionNum = fw.antiMalwareSystem(mode, checkLocation, x, content)

                temp = []
                temp.append(x.name)
                temp.append(suspicionNum)

                if malwareDetected == True:
                    infectedList.append(temp)
                elif suspicionDetected == True:
                    suspiciousList.append(temp)
                else:
                    healthyList.append(temp)

        return infectedList, suspiciousList, healthyList

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

    def checkForRebootedDevice(self, oldDict):
        """
        Check for rebooted devices
        """
        newDict = None

        for x in oldDict:
            for y in oldDict[x]['attackerNode']:
                if y.name != 'Intelligence Center' and y.name != 'SDN switch':
                    if y.status == 0:
                        newDict = copy.deepcopy(oldDict)
                        newDict[x]['attackerNode'].remove(y)

        if newDict == None:
            return oldDict
        else:
            return newDict

    def dReport(self, u, v, fw, actionName, num):
        """
        Create decoy report
        """
        exploit = ""
        vulnerability = ""
        sign = None
        nodeReset = False

        if u.exploitType[0] == "dc" or u.exploitType[0] == "mixed-c" or (u.exploitType[0] == "vuln" and u.exploitType[3] == "authenticationbypass") or (u.exploitType[0] == "mixed-v" and u.exploitType[3] == "authenticationbypass"): # or u.exploitType[0] == "wp":
            p = 'p0'
            nodeReset = fw.decoyReports([u.protocol, u.IPv4Add, p, u.name, u.binaryfile[0].name, None, "dc", None, None], [actionName], self.saveSimDir, self.defMode["Deception"]["response"], u)

        else:
            for x in u.carryExploit:
                for y in v.vuls:
                    if str(x) == str(y):
                        exploit = str(x)
                        vulnerability = str(y)
                        break
                if len(exploit) > 0:
                    break
            if len(u.binaryName) > 0:
                sign = u.binaryName
            else:
                sign = u.log
            cnc = u.CNCNode[0]

            for p in u.scanPort:
                for q in v.realPort:
                    if str(p) == str(q):
                        portNo = p
            nodeReset = fw.decoyReports([u.protocol, u.IPv4Add, portNo, u.name, sign, exploit, vulnerability, u.content[num], cnc], [actionName], self.saveSimDir, None, None)

        return nodeReset

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

    def showNodeVulnerableStatus(self, nodes):
        """
        Show a node's status about vulnerability
        """
        immune = 0
        vulnerable = 0
        vulnerabilities = []
        immuneNamelist = []
        for x in nodes:
            if x.canBeCompromised == False:
                pass
            else:
                if len(x.vuls) > 0:
                    vulnerable += 1
                    for y in x.vuls:
                        vulnerabilities.append(str(y))
                else:
                    immune += 1
                    immuneNamelist.append(x.name)

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
                    
        if v != None and portNum != None:
            if self.defMode["Patching"]["operational"] == True and self.defMode["Patching"]["mode"] == 3:
                fw.patchVulnerability(self.defMode["Patching"]["mode"], self.defMode["Patching"]["vulnerability"], v.name, portNum, self.nodes)

        return None

    def calcPath(self):
        """
        Trigger attack
        """
        return self.initAtk()