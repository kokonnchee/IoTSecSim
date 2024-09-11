'''
This module creates input files for simulation run. All parameters can be adjusted.

@author: Kok Onn Chee
'''


import os, glob
import pandas as pd
import copy

from SaveToFile import *

folderName = os.getcwd()
longFilename = []
filename = ""
inputFilename = ""
pbsFilename = ""

def getAddOnText(expNum, topologyStyle, graphDensity, graphDensityList, percentageOfVulnNodes, nodeNum, dm):
    text = ""
    #print(topologyStyle)
    if expNum == 3 or expNum == 4:
        if topologyStyle == "grid":
            text = "-gr"
        elif topologyStyle == "smallworld":
            text = "-sw"
        elif topologyStyle == "scalefree":
            text = "-sf"
        elif topologyStyle == "RGG":
            text = "-rgg"
        elif topologyStyle == "graphDen":
            num = graphDensityList.index(graphDensity)
            text = "-"+str(num)+"ad"
        else:
            text = ""

    if percentageOfVulnNodes is not None:
        num = int(nodeNum - (nodeNum * percentageOfVulnNodes[1]))
        text = text + "-" + str(num) + "v"
    
    if expNum == 7:
        if dm is not None:
            for x in dm:
                if x == "firewall":
                    text = text + "+fw"
                elif x == "patching":
                    text = text + "+pat"
                elif x == "ids":
                    text = text + "+idsSAI4"
                elif x == "ips":
                    text = text + "+ips"
                elif x == "mtd":
                    text = text + "+mtd"
                elif x == "decoy":
                    text = text + "+dec"
                else:
                    text = text + "+xdm"

    return text

def createAtkerInput(simRunName, atkerNum, atkerData):
    atkerDict = {}

    for x in atkerData:
        tempAttackers = []
        tempAttackers.append(x[0])
        tempAtkerDict = dict(AverageTime = x[2], ScanPro = x[4], AccessPro = x[6], ReportPro = x[8], InstallPro = x[10], exploit = x[11], scanPort = x[12], IP = x[13], protocol = x[14], cooperative = x[15], botCoop = x[16], scanningMethod = x[17], group = x[18], signature = x[19], 
                        content = x[20], goal = x[21], mode = x[22], attackData = [], accumulatedTime = x[23], status = x[24], target = x[25])

        if len(atkerDict) == 0:
            atkerDict = dict(zip(tempAttackers, [tempAtkerDict]))
        else:
            temp = dict(zip(tempAttackers, [tempAtkerDict]))
            atkerDict.update(temp)

    tempList = []

    for id, info in atkerDict.items():
        
        tempS = pd.Series(id, name="attacker")#, index=[i])
        tempList.append(tempS)

        for key in info:

            s1 = None
            s1 = pd.Series(info[key], name=key)

            if s1 is not None:
                tempList.append(s1)

    df = pd.concat(tempList, axis=1)
    df.to_csv(simRunName+'.atker', index=False)

    return None

def createDefenceInput(simRunName, defenderData):

    defenderDict = {}
    for x in defenderData:
        tempDefenders = []
        tempDefenders.append(x[0])
        tempDefDict = dict(Name = x[1], Action = x[3], Protocol = x[5], SourceIP = x[7], SourcePort = x[9], FlowDirection = x[11], DestinationIP = x[13], DestinationPort = x[15], msg = x[17], content = x[19], rev = x[21], priority = x[23], where = x[25], vulnerability = x[27], triggerAttempt = x[29], smart = x[31], dummy = x[33], mode = x[34], addNewRule = x[36])

        if len(defenderDict) == 0:
            defenderDict = dict(zip(tempDefenders, [tempDefDict]))
        else:
            temp = dict(zip(tempDefenders, [tempDefDict]))
            defenderDict.update(temp)

    tempList = []

    for id, info in defenderDict.items():
        tempS = pd.Series(id, name="defender")
        tempList.append(tempS)
        for key in info:
            s1 = None
            s1 = pd.Series(info[key], name=key)
            if s1 is not None:
                tempList.append(s1)
    
    df = pd.concat(tempList, axis=1)
    df.to_csv(simRunName+'.defender', index=False)

    return None

def detectListLen(list1, list2):
    if len(list1) == 0:
        list1.append(None)

    if len(list2) > 0:
        return list2[0]
    else:
        return None

def loadDefenderInput(folderName, simRunName, defenderNum, IoTDefence):
    
    files = glob.iglob(os.path.join(folderName, "*.defender"))

    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')
        
        text2 = text[-1].split('.defender')

        if simRunName in text2:
            print()
            print(x)
            df = pd.read_csv(x)

            defender = [z for z in list(df['defender']) if str(z) != 'nan']

            nm = [str(int(w)) for w in list(df['Name']) if str(w) != 'nan']
            act = [w for w in list(df['Action']) if str(w) != 'nan']
            pro = [w for w in list(df['Protocol']) if str(w) != 'nan']
            sip = [w for w in list(df['SourceIP']) if str(w) != 'nan']
            sport = [w for w in list(df['SourcePort']) if str(w) != 'nan']
            flow = [w for w in list(df['FlowDirection']) if str(w) != 'nan']
            dip = [w for w in list(df['DestinationIP']) if str(w) != 'nan']
            dport = [w for w in list(df['DestinationPort']) if str(w) != 'nan']
            msg = [w for w in list(df['msg']) if str(w) != 'nan']
            cont = [[w for w in list(df['content']) if str(w) != 'nan']]
            rev = [int(w) for w in list(df['rev']) if str(w) != 'nan']
            pri = [w for w in list(df['priority']) if str(w) != 'nan']
            whe = [[w for w in list(df['where']) if str(w) != 'nan']]
            mod = [int(w) for w in list(df['mode']) if str(w) != 'nan']
            vuln = [[w for w in list(df['vulnerability']) if str(w) != 'nan']]
            trig = [int(w) for w in list(df['triggerAttempt']) if str(w) != 'nan']
            sma = [int(w) for w in list(df['smart']) if str(w) != 'nan']
            dum = [int(w) for w in list(df['dummy']) if str(w) != 'nan']
            add = [[w for w in list(df['addNewRule']) if str(w) != 'nan']]

            if defenderNum > 1:
                for i in range(1, defenderNum):
                    temp = [z for z in list(df['defender'+'.'+str(i)]) if str(z) != 'nan']
                    defender.append(detectListLen(defender, temp))
                    temp = [str(int(w)) for w in list(df['Name'+'.'+str(i)]) if str(w) != 'nan']
                    nm.append(detectListLen(nm, temp))
                    temp = [w for w in list(df['Action'+'.'+str(i)]) if str(w) != 'nan']
                    act.append(detectListLen(act, temp))
                    temp = [w for w in list(df['Protocol'+'.'+str(i)]) if str(w) != 'nan']
                    pro.append(detectListLen(pro, temp))
                    temp = [w for w in list(df['SourceIP'+'.'+str(i)]) if str(w) != 'nan']
                    sip.append(detectListLen(sip, temp))
                    temp = [w for w in list(df['SourcePort'+'.'+str(i)]) if str(w) != 'nan']
                    sport.append(detectListLen(sport, temp))
                    temp = [w for w in list(df['FlowDirection'+'.'+str(i)]) if str(w) != 'nan']
                    flow.append(detectListLen(flow, temp))
                    temp = [w for w in list(df['DestinationIP'+'.'+str(i)]) if str(w) != 'nan']
                    dip.append(detectListLen(dip, temp))
                    temp = [w for w in list(df['DestinationPort'+'.'+str(i)]) if str(w) != 'nan']
                    dport.append(detectListLen(dport, temp))
                    temp = [w for w in list(df['msg'+'.'+str(i)]) if str(w) != 'nan']
                    msg.append(detectListLen(msg, temp))
                    temp = [w for w in list(df['content'+'.'+str(i)]) if str(w) != 'nan']
                    cont.append(temp)
                    temp = [int(w) for w in list(df['rev'+'.'+str(i)]) if str(w) != 'nan']
                    rev.append(detectListLen(rev, temp))
                    temp = [w for w in list(df['priority'+'.'+str(i)]) if str(w) != 'nan']
                    pri.append(detectListLen(pri, temp))
                    temp = [w for w in list(df['where'+'.'+str(i)]) if str(w) != 'nan']
                    whe.append(temp)
                    temp = [int(w) for w in list(df['mode'+'.'+str(i)]) if str(w) != 'nan']
                    mod.append(detectListLen(mod, temp))
                    temp = [w for w in list(df['vulnerability'+'.'+str(i)]) if str(w) != 'nan']
                    vuln.append(temp)
                    temp = [int(w) for w in list(df['triggerAttempt'+'.'+str(i)]) if str(w) != 'nan']
                    trig.append(detectListLen(trig, temp))
                    temp = [int(w) for w in list(df['smart'+'.'+str(i)]) if str(w) != 'nan']
                    sma.append(detectListLen(sma, temp))
                    temp = [int(w) for w in list(df['dummy'+'.'+str(i)]) if str(w) != 'nan']
                    dum.append(detectListLen(dum, temp))
                    temp = [w for w in list(df['addNewRule'+'.'+str(i)]) if str(w) != 'nan']
                    add.append(temp)

            for i in range(len(defender)):
                tempDef = []
                tempDef.append(defender[i])
                text = defender[i].split('-')
                if text[0] == 'ids' or text[0] == 'ips':
                    
                    text = text[0].upper()
                    IoTDefence[text]["operational"] = True 
                    IoTDefence[text]["mode"] = mod[i]
                    IoTDefence[text]["triggerAttempt"] = trig[i]
                    IoTDefence[text]["addNewRule"] = add[i]
                    IoTDefence[text]["rule"].update({nm[i] : {"Action" : act[i],
                                                        "Protocol" : pro[i],
                                                        "SourceIP" : sip[i],
                                                        "SourcePort" : sport[i],
                                                        "FlowDirection" : flow[i],
                                                        "DestinationIP" : dip[i],
                                                        "DestinationPort" : dport[i],
                                                        "msg" : msg[i],
                                                        "content" : cont[i],
                                                        "rev" : rev[i],
                                                        "priority" : pri[i]
                                                        }
                                                })
                elif text[0] == 'firewall':
                    IoTDefence["Firewall"]["operational"] = True 
                    IoTDefence["Firewall"]["mode"] = mod[i]
                    IoTDefence["Firewall"]["rule"].update({nm[i] : {"Action" : act[i],
                                                                "Protocol" : pro[i],
                                                                "SourceIP" : sip[i],
                                                                "SourcePort" : sport[i],
                                                                "DestinationIP" : dip[i],
                                                                "DestinationPort" : dport[i],
                                                                "msg" : msg[i],
                                                                "where" : whe[i]
                                                                }
                            })
                elif text[0] == 'patching':
                    IoTDefence["Patching"]["operational"] = True 
                    IoTDefence["Patching"]["mode"] = mod[i]
                    temp = []
                    temp2 = []

                    for j in range(0, len(vuln[i])):
                        if j % 2 == 0:
                            temp.append(vuln[i][j])
                        else:
                            temp.append(vuln[i][j])
                            temp2.append(temp)
                            temp = []

                    IoTDefence["Patching"]["vulnerability"] = temp2
                    IoTDefence["Patching"]["triggerAttempt"] = trig[i]
                    
                elif text[0] == 'decoy':
                    IoTDefence["Deception"]["operational"] = True 
                    IoTDefence["Deception"]["mode"] = mod[i]
                    IoTDefence["Deception"]["model"]["smart"] = sma[i]
                    IoTDefence["Deception"]["model"]["dummy"] = dum[i]
                    
                elif text[0] == 'mtd':
                    IoTDefence["MTD"]["operational"] = True 
                    IoTDefence["MTD"]["mode"] = mod[i]
                else:
                    print("Defender not found! 1")
    print(IoTDefence)

    return None

def loadAtkerInput(folderName, simRunName, atkerNum, IoTAtkDict, AtkerTimeDataDict):
    
    files = glob.iglob(os.path.join(folderName, "*.atker"))
    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')

        text2 = text[-1].split('.atker')

        if simRunName in text2:
            print()
            print(x)
            df = pd.read_csv(x)
            
            atker = [z for z in list(df['attacker']) if str(z) != 'nan']

            at = [w for w in list(df['AverageTime']) if str(w) != 'nan']
            exp = [[w for w in list(df['exploit']) if str(w) != 'nan']]
            sp = [[w for w in list(df['scanPort']) if str(w) != 'nan']]
            ip = [w for w in list(df['IP']) if str(w) != 'nan']
            pro = [w for w in list(df['protocol']) if str(w) != 'nan']
            coop1 = [w for w in list(df['cooperative']) if str(w) != 'nan']
            coop2 = [w for w in list(df['botCoop']) if str(w) != 'nan']
            sm = [w for w in list(df['scanningMethod']) if str(w) != 'nan']
            gro = [w for w in list(df['group']) if str(w) != 'nan']
            sig = [[w for w in list(df['signature']) if str(w) != 'nan']]
            cont = [[w for w in list(df['content']) if str(w) != 'nan']]
            go = [w for w in list(df['goal']) if str(w) != 'nan']
            mo = [w for w in list(df['mode']) if str(w) != 'nan']
            acct = [w for w in list(df['accumulatedTime']) if str(w) != 'nan']
            sta = [w for w in list(df['status']) if str(w) != 'nan']
            tar = [w for w in list(df['target']) if str(w) != 'nan']

            sPro = [w for w in list(df['ScanPro']) if str(w) != 'nan']
            aPro = [w for w in list(df['AccessPro']) if str(w) != 'nan']
            rPro = [w for w in list(df['ReportPro']) if str(w) != 'nan']
            iPro = [w for w in list(df['InstallPro']) if str(w) != 'nan']

            if atkerNum > 1:
                for i in range(1, atkerNum):
                    temp = [z for z in list(df['attacker'+'.'+str(i)]) if str(z) != 'nan']
                    atker.append(detectListLen(atker, temp))
                    temp = [w for w in list(df['AverageTime'+'.'+str(i)]) if str(w) != 'nan']
                    at.append(detectListLen(at, temp))
                    temp = [w for w in list(df['exploit'+'.'+str(i)]) if str(w) != 'nan']
                    exp.append(temp)
                    temp = [w for w in list(df['scanPort'+'.'+str(i)]) if str(w) != 'nan']
                    sp.append(temp)
                    temp = [w for w in list(df['IP'+'.'+str(i)]) if str(w) != 'nan']
                    ip.append(detectListLen(ip, temp))
                    temp = [w for w in list(df['protocol'+'.'+str(i)]) if str(w) != 'nan']
                    pro.append(detectListLen(pro, temp))
                    temp = [w for w in list(df['cooperative'+'.'+str(i)]) if str(w) != 'nan']
                    coop1.append(detectListLen(coop1, temp))
                    temp = [w for w in list(df['botCoop'+'.'+str(i)]) if str(w) != 'nan']
                    coop2.append(detectListLen(coop2, temp))
                    temp = [w for w in list(df['scanningMethod'+'.'+str(i)]) if str(w) != 'nan']
                    sm.append(detectListLen(sm, temp))
                    temp = [w for w in list(df['group'+'.'+str(i)]) if str(w) != 'nan']
                    gro.append(detectListLen(gro, temp))
                    temp = [w for w in list(df['signature'+'.'+str(i)]) if str(w) != 'nan']
                    sig.append(temp)
                    temp = [w for w in list(df['content'+'.'+str(i)]) if str(w) != 'nan']
                    cont.append(temp)
                    temp = [w for w in list(df['goal'+'.'+str(i)]) if str(w) != 'nan']
                    go.append(detectListLen(go, temp))
                    temp = [w for w in list(df['mode'+'.'+str(i)]) if str(w) != 'nan']
                    mo.append(detectListLen(mo, temp))
                    temp = [w for w in list(df['accumulatedTime'+'.'+str(i)]) if str(w) != 'nan']
                    acct.append(detectListLen(acct, temp))
                    temp = [w for w in list(df['status'+'.'+str(i)]) if str(w) != 'nan']
                    sta.append(detectListLen(sta, temp))
                    temp = [w for w in list(df['target'+'.'+str(i)]) if str(w) != 'nan']
                    tar.append(detectListLen(tar, temp))

                    temp = [w for w in list(df['ScanPro'+'.'+str(i)]) if str(w) != 'nan']
                    sPro.append(detectListLen(sPro, temp))
                    temp = [w for w in list(df['AccessPro'+'.'+str(i)]) if str(w) != 'nan']
                    aPro.append(detectListLen(aPro, temp))
                    temp = [w for w in list(df['ReportPro'+'.'+str(i)]) if str(w) != 'nan']
                    rPro.append(detectListLen(rPro, temp))
                    temp = [w for w in list(df['InstallPro'+'.'+str(i)]) if str(w) != 'nan']
                    iPro.append(detectListLen(iPro, temp))
            
            for i in range(len(atker)):
                tempAtker = []
                tempAtker.append(atker[i])
                tempAttackerInfo = {"AverageTime" : at[i], 
                                "exploit" : exp[i], 
                                "scanPort" : sp[i],
                                "IP" : ip[i],
                                "protocol" : pro[i],
                                "cooperative" : coop1[i], 
                                "botCoop" : coop2[i], 
                                "scanningMethod" : sm[i], 
                                "group" : gro[i], 
                                "signature" : sig[i], 
                                "content" : cont[i],
                                "goal" : go[i], 
                                "mode" : mo[i], 
                                "attackData" : [], 
                                "accumulatedTime" : acct[i], 
                                "status" : sta[i],
                                "target" : tar[i]
                }

                tempIoTAtk = dict(zip(tempAtker, [tempAttackerInfo]))

                IoTAtkDict.update(tempIoTAtk)

                tempAtkerTimeDataDict = {"AverageTime" : at[i],
                                    "scan" : {"available" : True, "proportion" : sPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "access" : {"available" : True, "proportion" : aPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "report" : {"available" : True, "proportion" : rPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "install" : {"available" : True, "proportion" : iPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None}}
                
                tempAtkerTimeData = dict(zip(tempAtker, [tempAtkerTimeDataDict]))

                AtkerTimeDataDict.update(tempAtkerTimeData)
    print(IoTAtkDict)

    return None

def createDeviceInput(simRunName, deviceDict):

    tempList = []

    for id, info in deviceDict.items():
        tempS = pd.Series(id, name="device")
        tempList.append(tempS)

        for key in info:

            s1 = None
            s1 = pd.Series(info[key], name=key)
            
            if s1 is not None:
                tempList.append(s1)
            
    df = pd.concat(tempList, axis=1)
    df.to_csv(simRunName+'.device', index=False)

    return None

def loadDeviceInput(folderName, simRunName, IoTDeviceNum, deviceDict):
    
    files = glob.iglob(os.path.join(folderName, "*.device"))

    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')
        
        text2 = text[-1].split('.device')

        if simRunName in text2:
            print()
            print(x)
            df = pd.read_csv(x)

            device = [z for z in list(df['device']) if str(z) != 'nan']

            num = [int(w) for w in list(df['numbers']) if str(w) != 'nan']
            op = [[w for w in list(df['openPort']) if str(w) != 'nan']]
            ov = [w for w in list(df['otherValues']) if str(w) != 'nan']
            
            if IoTDeviceNum > 1:
                for i in range(1, IoTDeviceNum):
                    temp = [z for z in list(df['device'+'.'+str(i)]) if str(z) != 'nan']
                    device.append(detectListLen(device, temp))
                    temp = [int(w) for w in list(df['numbers'+'.'+str(i)]) if str(w) != 'nan']
                    num.append(detectListLen(num, temp))
                    temp = [w for w in list(df['openPort'+'.'+str(i)]) if str(w) != 'nan']
                    op.append(temp)
                    temp = [w for w in list(df['otherValues'+'.'+str(i)]) if str(w) != 'nan']
                    ov.append(detectListLen(ov, temp))

            for i in range(len(device)):
                deviceDict[device[i]]["numbers"] = num[i]
                deviceDict[device[i]]["otherValues"] = ov[i]
                deviceDict[device[i]]["openPort"] = {}

                for k in range(len(op[i])):
                    if op[i][k] == "open":
                        if op[i][k+1] == "True":
                            deviceDict[device[i]]["openPort"].update({op[i][k-1]:{"open": True, "Vuln":[op[i][k+3]]}})
    print(deviceDict)

    return None

series = "c" # series codename: "a", "b", "c"
expNumList = [1, 2, 3, 4, 5, 7] # 1=net size; 2=no. non vul nodes; 3=average degree; 4=net topology; 5=scanning method; and 7=defence method
expNum = expNumList[0]

attackNum = ["0"]#, "1", "2", "3", "4"] # 0=single+LNC; 1=multi+LNC; 2=multi+LC; 3=multi+GNC; 4=multi+GC;

nodeNumList = [25, 50, 75, 100]
nodeNum = nodeNumList[1]

#                   0      1     2     3      4    5
expCodeNameList = ["ns", "vul", "ad", "nt", "sm", "dm"] #ns = network size; vul = non vuln node; ad = avg degree; nt = network topology; sm = scanning method; dm = defence method;
expCodeName = expCodeNameList[0]

#                       0          1        2           3       4        5        6              7           8        9
topologyStyleList = ["25same", "50same", "75same", "100same", "50dif", "grid", "smallworld", "scalefree", "RGG", "graphDen"]
topologyStyle = topologyStyleList[1]

graphDensityList = [1.96, 2.53, 3.02, 4, 5.02]
graphDensity = graphDensityList[0]

percentageOfVulnNodesList = [None, ["all", 0.8], ["all", 0.6], ["all", 0.4], ["all", 0.2]]
percentageOfVulnNodes = percentageOfVulnNodesList[0]

specialList = ["0", "1"]
special = specialList[0]

randScan = False #True

atkerNum = 1 #or 2 or 3 or more

defenceON = False #True

defenceMethod = ["firewall", "patching", "ids", "ips", "mtd", "decoy"]
defenceMethodChoiceNum = [0, 2] # [0] = one def technique; [0, 1] = two def techniques
defenceRuleNum = [1, 1] # rule mode for each def technique
defenderNum = 0
if len(defenceRuleNum) > 0:
    defenderNum = sum(x for x in defenceRuleNum)

defenceMethodChoice = []

if defenceMethodChoiceNum is not None:
    for x in defenceMethodChoiceNum:
        defenceMethodChoice.append(defenceMethod[x])

defenceMethodMode = 1

triggerAddDM = ['firewall']

blacklist = {"SourceIP" : [],# wrong = "10.127.162.201"], #correct = ["10.127.162.234"], #
            "SourcePort" : [],
            "DestinationIP" : [],
            "DestinationPort" : [], 
            "content" : ["|00 00 00 01|", "|11 11 11 11|", "|99 99 99 99|"] #["|00 00 00 01|", "|11 11 11 11|", "|99 99 99 99|"]
            }

blSip = "any"
blSport = "any"
blDip = "any"
blDport = "any"
blContent = "any"

if len(blacklist["SourceIP"]) > 0:
    blSip = blacklist["SourceIP"]
if len(blacklist["SourcePort"]) > 0:
    blSport = blacklist["SourcePort"]
if len(blacklist["DestinationIP"]) > 0:
    blDip = blacklist["DestinationIP"]
if len(blacklist["DestinationPort"]) > 0:
    blDport = blacklist["DestinationPort"]
if len(blacklist["content"]) > 0:
    blContent = blacklist["content"]

where = ['all'] #'router-1', 'router-2', 'router-3', 'all'

homogeneousDevice = True

addonText = getAddOnText(expNum, topologyStyle, graphDensity, graphDensityList, percentageOfVulnNodes, nodeNum, defenceMethodChoice)

IoTDeviceSetup = {"iotdevice": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p2": {"open": True, "Vuln": ["v2"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1"],# "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                "otherValues" : None
                                },
                "lightbulb": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p2": {"open": True, "Vuln": ["v2"]}, "p3": {"open": True, "Vuln": ["v3"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : None
                                },
                "nvr": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", False, "Vuln", None, "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : None
                                },
                "ipcamera": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}},#, "p3": {"open": True, "Vuln": ["v3"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                "otherValues" : None
                                },
                "projector": {"numbers" : 0,
                                #"openPort" : {"p2": {"open": True, "Vuln": ["v2"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : None
                                },
                "router": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p2": {"open": True, "Vuln": ["v2"]}, "p3": {"open": True, "Vuln": ["v3"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : "Cannot be compromised"
                                },
                "tv": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p2": {"open": True, "Vuln": ["v2"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                "otherValues" : None
                                },
                "printer": {"numbers" : 0,
                                #"openPort" : {"p3": {"open": True, "Vuln": ["v3"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", False, "Vuln", None, "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : None
                                },
                "laptop": {"numbers" : 0,
                                #"openPort" : {"p2": {"open": True, "Vuln": ["v2"]}, "p3": {"open": True, "Vuln": ["v3"]}, "p4": {"open": True, "Vuln": ["v4"]}},
                                "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                "otherValues" : None
                                },
                "fridge": {"numbers" : 0,
                                #"openPort" : {"p2": {"open": True, "Vuln": ["v2"]}, "p3": {"open": True, "Vuln": ["v3"]}},
                                "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", False, "Vuln", None],
                                "otherValues" : None
                                },
                "smokeAlarm": {"numbers" : 0,
                                #"openPort" : {"p1": {"open": True, "Vuln": ["v1"]}, "p3": {"open": True, "Vuln": ["v3"]}},
                                "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", True, "Vuln", "v3", "p4", "open", False, "Vuln", None],
                                "otherValues" : None
                                }
                }

IoTDeviceNum = len(IoTDeviceSetup)

for i in range(len(attackNum)):
    atkerData = [['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
    ["v1"], ["p1"], "10.127.162.55", "TCP", False, False, "d2d", "A", ["mirai_A", "attacker-1"], ["|00 00 01 01|", "|11 11 11 21|", "|99 99 99 89|"], 100, "local", 0, 1, True], 
    ['attacker-2', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
    ["v2"], ["p2"], "10.55.162.41", "TCP", False, False, "d2d", "B", ["mirai_B", "attacker-2"], ["|00 00 00 01|", "|22 22 22 22|", "|88 88 88 88|"], 100, "local", 0, 1, False]]

    defenderData = []
    if defenceON == True:
        for x, y in zip(defenceMethodChoice, defenceRuleNum):
            for j in range(y):
                z = x + '-' + str(j+1)
                if str(x) == "ids":
                    num = 101 + j
                    temp = [z, num, "Action", "alert", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", "->", "DestinationIP", blDip, "DestinationPort", blDport,
                    "msg", "Alert! Someone is trying to enter network via IP address", "content", blContent, "rev", 1, "priority", 10, "where", None, "vulnerability", None, "triggerAttempt", 1, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", triggerAddDM]
                elif str(x) == "ips":
                    num = 201 + j
                    temp = [z, num, "Action", "drop", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", "->", "DestinationIP", blDip, "DestinationPort", blDport,
                    "msg", "Blocking dest port p1", "content", blContent, "rev", 1, "priority", 10, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None]
                elif str(x) == "firewall":
                    num = 301 + j
                    temp = [z, num, "Action", "allow", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", None,"DestinationIP", blDip, "DestinationPort", blDport,
                    "msg", "Allow all", "content", None, "rev", None, "priority", None, "where", where, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None]
                    #temp = [z, num, "Action", "block", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", None,"DestinationIP", blDip, "DestinationPort", blDport,
                    #"msg", "Blocking C&C IP", "content", None, "rev", None, "priority", None, "where", where, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None]
                elif str(x) == "patching":
                    num = 401 + j
                    temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                    "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", [], "triggerAttempt", 5, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None]
                    #"lightbulb", "v1", "ipcamera", "v1", "smokeAlarm", "v1", "nvr", "v1", "tv", "v1"
                    #"lightbulb", "v2", "projector", "v2", "tv", "v2", "laptop", "v2", "fridge", "v2"
                    #"lightbulb", "v1", "ipcamera", "v1", "smokeAlarm", "v1", "nvr", "v1", "tv", "v1", "lightbulb", "v2", "projector", "v2", "tv", "v2", "laptop", "v2", "fridge", "v2"
                    #"lightbulb", "v1", "lightbulb", "v2", "lightbulb", "v3", "lightbulb", "v4"
                elif str(x) == "decoy":
                    num = 501 + j
                    temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                    "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", 5, "dummy", 0, defenceMethodMode, "addNewRule", None]
                elif str(x) == "mtd":
                    num = 601 + j
                    temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                    "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None]
                    
                else:
                    print("Defence method not found! 2")
                
                defenderData.append(temp)
    if homogeneousDevice == True:
        for x in IoTDeviceSetup:
            if x == "iotdevice":
                IoTDeviceSetup[x]["numbers"] = nodeNum
            elif x == "router":
                if expCodeName == "nt":
                    IoTDeviceSetup[x]["numbers"] = 0
                else:
                    IoTDeviceSetup[x]["numbers"] = 3
            else:
                IoTDeviceSetup[x]["numbers"] = 0
    else:
        numlist = [0, 19, 1, 4, 2, 3, 3, 8, 9, 1, 3]
        m = 0
        for x in IoTDeviceSetup:
            IoTDeviceSetup[x]["numbers"] = numlist[m]
            m+=1

    AtkerTimeDataDict = {}
    IoTAtkDict = {}

    IoTDeviceSetupNew = copy.deepcopy(IoTDeviceSetup)

    IoTDefence = {
        "IDS" : {"operational" : False,
                "method" : "monitor network and generate warning message if detected anything suspicious",
                "log type" : ["all", "alert"], #Actions type: alert, log, pass, activate, dynamic, drop, reject, sdrop
                "triggerAttempt" : 0,
                "addNewRule": [],
                "rule" : {}
                },

        "IPS" : {"operational" : False,
                "method" : "inspect traffic, detect threat based on signature and proactively stop malicious traffic",
                "rule" : {}
                },

        "Firewall" : {"operational" : False,
                    "method" : "monitor and control network",
                    "mode" : 0, 
                    # 1 for pre-attack blacklist IP (specific IP address only);
                    # 2 for mid-attack firewall (with IDS and trigger);
                    # 3 for pre-attack blacklist Port Num (specific port num only);
                    "rule" : {}
                },

        "Patching" : {"operational" : False,
                    "method" : "remove vulnerability",
                    "mode" : 0, 
                    # 1 for pre-attack patch type 1 (specific vuln only); example: [["iotdevice", "v2"]]
                    # 2 for pre-attack patch type 2 (full device); example: [["iotdevice", "all"]]
                    # 3 for mid-attack patch (with IDS); example: [["iotdevice", "v1"]] with a trigger
                    "vulnerability" : None, #[["lightbulb", "v1"], ["lightbulb", "v2"], ["lightbulb", "v3"], ["lightbulb", "v4"]],#["router", "v2"], ["ipcamera", "v3"]]#["printer", "default credential2"], ["laptop", "default credential3"]]#[["lightbulb", "CVE-2018-8308"],["router", "CVE-2017-17215"],["iotdevice", "default credential"]]
                    "triggerAttempt" : 0
                },

        "MTD" : {"operational" : False,
                    "method" : "defend against attack by changing attack surface",
                    "mode" : 0
                    # 1 for "topology shuffling" 
                    # 2 for "ip shuffling"
                },

        "Deception" : {"operational" : False,
                    "method" : "add decoy node to deceive attackers",
                    "mode" : 0,
                    # 1 for "add decoy" 
                    # 2 for "convert into decoy"
                    "model" : {"smart" : 0, "dummy" : 0}
                }
                }

    simRunName = series+str(expNum)+"-"+str(attackNum[i])+"-"+str(nodeNum)+""+expCodeName+addonText
    line1 = "simRunName=" + simRunName
    line2 = "topologyStyle=" + topologyStyle
    line3 = "graphDensity=" + str(graphDensity)
    line4 = "special=" + special
    line5 = "attackNum=" + attackNum[i]
    if percentageOfVulnNodes is not None:
        line6 = "percentageOfVulnNodes=" + str(percentageOfVulnNodes[0]) + "+" + str(percentageOfVulnNodes[1])
    else:
        line6 = "percentageOfVulnNodes=None"

    if attackNum[i] == "0":
        atkerNum = 1
    else:
        atkerNum = 2

    line7 = "atkerNum=" + str(atkerNum)

    line8 = "defenderNum=" + str(defenderNum)

    line9 = "deviceTypeNum=" + str(IoTDeviceNum)

    inputFilename = simRunName + ".input"

    lineList = [line1, line2, line3, line4, line5, line6, line7, line8, line9]

    for y in lineList:
        #create .input file
        createRecord(y, os.path.join(folderName, inputFilename))

    if randScan == True:
        for x in atkerData:
            x[17] = "random"

    if attackNum[i] == "0":
        atkerData.pop(1)

    if attackNum[i] == "2" or attackNum[i] == "4":
        for x in atkerData:
            x[15] = True
            x[16] = True
            x[18] = "A"

    if attackNum[i] == "3" or attackNum[i] == "4":
        for x in atkerData:
            x[22] = "global"
            
    #create .atker file
    createAtkerInput(simRunName, atkerNum, atkerData)
    loadAtkerInput(folderName, simRunName, atkerNum, IoTAtkDict, AtkerTimeDataDict)

    if len(defenderData) > 0:
        #create .defender file
        createDefenceInput(simRunName, defenderData)
        loadDefenderInput(folderName, simRunName, defenderNum, IoTDefence)

    #create .device file
    createDeviceInput(simRunName, IoTDeviceSetupNew)
    loadDeviceInput(folderName, simRunName, IoTDeviceNum, IoTDeviceSetupNew)