'''
This individual module creates input files for simulation run. All parameters can be adjusted.
This script runs independently from IoTSecSimMain.py.

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

def createSimName(series, expNum, attackNum, nodeNum, expCodeName, topologyStyle, graphDensity, graphDensityList, percentageOfVulnNodes, defenceON, dm, expVulnTypesAddonText, propagationTypes, respondToReboot, resideLocation, botTaskList, killerBlackList, fortificationList, evasionList, deviceWordList, atkerWordList, rebootTypesAll, vsBattle):
    """
    Example: U9wp-N50gr+uniq-A0dc+sync1-Dfw
    """
    text = ""
    ts = ""
    if expNum == 3 or expNum == 4:
        if topologyStyle == "grid":
            ts = "gr"
        elif topologyStyle == "IAS":
            ts = "ias"
        elif topologyStyle == "smallworld":
            ts = "sw"
        elif topologyStyle == "scalefree":
            ts = "sf"
        elif topologyStyle == "tree":
            ts = "tr"
        elif topologyStyle == "RGG":
            ts = "rgg"
        elif topologyStyle == "graphDen":
            num = graphDensityList.index(graphDensity)
            ts = "ad"+str(num)
        else:
            ts = ""
    else:
        ts = "off"

    tpov = ""
    if percentageOfVulnNodes is not None:
        num = int(nodeNum - (nodeNum * percentageOfVulnNodes[1]))
        tpov = "+" + str(num) + "v"
    
    te = ""
    tv = ""
    if len(expVulnTypesAddonText) > 0:
        if expVulnTypesAddonText[0] == 'general':
            te = "gen"
        elif expVulnTypesAddonText[0] == 'dc': 
            te = "dc"
        elif expVulnTypesAddonText[0] == 'vuln':
            te = "vuln"
        elif expVulnTypesAddonText[0] == 'mixed-v':
            te = "mixV"
        elif expVulnTypesAddonText[0] == 'mixed-c':
            te = "mixC"
        else:
            pass

        if expVulnTypesAddonText[1] == 'unique':
            tv = "+uniq"
        elif expVulnTypesAddonText[1] == 'identical':
            tv = "+iden"
        else:
            pass

    dw = ""
    if deviceWordList == "carna":
        dw = "+WS1"
    elif deviceWordList == "mirai":
        dw = "+WS2"
    elif deviceWordList == "strong":
        dw = "+WS4"
    elif deviceWordList == "others":
        dw = "+WS3"
    elif deviceWordList == None:
        dw = "+WX"
    else:
        pass

    aw = ""
    if atkerWordList == "carna":
        aw = "+WA"
    elif atkerWordList == "mirai":
        aw = "+WB"
    elif atkerWordList == "others":
        aw = "+WC"
    elif atkerWordList == "dark_nexus":
        aw = "+WD"
    elif atkerWordList == "torii":
        aw = "+WE"
    elif atkerWordList == "dark_iot":
        aw = "+WF"
    elif atkerWordList == "hydra":
        aw = "+WG"
    elif atkerWordList == None:
        aw = "+WX"
    else:
        pass

    atker = ""
    for i in range (len(vsBattle)):
        if i == 0:
            atker = vsBattle[i]
        else:
            atker = atker+"v"+vsBattle[i]

    td = ""

    if defenceON == True:
        for x in dm:
            if x == "firewall":
                td = "fw"
            elif x == "patching":
                td = "pat"
            elif x == "ids":
                td = "ids"#SAI4"
            elif x == "ips":
                td = "ips"
            elif x == "mtd":
                td = "mtd"
            elif x == "decoy":
                td = "dec"
            elif x == "antimalware":
                td = "am"
            elif x == "dbf":
                td = "dbf"
            else:
                pass
    else:
        td = "Dx"

    rta = ""
    if rebootTypesAll is not None:
        if rebootTypesAll == "disable":
            rta = "+Rd"
        elif rebootTypesAll == "manual":
            rta = "+Rm"
        elif rebootTypesAll == "auto":
            rta = "+Ra"
        elif rebootTypesAll == "periodic":
            rta = "+Rp"
        else:
            print("unknown reboot type")

    rtb = ""
    if respondToReboot is not None:
        if respondToReboot == "terminated":
            rtb = "+ter"
        elif respondToReboot == "prevent":
            rtb = "+pre"
        elif respondToReboot == "survive":
            rtb = "+sur"
        else:
            print("unknown reboot response")
    
    rl = ""
    if len(resideLocation) > 0:
        for x in resideLocation:
            if str(x) == "memory":
                rl = rl + "+mem"
            elif str(x) == "cron":
                rl = rl + "+cro"
            elif str(x) == "init":
                rl = rl + "+ini"
            else:
                print("unknown reside location")

    bt = ""
    if len(botTaskList) > 0:
        for x in botTaskList:
            if str(x) == "propagate":
                bt = bt + "Pr"
            elif str(x) == "ddos":
                bt = bt + "Ds"
            elif str(x) == "exfiltrate data":
                bt = bt + "Ex"
            elif str(x) == "pdos":
                bt = bt + "Ps"
            elif str(x) == "cryptomining":
                bt = bt + "Cm"
            elif str(x) == "proxy server":
                bt = bt + "Px"
            else:
                pass
                #print("unknown task")

    kl = ""
    if "no killer" in killerBlackList:
        kl = "k0"
    else:
        kl = "k1"
    fl = ""
    if "no fortify" in fortificationList:
        fl = "f0"
    else:
        fl = "f1"

    el = ""
    if "no evasion" in evasionList:
        el = "e0"
    else:
        if len(evasionList) == 1:
            el = "e1"
        elif len(evasionList) == 2:
            el = "e2"
        elif len(evasionList) == 3:
            el = "e3"

    textForSim = series+str(expNum)+expCodeName

    textForNetwork = "-N"+str(nodeNum)+ts+tpov+tv+dw+rta

    textForAtker = "-A"+attackNum+te+"+"+atker+aw+"+"+propagationTypes+rtb+rl+"+"+bt+"+"+kl+fl+el

    textForDefender = "-D"+td

    text = textForSim+textForNetwork+textForAtker+textForDefender

    return text

def createAtkerInput(simRunName, atkerNum, atkerData):
    """
    Create input file for attacker
    """
    atkerDict = {}
    for x in atkerData:
        tempAttackers = []
        tempAttackers.append(x[0])
        tempAtkerDict = dict(AverageTime = x[2], ScanPro = x[4], AccessPro = x[6], ReportPro = x[8], InstallPro = x[10], exploit = x[11], scanPort = x[12], 
                        IP = x[13], protocol = x[14], collusive = x[15], botCollude = x[16], scanningMethod = x[17], group = x[18], binaryName = x[19], 
                        content = x[20], goal = x[21], mode = x[22], attackData = [], accumulatedTime = x[23], status = x[24], target = x[25], exploitType = x[26], 
                        propagationType = x[27], respondToReboot = x[28], resideLocation = x[29], botTaskList = x[30], killerBlackList = x[31], fortificationList = x[32], 
                        evasionList = x[33], botActionList = x[34], credentialList = x[35])

        if len(atkerDict) == 0:
            atkerDict = dict(zip(tempAttackers, [tempAtkerDict]))
        else:
            temp = dict(zip(tempAttackers, [tempAtkerDict]))
            atkerDict.update(temp)

    tempList = []

    for id, info in atkerDict.items():
        tempS = pd.Series(id, name="attacker")
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
    """
    Create input file for defender
    """
    defenderDict = {}
    for x in defenderData:
        tempDefenders = []
        tempDefenders.append(x[0])
        tempDefDict = dict(Name = x[1], Action = x[3], Protocol = x[5], SourceIP = x[7], SourcePort = x[9], FlowDirection = x[11], DestinationIP = x[13], 
                           DestinationPort = x[15], msg = x[17], content = x[19], rev = x[21], priority = x[23], where = x[25], vulnerability = x[27], 
                           triggerAttempt = x[29], smart = x[31], dummy = x[33], mode = x[34], addNewRule = x[36], configuration = x[38])

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

def createDeviceInput(simRunName, deviceDict):
    """
    Create input file for device
    """
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

def detectListLen(list1, list2):
    if len(list1) == 0:
        list1.append(None)

    if len(list2) > 0:
        return list2[0]
    else:
        return None

def loadDefenderInput(folderName, simRunName, defenderNum, IoTDefence):
    """
    This function is identical with the one in IoTSecSimMain.py.

    We use this function to test and verify the defender input file.
    """
    
    files = glob.iglob(os.path.join(folderName, "*.defender"))

    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')
        
        text2 = text[-1].split('.defender')

        if simRunName in text2:
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
            config = [[w for w in list(df['configuration']) if str(w) != 'nan']]

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
                    temp = [w for w in list(df['configuration'+'.'+str(i)]) if str(w) != 'nan']
                    config.append(temp)

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
                    IoTDefence["Deception"]["response"] = act[i]
                    
                elif text[0] == 'mtd':
                    IoTDefence["MTD"]["operational"] = True 
                    IoTDefence["MTD"]["mode"] = mod[i]
                    IoTDefence["MTD"]["shufflelist"] = vuln[i]
                    IoTDefence["MTD"]["nodenum"] = trig[i]
                    IoTDefence["MTD"]["isolationlist"] = []
                    IoTDefence["MTD"]["shuffletime"] = float(pri[i])
                    IoTDefence["MTD"]["restorelist"] = []
                    IoTDefence["MTD"]["resetlist"] = []

                elif text[0] == 'antimalware':
                    amModeAll = ['Nothing', 'simple1', 'simple2', 'basic', 'advanced']
                    IoTDefence["AntiMalware"]["operational"] = True 
                    IoTDefence["AntiMalware"]["mode"] = amModeAll[mod[i]]
                    IoTDefence["AntiMalware"]["checkLocation"] = whe[i]
                    IoTDefence["AntiMalware"]["content"] = cont[i]

                elif text[0] == 'dbf':
                    IoTDefence["DBF"]["operational"] = True 
                    IoTDefence["DBF"]["configuration"] = []

                    temp = []
                    temp1 = []
                    temp2 = []
                    isANum = 0
                    for k in range(len(config[i])):
                        if config[i][k] == "all" and config[i][k+1] == "all" and isANum == 0:
                            temp.append(config[i][k])
                            
                        elif config[i][k] == "all" and config[i][k+1] != "all" and config[i][k+1].isdigit() == False and isANum == 0:
                            isANum += 1
                            temp.append(config[i][k])
                            
                        elif config[i][k].isdigit() == True and isANum == 0:
                            isANum += 1
                            temp.append(int(config[i][k]))

                        elif config[i][k].isdigit() == True and isANum == 1:
                            isANum += 1
                            temp.append(temp1)
                            temp1 = []
                            temp.append(int(config[i][k]))

                        elif config[i][k].isdigit() == False and isANum == 0:
                            temp.append(config[i][k])

                        elif config[i][k].isdigit() == False and isANum == 1:
                            temp1.append(config[i][k])

                        elif config[i][k].isdigit() == False and isANum == 2:
                            temp2.append(config[i][k])

                            if config[i][k] == "nothing" and isANum == 2:
                                isANum = 0
                                temp.append(temp2)
                                temp2 = []
                                IoTDefence["DBF"]["configuration"].append(temp)
                                temp = []
                        else:
                            print("error decoding dbf")
                else:
                    print("Defender not found! 1")

    return None

def loadAtkerInput(folderName, simRunName, atkerNum, IoTAtkDict, AtkerTimeDataDict):
    """
    This function is identical with the one in IoTSecSimMain.py.

    We use this function to test and verify the attacker input file.
    """
    files = glob.iglob(os.path.join(folderName, "*.atker"))
    
    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')

        text2 = text[-1].split('.atker')

        if simRunName in text2:
            df = pd.read_csv(x)
        
            atker = [z for z in list(df['attacker']) if str(z) != 'nan']

            at = [w for w in list(df['AverageTime']) if str(w) != 'nan']
            exp = [[w for w in list(df['exploit']) if str(w) != 'nan']]
            sp = [[w for w in list(df['scanPort']) if str(w) != 'nan']]
            ip = [w for w in list(df['IP']) if str(w) != 'nan']
            pro = [w for w in list(df['protocol']) if str(w) != 'nan']
            collude1 = [w for w in list(df['collusive']) if str(w) != 'nan']
            collude2 = [w for w in list(df['botCollude']) if str(w) != 'nan']
            sm = [w for w in list(df['scanningMethod']) if str(w) != 'nan']
            gro = [w for w in list(df['group']) if str(w) != 'nan']
            sig = [[w for w in list(df['binaryName']) if str(w) != 'nan']]
            cont = [[w for w in list(df['content']) if str(w) != 'nan']]
            go = [w for w in list(df['goal']) if str(w) != 'nan']
            mo = [w for w in list(df['mode']) if str(w) != 'nan']
            acct = [w for w in list(df['accumulatedTime']) if str(w) != 'nan']
            sta = [w for w in list(df['status']) if str(w) != 'nan']
            tar = [w for w in list(df['target']) if str(w) != 'nan']
            expType = [[w for w in list(df['exploitType']) if str(w) != 'nan']]
            propType = [w for w in list(df['propagationType']) if str(w) != 'nan']
            resp = [w for w in list(df['respondToReboot']) if str(w) != 'nan']
            reside = [[w for w in list(df['resideLocation']) if str(w) != 'nan']]
            btl = [[w for w in list(df['botTaskList']) if str(w) != 'nan']]
            kbl = [[w for w in list(df['killerBlackList']) if str(w) != 'nan']]
            fl = [[w for w in list(df['fortificationList']) if str(w) != 'nan']]
            el = [[w for w in list(df['evasionList']) if str(w) != 'nan']]
            bal = [[w for w in list(df['botActionList']) if str(w) != 'nan']]
            cdl = [[w for w in list(df['credentialList']) if str(w) != 'nan']]

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
                    temp = [w for w in list(df['collusive'+'.'+str(i)]) if str(w) != 'nan']
                    collude1.append(detectListLen(collude1, temp))
                    temp = [w for w in list(df['botCollude'+'.'+str(i)]) if str(w) != 'nan']
                    collude2.append(detectListLen(collude2, temp))
                    temp = [w for w in list(df['scanningMethod'+'.'+str(i)]) if str(w) != 'nan']
                    sm.append(detectListLen(sm, temp))
                    temp = [w for w in list(df['group'+'.'+str(i)]) if str(w) != 'nan']
                    gro.append(detectListLen(gro, temp))
                    temp = [w for w in list(df['binaryName'+'.'+str(i)]) if str(w) != 'nan']
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
                    temp = [w for w in list(df['exploitType'+'.'+str(i)]) if str(w) != 'nan']
                    expType.append(temp)
                    temp = [w for w in list(df['propagationType'+'.'+str(i)]) if str(w) != 'nan']
                    propType.append(detectListLen(propType, temp))
                    temp = [w for w in list(df['respondToReboot'+'.'+str(i)]) if str(w) != 'nan']
                    resp.append(detectListLen(propType, temp))
                    temp = [w for w in list(df['resideLocation'+'.'+str(i)]) if str(w) != 'nan']
                    reside.append(temp)
                    temp = [w for w in list(df['botTaskList'+'.'+str(i)]) if str(w) != 'nan']
                    btl.append(temp)
                    temp = [w for w in list(df['killerBlackList'+'.'+str(i)]) if str(w) != 'nan']
                    kbl.append(temp)
                    temp = [w for w in list(df['fortificationList'+'.'+str(i)]) if str(w) != 'nan']
                    fl.append(temp)
                    temp = [w for w in list(df['evasionList'+'.'+str(i)]) if str(w) != 'nan']
                    el.append(temp)
                    temp = [w for w in list(df['botActionList'+'.'+str(i)]) if str(w) != 'nan']
                    bal.append(temp)
                    temp = [w for w in list(df['credentialList'+'.'+str(i)]) if str(w) != 'nan']
                    cdl.append(temp)
                    
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
                                "propagationType" : propType[i],
                                "exploitType" : expType[i],
                                "exploit" : exp[i],
                                "credentialList" : cdl[i],
                                "scanPort" : sp[i],
                                "IP" : ip[i],
                                "protocol" : pro[i],
                                "collusive" : collude1[i], 
                                "botCollude" : collude2[i], 
                                "botTaskList" : [],
                                "botActionList" : bal[i],
                                "killerBlackList" : kbl[i],
                                "fortificationList" : fl[i],
                                "evasionList" : el[i],
                                "scanningMethod" : sm[i], 
                                "group" : gro[i], 
                                "binaryName" : sig[i], 
                                "content" : cont[i],
                                "goal" : go[i], 
                                "mode" : mo[i], 
                                "respondToReboot" : resp[i], 
                                "resideLocation" : reside[i],
                                "attackData" : [], 
                                "accumulatedTime" : acct[i], 
                                "status" : sta[i],
                                "target" : tar[i]
                }
                if len(btl[i]) % 3 == 0:
                    for k in range(len(btl[i])):
                        if btl[i][k] == "True" or btl[i][k] == "False":
                            temp = []
                            temp.append(btl[i][k-1])
                            if btl[i][k] == "True":
                                temp.append(bool(1))
                            else:
                                temp.append(bool(0))
                            temp.append(int(btl[i][k+1]))
                            tempAttackerInfo["botTaskList"].append(temp)
                else:
                    print("Bot task list error.")

                tempIoTAtk = dict(zip(tempAtker, [tempAttackerInfo]))
                IoTAtkDict.update(tempIoTAtk)

                tempAtkerTimeDataDict = {"AverageTime" : at[i],
                                    "scan" : {"available" : True, "proportion" : sPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "access" : {"available" : True, "proportion" : aPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "report" : {"available" : True, "proportion" : rPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                    "install" : {"available" : True, "proportion" : iPro[i], "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None}}
                
                tempAtkerTimeData = dict(zip(tempAtker, [tempAtkerTimeDataDict]))
                AtkerTimeDataDict.update(tempAtkerTimeData)

    return None

def loadDeviceInput(folderName, simRunName, IoTDeviceNum, deviceDict):
    """
    This function is identical with the one in IoTSecSimMain.py.

    We use this function to test and verify the device input file.
    """
    files = glob.iglob(os.path.join(folderName, "*.device"))

    for x in files:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')
        
        text2 = text[-1].split('.device')

        if simRunName in text2:
            df = pd.read_csv(x)

            device = [z for z in list(df['device']) if str(z) != 'nan']

            num = [int(w) for w in list(df['numbers']) if str(w) != 'nan']
            op = [[w for w in list(df['openPort']) if str(w) != 'nan']]
            dc = [[w for w in list(df['defaultCredential']) if str(w) != 'nan']]
            re = [[w for w in list(df['rebootable']) if str(w) != 'nan']]
            rcl = [[int(w) for w in list(df['resourceConsumptionNLimit']) if str(w) != 'nan']]
            pl = [[w for w in list(df['processList']) if str(w) != 'nan']]
            fil = [[w for w in list(df['filelist']) if str(w) != 'nan']]
            fol = [[w for w in list(df['folderlist']) if str(w) != 'nan']]
            cfo = [[w for w in list(df['cronFolder']) if str(w) != 'nan']]
            ifo = [[w for w in list(df['initFolder']) if str(w) != 'nan']]
            cond = [w for w in list(df['condition']) if str(w) != 'nan']
            ov = [w for w in list(df['otherValues']) if str(w) != 'nan']
            
            if IoTDeviceNum > 1:
                for i in range(1, IoTDeviceNum):
                    temp = [z for z in list(df['device'+'.'+str(i)]) if str(z) != 'nan']
                    device.append(detectListLen(device, temp))
                    temp = [int(w) for w in list(df['numbers'+'.'+str(i)]) if str(w) != 'nan']
                    num.append(detectListLen(num, temp))
                    temp = [w for w in list(df['openPort'+'.'+str(i)]) if str(w) != 'nan']
                    op.append(temp)
                    temp = [w for w in list(df['defaultCredential'+'.'+str(i)]) if str(w) != 'nan']
                    dc.append(temp)
                    temp = [w for w in list(df['rebootable'+'.'+str(i)]) if str(w) != 'nan']
                    re.append(temp)
                    temp = [int(w) for w in list(df['resourceConsumptionNLimit'+'.'+str(i)]) if str(w) != 'nan']
                    rcl.append(temp)
                    temp = [w for w in list(df['processList'+'.'+str(i)]) if str(w) != 'nan']
                    pl.append(temp)
                    temp = [w for w in list(df['filelist'+'.'+str(i)]) if str(w) != 'nan']
                    fil.append(temp)
                    temp = [w for w in list(df['folderlist'+'.'+str(i)]) if str(w) != 'nan']
                    fol.append(temp)
                    temp = [w for w in list(df['cronFolder'+'.'+str(i)]) if str(w) != 'nan']
                    cfo.append(temp)
                    temp = [w for w in list(df['initFolder'+'.'+str(i)]) if str(w) != 'nan']
                    ifo.append(temp)
                    temp = [w for w in list(df['condition'+'.'+str(i)]) if str(w) != 'nan']
                    cond.append(detectListLen(ov, temp))
                    temp = [w for w in list(df['otherValues'+'.'+str(i)]) if str(w) != 'nan']
                    ov.append(detectListLen(ov, temp))

            for i in range(len(device)):
                deviceDict[device[i]]["numbers"] = num[i]
                deviceDict[device[i]]["otherValues"] = ov[i]
                deviceDict[device[i]]["defaultCredential"] = dc[i]
                deviceDict[device[i]]["rebootable"] = re[i]
                deviceDict[device[i]]["resourceConsumptionNLimit"] = rcl[i]
                deviceDict[device[i]]["processList"] = pl[i]
                deviceDict[device[i]]["filelist"] = fil[i]
                deviceDict[device[i]]["folderlist"] = fol[i]
                deviceDict[device[i]]["cronFolder"] = cfo[i]
                deviceDict[device[i]]["initFolder"] = ifo[i]
                deviceDict[device[i]]["condition"] = cond[i]
                deviceDict[device[i]]["openPort"] = {}

                for k in range(len(op[i])):
                    if op[i][k] == "open":
                        if op[i][k+1] == "True":
                            deviceDict[device[i]]["openPort"].update({op[i][k-1]:{"open": True, "Vuln":[op[i][k+3]]}})

    return None

series = "d" #"a", "b", "c"
expNumList = [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15] 
# 1=net size; 2=no. non vul nodes; 3=average degree; 4=net topology; 5=scanning method; 
# 7=defence method; 8=comparing real malware; 9=weaponisation; 10=sync vs async propagation; 
# 11=persistence; 12=competition; 13=evasion; 14=action on objectives; 15=scalability
expNum = expNumList[13]

attackNum = ["0"]#, "1", "2", "3", "4"] # 0=single+LNC; 1=multi+LNC; 2=multi+LC; 3=multi+GNC; 4=multi+GC; #, "5", "8", "9", "12"]

#               0   1   2   3    4      5       6
nodeNumList = [25, 50, 75, 100, 1000, 10000, 100000]
nodeNum = nodeNumList[1]

#                   0      1     2     3      4    5      6     7       8     9     10     11    12     13
expCodeNameList = ["ns", "vul", "ad", "nt", "sm", "dm", "crm", "wp", "sync", "pe", "com", "ev", "aoo", "scala"] 
#ns = network size; vul = non vuln node; ad = avg degree; nt = network topology; sm = scanning method; dm = defence method; 
# crm = comparing real malware; wp=weaponisation; sync=sync vs async propagation; pe=persistence; com=competition; ev=evasion; 
# aoo=action on objectives
expCodeName = expCodeNameList[13]

#                       0          1        2           3       4        5        6         7           8           9       10      11          12
topologyStyleList = ["25same", "50same", "75same", "100same", "50dif", "grid" , "IAS", "smallworld", "scalefree", "tree", "RGG", "graphDen", "scalable"]
topologyStyle = topologyStyleList[4]

graphDensityList = [1.96, 2.53, 3.02, 4, 5.02]
graphDensity = graphDensityList[1] # can be ignored if it != graph density topology

percentageOfVulnNodesList = [None, ["all", 0.8], ["all", 0.6], ["all", 0.4], ["all", 0.2]]
percentageOfVulnNodes = percentageOfVulnNodesList[0]

specialList = ["0", "1"] # homo, hetero
special = specialList[1]

randScan = False

atkerNum = 1 #or 2 or 3 or more

defenceON = True

defenceMethod = ["firewall", "patching", "ids", "ips", "mtd", "decoy", "antimalware", "dbf"]
defenceMethodChoiceNum = [4, 5]
defenceRuleNum = [1, 1]
defenderNum = 0
if len(defenceRuleNum) > 0:
    defenderNum = sum(x for x in defenceRuleNum)

defenceMethodChoice = []

if defenceMethodChoiceNum is not None:
    for x in defenceMethodChoiceNum:
        defenceMethodChoice.append(defenceMethod[x])

defenceMethodMode = 3

amModeAll = ['Nothing', 'simple1', 'simple2', 'basic', 'advanced']
amWhereAll = ['Nothing', 'memory', 'file', 'folder']
amWhere = [amWhereAll[2], amWhereAll[3], amWhereAll[1]]
amMode = 2
amContent = "mirai"

triggerAddDM = ['firewall']

blacklist = {"SourceIP" : [],# wrong = "10.127.162.201"], #correct = ["10.127.162.234"], #
            "SourcePort" : [],
            "DestinationIP" : [],
            "DestinationPort" : [], 
            "content" : ["|00 00 00 01|", "|11 11 11 11|", "|99 99 99 99|"] #["|00 00 00 01|", "|11 11 11 11|", "|99 99 99 99|"]
            }

blSip = "any" #blacklist source ip
blSport = "any" #blacklist source port
blDip = "any" #blacklist destination ip
blDport = "any" #blacklist destination port
blContent = "any" #blacklist content

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

homogeneousDevice = False

ports = ['p1', 'p2', 'p3', 'p4', 'p5']
vuln = ['v1', 'v2', 'v3', 'v4', 'v5']
vulnTypes = ['general', 1, 'v1']

commandTypes = ['propagate', 'ddos', 'exfiltrate data', 'pdos', 'cryptomining', 'proxy server']
commandActive = [True, False]
taskResourceConsumption = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
botTaskList = [commandTypes[0], commandActive[0], taskResourceConsumption[1]]#, commandTypes[1], commandActive[1], taskResourceConsumption[3]]
botTaskList2 = [commandTypes[0], commandActive[0], taskResourceConsumption[1], commandTypes[1], commandActive[1], taskResourceConsumption[1]] #ddos
#botTaskList = [commandTypes[0], commandActive[0], taskResourceConsumption[1], commandTypes[3], commandActive[1], taskResourceConsumption[0]] #pdos
#botTaskList = [commandTypes[0], commandActive[0], taskResourceConsumption[1], commandTypes[2], commandActive[1], taskResourceConsumption[0]] #data exfiltration

actionStart = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
actionKeepBot = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
actionTargetServer = ["random", "100.127.162.10"]
actionDuration = [5, 10, 15]
botActionList = []
#botActionList = [commandTypes[1], actionStart[2], actionKeepBot[2], actionTargetServer[0], actionDuration[0]] #ddos
#botActionList = [commandTypes[3], actionStart[0], actionKeepBot[2]] #pdos
#botActionList = [commandTypes[2], actionStart[0], actionKeepBot[2]] #data exfiltration

processNameList = ["deviceOS"]
folderNameList = ["system", "cron", "init"]
fileNameList = ["device os", "device startup", "device reboot"]

evasionTypes = ['change process name', 'single instance', 'memory'] #, 'obfuscation']
evasionNum = ['no evasion', 'all', 'single', 'multiple']
evasionList = [evasionNum[0], evasionTypes[1], evasionTypes[2]]
evasionList2 = [evasionTypes[0], evasionTypes[1], evasionTypes[2]]
evasionList3 = [evasionTypes[2], evasionTypes[1]]
evasionList4 = [evasionTypes[0], evasionTypes[1]] #, evasionTypes[1], evasionTypes[2]]

killerCheckList = ['all', 'hydra', 'carna', 'mirai', 'dark_iot']#'mirai', 'aidra', 'persirai', 'carna', 'goscanssh', 'echobot']
killerTypes = ['no killer', 'once', 'periodic']
killerCheckPlace = ['all', 'process', 'file', 'cron', 'init', 'nothing']
killerBlackList = [killerTypes[0], killerCheckPlace[0], killerCheckList[0]]
killerBlackList2 = [killerTypes[1], killerCheckPlace[0], killerCheckList[0]]

fortificationCheckList = ['all', 'p0', 'p1', 'p2', 'p3', 'p4', 'p5']
fortificationTypes = ['no fortify', 'iptables']
fortificationPlace = ['all']
#fortificationList = [fortificationTypes[0], fortificationPlace[0], fortificationCheckList[2]]
fortificationList = [fortificationTypes[0], fortificationCheckList[1]]#, fortificationCheckList[3]]
fortificationList2 = [fortificationTypes[1], fortificationCheckList[1]]
fortificationList3 = [fortificationTypes[1], fortificationCheckList[0]]

expTypes = ['general', 'dc', 'vuln', 'mixed-v', 'mixed-c']
exploitNum = [0, 1, 2, 3, 4, 5, 10, -1]
wordlist = ['carna', 'mirai', 'strong', 'others', None] #'common'
otherExp = ["nothing", "authenticationbypass"]
credentialList = [] # empty

dcTypes = ["unique", "identical", wordlist[2]]#"weak", "strong", "specialwordlist"] , "mixed"
deviceDCType = dcTypes[0]
deviceWordList = wordlist[0] # carna
deviceWordList2 = wordlist[1] # mirai
deviceWordList3 = wordlist[2] # strong
deviceWordList4 = wordlist[3] # others
atkerWordList = wordlist[0]
atkerWordList2 = wordlist[1]
atkerWordList3 = wordlist[3]
atkerOtherVulnList = otherExp[0]
expVulnTypesAddonText = [expTypes[1], dcTypes[0]]

atkerList = ['hydra', 'carna', 'mirai', 'dark_iot', 'malwareX', 'spike', 'baseline', 'goscanssh', 'hns', 'dark_nexus', 'torii'] 

propagationTypes = ['async', 'sync1', 'sync2', 'mixed']
#async: 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151
#sync1: 'AverageTime', 0.5, 'ScanPro', 0.2044, 'AccessPro', 0.077, 'InstallPro', 0.7186
#sync2: 'AverageTime', 0.83, 'ScanPro', 0.1231, 'AccessPro', 0.0464, 'ReportPro', 0.3976 , 'InstallPro', 0.4329
propagationTypesA = propagationTypes[0]

respondToReboot = ['terminated', 'prevent', 'survive']
respondToRebootA = respondToReboot[0]
rebootTypes = ['manual', 'auto', 'periodic', 'disable', 'crash']
rebootTypesAll = rebootTypes[0]
binaryLocation = ['memory', 'cron', 'init']
resideLocation = []
resideLocation.append(binaryLocation[0])
# resideLocation.append(binaryLocation[1])
# resideLocation.append(binaryLocation[2])
resideLocation2 = []
resideLocation2.append(binaryLocation[0])
resideLocation2.append(binaryLocation[1])
resideLocation2.append(binaryLocation[2])

chanceToReboot = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
chanceToRebootAll = chanceToReboot[3]
timeToReboot = [0.0, 0.5, 1.0, 1.5, 2.0] # reboots every X seconds
timeToRebootAll = timeToReboot[2]
periodInReboot = [0.5, 1.0, 1.5, 2.0] # time taken to reboot a device
periodInRebootAll = periodInReboot[0]
condition = ["enable", "disable", "rebooting", "crashed", "busy"]
commandList = [["propagate", True, 20], ["ddos", False, 40], ["exfiltrate data", False, 10] , ["pdos", False, 100], ["cryptomining", False, 45], ["proxy server", False, 20]]
#botTaskList = [commandList[0], commandList[1]]

atkerA = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.127.162.55", "TCP", False, False, "d2d", "A", [atkerList[1], "attacker-1", "device0s"], ["|00 00 01 01|", "|11 11 11 21|", "|99 99 99 89|"], 
        "all", "local", 0, 1, True, [expVulnTypesAddonText[0], exploitNum[6], atkerWordList, atkerOtherVulnList], propagationTypesA, respondToRebootA, resideLocation, 
        botTaskList, killerBlackList, fortificationList2, evasionList, botActionList, credentialList]

atkerB = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.55.162.41", "TCP", False, False, "d2d", "B", [atkerList[2], "attacker-1", "sysR00t"], ["|00 00 02 02|", "|11 11 11 21|", "|99 99 99 89|"], 
        "all", "local", 0, 1, True, [expVulnTypesAddonText[0], exploitNum[6], atkerWordList, atkerOtherVulnList], propagationTypesA, respondToRebootA, resideLocation, 
        botTaskList, killerBlackList, fortificationList2, evasionList, botActionList, credentialList]

atkerC = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.44.162.44", "TCP", False, False, "d2d", "C", [atkerList[8], "attacker-1", "admin0s"], ["|00 00 03 03|", "|11 11 11 21|", "|99 99 99 89|"], 
        "all", "local", 0, 1, True, [expVulnTypesAddonText[0], exploitNum[6], atkerWordList, atkerOtherVulnList], propagationTypesA, respondToRebootA, resideLocation, 
        botTaskList, killerBlackList, fortificationList2, evasionList, botActionList, credentialList]

atkerD = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.22.162.135", "TCP", False, False, "d2d", "D", [atkerList[2], "attacker-1", "other0s"], ["|00 00 04 04|", "|11 11 11 21|", "|99 99 99 89|"], 
        "all", "local", 0, 1, True, [expVulnTypesAddonText[0], exploitNum[6], atkerWordList, atkerOtherVulnList], propagationTypesA, respondToRebootA, resideLocation, 
        botTaskList, killerBlackList2, fortificationList2, evasionList4, botActionList, credentialList]

atkerE = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v1"], ["p1"], "10.22.162.66", "TCP", False, False, "d2d", "E", [atkerList[0], "attacker-1", "device0s"], ["|00 00 05 05|", "|11 11 21 21|", "|99 99 00 89|"], 
        "all", "local", 0, 1, True, [expTypes[0], exploitNum[1], wordlist[4], atkerOtherVulnList], propagationTypesA, respondToRebootA, resideLocation, 
        botTaskList, killerBlackList, fortificationList3, evasionTypes[1], botActionList, credentialList]

atkerMirai = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.22.162.66", "TCP", False, False, "d2d", "F", [atkerList[2], "attacker-1", "device0s"], ["|00 00 01 05|", "|11 11 21 21|", "|99 99 00 89|"], 
        "all", "local", 0, 1, True, [expTypes[1], exploitNum[6], wordlist[1], atkerOtherVulnList], propagationTypes[0], respondToReboot[0], resideLocation, 
        botTaskList, killerBlackList2, fortificationList3, evasionList2, botActionList, credentialList]

atkerDNexus = ['attacker-1', 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151, 
        ["v99"], ["p0"], "10.22.162.66", "TCP", False, False, "d2d", "G", [atkerList[9], "attacker-1", "device0s"], ["|00 00 02 05|", "|11 11 21 21|", "|99 99 00 89|"], 
        "all", "local", 0, 1, True, [expTypes[1], exploitNum[6], wordlist[1], atkerOtherVulnList], propagationTypes[1], respondToReboot[1], resideLocation2, 
        botTaskList, killerBlackList2, fortificationList3, evasionList4, botActionList, credentialList]

vsBattle = ["F"]#"A"]#, "D"]
secondIP = ["10.33.162.115", "10.44.162.125", "10.55.162.135", "10.66.162.145"]
secondGroup = ["B", "C", "D", "E"]
secondAtker = ['attacker-2', 'attacker-3', 'attacker-4', 'attacker-5']

for a in range(1):
    #atkerWordList = wordlist[0]
    for b in range(1):
        deviceWordList2 = wordlist[0]

        for i in range(len(attackNum)):
            atkerData = []
            for c in range(len(vsBattle)):
                e = 0
                if c == 0:
                    if vsBattle[c] == "A":
                        atkerData.append(atkerA)
                    elif vsBattle[c] == "B":
                        atkerData.append(atkerB)
                    elif vsBattle[c] == "C":
                        atkerData.append(atkerC)
                    elif vsBattle[c] == "D":
                        atkerData.append(atkerD)
                    elif vsBattle[c] == "E":
                        atkerData.append(atkerE)
                    elif vsBattle[c] == "F":
                        atkerData.append(atkerMirai)
                    elif vsBattle[c] == "G":
                        atkerData.append(atkerDNexus)
                else:
                    temp = []
                    if vsBattle[c] == "A":
                        temp = copy.deepcopy(atkerA)
                    elif vsBattle[c] == "B":
                        temp = copy.deepcopy(atkerB)
                    elif vsBattle[c] == "C":
                        temp = copy.deepcopy(atkerC)
                    elif vsBattle[c] == "D":
                        temp = copy.deepcopy(atkerD)
                    elif vsBattle[c] == "E":
                        temp = copy.deepcopy(atkerE)
                    elif vsBattle[c] == "F":
                        temp = copy.deepcopy(atkerMirai)
                    elif vsBattle[c] == "G":
                        temp = copy.deepcopy(atkerDNexus)
                    
                    temp[0] = secondAtker[e]
                    temp[13] = secondIP[e]
                    temp[18] = secondGroup[e]
                    temp[19][1] = secondAtker[e]
                    e += 1

                    atkerData.append(temp)

            IoTDeviceSetup = {"iotdevice": {"numbers" : 0,
                                            "openPort" : [ports[0], "open", True, "Vuln", vuln[0]],# "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "lightbulb": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "nvr": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", False, "Vuln", None, "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "ipcamera": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "projector": {"numbers" : 0,
                                            "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "router": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : "Cannot be compromised"
                                            },
                            "tv": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", True, "Vuln", "v2", "p3", "open", False, "Vuln", None, "p4", "open", False, "Vuln", None],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "printer": {"numbers" : 0,
                                            "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", False, "Vuln", None, "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #deviceWordList3], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "laptop": {"numbers" : 0,
                                            "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", True, "Vuln", "v4"],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #deviceWordList3], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "fridge": {"numbers" : 0,
                                            "openPort" : ["p1", "open", False, "Vuln", None, "p2", "open", True, "Vuln", "v2", "p3", "open", True, "Vuln", "v3", "p4", "open", False, "Vuln", None],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            },
                            "smokeAlarm": {"numbers" : 0,
                                            "openPort" : ["p1", "open", True, "Vuln", "v1", "p2", "open", False, "Vuln", None, "p3", "open", True, "Vuln", "v3", "p4", "open", False, "Vuln", None],
                                            "defaultCredential" : ['p0', "open", True, dcTypes[0], deviceWordList2], #deviceWordList3], #dcTypes[2]],
                                            "rebootable" : [rebootTypesAll, chanceToRebootAll, timeToRebootAll, periodInRebootAll],
                                            "resourceConsumptionNLimit" : [56, 100], #[consumption, limit]
                                            "processList" : [processNameList[0]],
                                            "filelist" : [fileNameList[0], fileNameList[1], fileNameList[2]],
                                            "folderlist" : [folderNameList[0], folderNameList[1], folderNameList[2]],
                                            "cronFolder" : [folderNameList[1]],
                                            "initFolder" : [folderNameList[2]],
                                            "condition" : condition[0],
                                            "otherValues" : None
                                            }
                            }

            IoTDeviceNum = len(IoTDeviceSetup)

            defenderData = []
            if defenceON == True:
                for x, y in zip(defenceMethodChoice, defenceRuleNum):
                    for j in range(y):
                        z = x + '-' + str(j+1)
                        if str(x) == "ids":
                            num = 101 + j
                            temp = [z, num, "Action", "alert", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", "->", "DestinationIP", blDip, "DestinationPort", blDport,
                            "msg", "Alert! Someone is trying to enter network via IP address", "content", blContent, "rev", 1, "priority", 10, "where", None, "vulnerability", None, "triggerAttempt", 1, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", triggerAddDM, "configuration", None]
                        elif str(x) == "ips":
                            num = 201 + j
                            temp = [z, num, "Action", "drop", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", "->", "DestinationIP", blDip, "DestinationPort", blDport,
                            "msg", "Blocking dest port p1", "content", blContent, "rev", 1, "priority", 10, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None, "configuration", None]
                        elif str(x) == "firewall":
                            num = 301 + j
                            temp = [z, num, "Action", "allow", "Protocol", "any", "SourceIP", blSip, "SourcePort", blSport, "FlowDirection", None,"DestinationIP", blDip, "DestinationPort", blDport,
                            "msg", "Allow all", "content", None, "rev", None, "priority", None, "where", where, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None, "configuration", None]
                        elif str(x) == "patching":
                            num = 401 + j
                            temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                            "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", [], "triggerAttempt", 5, "smart", None, "dummy", None, defenceMethodMode, "addNewRule", None, "configuration", None]
                        elif str(x) == "decoy":
                            num = 501 + j
                            temp = [z, num, "Action", "isolation", "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                            "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", 5, "dummy", 0, 1, "addNewRule", None, "configuration", None]
                        elif str(x) == "mtd":
                            num = 601 + j
                            temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                            "msg", None, "content", None, "rev", None, "priority", 0.5, "where", None, "vulnerability", [], "triggerAttempt", 5, "smart", None, "dummy", None, 3, "addNewRule", None, "configuration", []]
                        elif str(x) == "antimalware":
                            num = 701 + j
                            temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                            "msg", None, "content", amContent, "rev", None, "priority", None, "where", amWhere, "vulnerability", None, "triggerAttempt", None, "smart", None, "dummy", None, amMode, "addNewRule", None, "configuration", None]
                        elif str(x) == "dbf":
                            # [which node, node num, [binary file names], time to check, response1, response2]
                            # = [['all', 50, ['mirai', 'carna', 'hns', 'hajime'], 2s], 
                            # ['lightbulb', 5, ['mirai', 'carna'], 5s]]
                            num = 801 + j
                            temp = [z, num, "Action", None, "Protocol", None, "SourceIP", None, "SourcePort", None, "FlowDirection", None,"DestinationIP", None, "DestinationPort", None,
                            "msg", None, "content", None, "rev", None, "priority", None, "where", None, "vulnerability", None, "triggerAttempt", None, "smart", 5, "dummy", 0, defenceMethodMode, "addNewRule", None, "configuration", configList]
                        
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
                if nodeNum == 50:
                    numlist = [0, 19, 1, 4, 2, 3, 3, 8, 9, 1, 3]
                    m = 0
                    for x in IoTDeviceSetup:
                        IoTDeviceSetup[x]["numbers"] = numlist[m]
                        m+=1
                else:
                    IoTDeviceSetup["lightbulb"]["numbers"] = nodeNum
                    IoTDeviceSetup["router"]["numbers"] = 3

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
                        "method" : "Is a device that can inspect traffic, detect threat based on signature and proactively stop malicious traffic", # https://ipwithease.com/firewall-vs-ips-vs-ids/
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
                            "mode" : 0,
                            "shufflelist" : [], 
                            "nodenum" : 0, 
                            "isolationlist" : [],
                            "shuffletime" : 0,
                            "restorelist" : [],
                            "resetlist" : []
                            # 1 for "topology shuffling" 
                            # 2 for "ip shuffling"
                            # 3 for "AP shuffling"
                            # 4 for "isolation"
                            # 5 for "reset"
                            # 6 for "restore connection"
                        },

                "Deception" : {"operational" : False,
                            "method" : "add decoy node to deceive attackers",
                            "mode" : 0,
                            # 1 for "add decoy" 
                            # 2 for "convert into decoy"
                            "model" : {"smart" : 0, "dummy" : 0},
                            "response" : None
                        },

                "DBF" : {"operational" : False,
                        "method" : "add decoy binary files to iot nodes",
                        "configuration" : []
                        # [which node, node num, [binary file names], time to check, response]
                        },

                "AntiMalware" : {"operational" : False,
                            "method" : "scan and detect malicious files",
                            "mode" : 0,
                            "checkLocation" : None,
                            "content" : None
                        }
                        }

            simRunName = createSimName(series, expNum, str(attackNum[i]), nodeNum, expCodeName, topologyStyle, graphDensity, graphDensityList, 
                                        percentageOfVulnNodes, defenceON, defenceMethodChoice, expVulnTypesAddonText, propagationTypesA, respondToRebootA, 
                                        resideLocation, botTaskList, killerBlackList, fortificationList2, evasionList, deviceWordList2, atkerWordList, 
                                        rebootTypesAll, vsBattle)
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
                pass

            line7 = "atkerNum=" + str(atkerNum)

            line8 = "defenderNum=" + str(defenderNum)

            line9 = "deviceTypeNum=" + str(IoTDeviceNum)

            inputFilename = simRunName + ".input"

            lineList = [line1, line2, line3, line4, line5, line6, line7, line8, line9]

            for y in lineList:
                createRecord(y, os.path.join(folderName, inputFilename))

            if randScan == True:
                for x in atkerData:
                    x[17] = "random"

            if attackNum[i] == "0":
                if len(atkerData) > 1:
                    atkerData.pop(1)

            if attackNum[i] == "2" or attackNum[i] == "4":
                for x in atkerData:
                    x[15] = True
                    x[16] = True
                    x[18] = "A"

            if attackNum[i] == "3" or attackNum[i] == "4":
                for x in atkerData:
                    x[22] = "global"
                    
            #async: 'AverageTime', 0.9707, 'ScanPro', 0.1053, 'AccessPro', 0.0397, 'ReportPro', 0.34 , 'InstallPro', 0.5151
            #sync1: 'AverageTime', 0.5, 'ScanPro', 0.2044, 'AccessPro', 0.077, 'InstallPro', 0.7186
            #sync2: 'AverageTime', 0.83, 'ScanPro', 0.1231, 'AccessPro', 0.0464, 'ReportPro', 0.3976 , 'InstallPro', 0.4329
            for x in atkerData:
                if x[27] == "async":
                    x[2] = 0.9707
                    x[4] = 0.1053
                    x[6] = 0.0397
                    x[8] = 0.34
                    x[10] = 0.5151
                elif x[27] == "sync1":
                    x[2] = 0.5
                    x[4] = 0.2044
                    x[6] = 0.077
                    x[8] = 0.0
                    x[10] = 0.7186
                elif x[27] == "sync2":
                    x[2] = 0.83
                    x[4] = 0.1231
                    x[6] = 0.0464
                    x[8] = 0.3976
                    x[10] = 0.4329
                else:
                    pass
                    
            createAtkerInput(simRunName, atkerNum, atkerData)
            loadAtkerInput(folderName, simRunName, atkerNum, IoTAtkDict, AtkerTimeDataDict)
            if len(defenderData) > 0:
                createDefenceInput(simRunName, defenderData)
                loadDefenderInput(folderName, simRunName, defenderNum, IoTDefence)

            createDeviceInput(simRunName, IoTDeviceSetupNew)
            loadDeviceInput(folderName, simRunName, IoTDeviceNum, IoTDeviceSetupNew)