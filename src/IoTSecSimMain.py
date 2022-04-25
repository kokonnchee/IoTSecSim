'''
This module serves as the starting point for IoTSecSim. Set up parameters and run simulations. 

@author: Kok Onn Chee
'''
import sys
import os, glob
import pandas as pd
import copy
from timeit import default_timer as timer
from datetime import timedelta

from IoTNetworkGen import *
from SaveToFile import *
from SecurityAnalysis import *
from DatasetGen import *
from GraphsGen import *

#=================================================================================================
# Message Passing Interface (MPI) for Parallelization
#=================================================================================================
"""
[MPI Tutorial]:
https://www.youtube.com/watch?v=JrCMi3_yCA0
"""
#MPI Setup------
from mpi4py import MPI

comm = MPI.COMM_WORLD
root = 0 #specify 0 as root
rank = comm.Get_rank() #the rank of process
num_procs = comm.Get_size() #get the number of processes
#MPI Setup------


#=================================================================================================
# IoTSecSim Main 
#=================================================================================================

def getDeviceNum(mode, solution_set):
    """
    Create attack graph.
    """
    if mode == "home":
        return solution_set['iotdevice']['numbers'], solution_set['lightbulb']['numbers'], solution_set['slowcooker']['numbers'], solution_set['ipcamera']['numbers'], solution_set['dvr']['numbers'], solution_set['router']['numbers']
    elif mode == "office":
        return solution_set['iotdevice']['numbers'], solution_set['lightbulb']['numbers'], solution_set['nvr']['numbers'], solution_set['ipcamera']['numbers'], solution_set['projector']['numbers'], solution_set['router']['numbers'], solution_set['tv']['numbers'], solution_set['printer']['numbers'], solution_set['laptop']['numbers'], solution_set['fridge']['numbers'], solution_set['smokeAlarm']['numbers']
    else:
        print("Error!!")
        return None

def initialiseIoTNetwork(mode, IoTDeviceSetup, topologyStyle, attackerList, IoTDefence, AtkerTimeDataDict, saveSimDir, saveFolder, entryPointNode, percentageOfVulnNodes, specialChanges, graphDensity):
    device = []
    iotdeviceNum = 0
    lightbulbNum = 0
    slowcookerNum = 0
    ipcameraNum = 0
    dvrNum = 0
    routerNum = 0
    nvrNum = 0
    projectorNum = 0
    tvNum = 0
    printerNum = 0
    laptopNum = 0
    fridgeNum = 0
    smokeAlarmNum = 0

    if mode == "home":
        iotdeviceNum, lightbulbNum, slowcookerNum, ipcameraNum, dvrNum, routerNum = getDeviceNum(mode, IoTDeviceSetup)
    elif mode == "office":
        iotdeviceNum, lightbulbNum, nvrNum, ipcameraNum, projectorNum, routerNum, tvNum, printerNum, laptopNum, fridgeNum, smokeAlarmNum = getDeviceNum(mode, IoTDeviceSetup)

    deviceTotal = 0
    
    if iotdeviceNum > 0:
        for i in range(0, iotdeviceNum):
            device.append("iotdevice-" + str(i + 1))
            deviceTotal += 1
    if routerNum > 0:
        for i in range(0, routerNum):
            device.append("router-" + str(i + 1))
            deviceTotal += 1
    if lightbulbNum > 0:
        for i in range(0, lightbulbNum):
            device.append("lightbulb-" + str(i + 1))
            deviceTotal += 1
    if printerNum > 0:
        for i in range(0, printerNum):
            device.append("printer-" + str(i + 1))
            deviceTotal += 1
    if laptopNum > 0:
        for i in range(0, laptopNum):
            device.append("laptop-" + str(i + 1))
            deviceTotal += 1
    if ipcameraNum > 0:
        for i in range(0, ipcameraNum):
            device.append("ipcamera-" + str(i + 1))
            deviceTotal += 1
    if tvNum > 0:
        for i in range(0, tvNum):
            device.append("tv-" + str(i + 1))
            deviceTotal += 1
    if projectorNum > 0:
        for i in range(0, projectorNum):
            device.append("projector-" + str(i + 1))
            deviceTotal += 1
    if nvrNum > 0:
        for i in range(0, nvrNum):
            device.append("nvr-" + str(i + 1))
            deviceTotal += 1
    if fridgeNum > 0:
        for i in range(0, fridgeNum):
            device.append("fridge-" + str(i + 1))
            deviceTotal += 1
    if smokeAlarmNum > 0:
        for i in range(0, smokeAlarmNum):
            device.append("smokeAlarm-" + str(i + 1))
            deviceTotal += 1
    if dvrNum > 0:
        for i in range(0, dvrNum):
            device.append("dvr-" + str(i + 1))
            deviceTotal += 1
    if slowcookerNum > 0:
        for i in range(0, slowcookerNum):
            device.append("slowcooker-" + str(i + 1))
            deviceTotal += 1

    net = createIoTNetwork(device, topologyStyle, IoTDeviceSetup, IoTDefence, AtkerTimeDataDict, saveSimDir, saveFolder, entryPointNode, percentageOfVulnNodes, specialChanges, graphDensity) ## for other topologies

    addAttackersToPool(net, attackerList)

    return net

def executeSim(net):
    h = constructHARM(net)
    return None

def createDataset(datasetFile, AtkerTimeDataDict):
    """
    Create dataset for each phase.
    """
    for x in AtkerTimeDataDict:
        setupDataset(AtkerTimeDataDict[x])

    for x in AtkerTimeDataDict:
        for id, info in AtkerTimeDataDict[x].items():
            temp = datasetFile+str(x)+'+'+str(id)
            tempList = []
            if id == "AverageTime":
                pass
            else:
                for key in info:
                    s1 = None
                    if key == 'timeData':
                        temp1 = temp+'_'+str(key)+'.csv'
                        df1 = pd.DataFrame(info[key])
                        df1.to_csv(temp1)
                    else:
                        s1 = pd.Series(info[key], name=str(key))
                    if s1 is not None:
                        tempList.append(s1)
                if len(tempList) > 0:
                    tempS = pd.Series(AtkerTimeDataDict[x]["AverageTime"], name=str(id))
                    tempList.append(tempS)
                df = pd.concat(tempList, axis=1)
                df.to_csv(temp+'.csv')
    return None

def loadDataset(datasetDir, AtkerTimeDataDict):
    """
    Load dataset into simulation tool.
    """
    files = glob.iglob(os.path.join(datasetDir, "*.csv"))

    print("\nLoading all datasets into simulator...")
    for x in files:
        text = x.split('/')
        if len(text) == 1:
            text = x.split('\\')
        text2 = text[-1].split('_')
        df = pd.read_csv(x)
        if 'timeData.csv' in text2:
            text3 = text2[0].split('+')
            AtkerTimeDataDict[text3[0]][text3[1]]['timeData'] = list(df['0'])
        else:
            text3 = text2[-1].split('.csv')
            text4 = text3[0].split('+')
            di = [z for z in list(df['dist']) if str(z) != 'nan']
            AtkerTimeDataDict[text4[0]][text4[1]]['dist'] = di[0]
            pv = [w for w in list(df['pVal']) if str(w) != 'nan']
            AtkerTimeDataDict[text4[0]][text4[1]]['pVal'] = float(pv[0])
            AtkerTimeDataDict[text4[0]][text4[1]]['params'] = [x for x in list(df['params']) if str(x) != 'nan']
            AtkerTimeDataDict[text4[0]][text4[1]]['parameterX'] = [x for x in list(df['parameterX']) if str(x) != 'nan']
    return None

def readInput(inputfile):
    """
    Load normal information for simulation run.
    """
    dataList = []
    if len(inputfile) > 1:
    #if inputfile is not None:
        #for x in inputfile:
        lines = []
        file1 = open(inputfile, 'r')
        lines = file1.readlines()

        for y in lines:
            inputData = y.strip().split('=')
            dataList.append(inputData[0])
            if len(inputData) > 1:
                for i in range(1, len(inputData)): 
                    dataList.append(inputData[i])
        file1.close()
    else:
        print("Input file not found! Simulation terminated!")
        sys.exit(1)

    if len(dataList) > 0:
        temp = []
        attacks = []
        percentageOfVulnNodes = []
        atkerNum = 0
        defenderNum = 0
        deviceTypeNum = 0
        for i in range (len(dataList)):
            if dataList[i] == "simRunName":
                ts = dataList[i+1]
            elif dataList[i] == "topologyStyle":
                topologyStyle = dataList[i+1]
            elif dataList[i] == "graphDensity":
                graphDensity = float(dataList[i+1])
            elif dataList[i] == "special":
                if dataList[i+1] == "0":
                    special = True
                else:
                    special = False
            elif dataList[i] == "attackNum":
                attacks.append(dataList[i+1])
            elif dataList[i] == "percentageOfVulnNodes":
                if dataList[i+1] == "None":
                    percentageOfVulnNodes = []
                else:
                    text = dataList[i+1].split("+")
                    temp.append(text[0])
                    temp.append(float(text[1]))
                    percentageOfVulnNodes.append(temp)
            elif dataList[i] == "atkerNum":
                atkerNum = int(dataList[i+1])
            elif dataList[i] == "defenderNum":
                defenderNum = int(dataList[i+1])
            elif dataList[i] == "deviceTypeNum":
                deviceTypeNum = int(dataList[i+1])
            else:
                pass
    else:
        print("No data found!")
        sys.exit(1)
    return ts, topologyStyle, graphDensity, special, attacks, percentageOfVulnNodes, atkerNum, defenderNum, deviceTypeNum

def loadAtkerInput(folderName, simRunName, atkerNum, IoTAtkDict, AtkerTimeDataDict):
    """
    Load attacker information for simulation run.
    """
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
    
    return None

def loadDefenderInput(folderName, simRunName, defenderNum, IoTDefence):
    """
    Load defence information for simulation run.
    """
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

    return None

def loadDeviceInput(folderName, simRunName, IoTDeviceNum, deviceDict):
    """
    Load device information for simulation run.
    """
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

    return None

def detectListLen(list1, list2):
    """
    Detect the length of a list.
    """
    if len(list1) == 0:
        list1.append(None)

    if len(list2) > 0:
        return list2[0]
    else:
        return None

def getTargetlist(special, topologyStyle, order):
    """
    Determine the target list for global learning option.
    """
    targetList = []
    num = 0
    if topologyStyle == "25same" or topologyStyle == "75same" or topologyStyle == "100same":
        if topologyStyle == "25same":
            num = 25
        elif topologyStyle == "75same":
            num = 75
        else:
            num = 100
    else:
        num = 50

    if special == True:
        for i in range(num):
            tempStr = "iotdevice-"+str(i+1)
            targetList.append(tempStr)

        if order == False:
            targetList.reverse()
    else:
        targetList = ["laptop-1", "printer-1", "lightbulb-1", "lightbulb-3", "lightbulb-2", "printer-3", "laptop-3", "printer-4", "laptop-4", "lightbulb-4", "laptop-5", "ipcamera-1", "lightbulb-5", "laptop-2", "printer-2", "smokeAlarm-1", "nvr-1", "ipcamera-2", "ipcamera-3", "tv-1", "lightbulb-14", "lightbulb-11", "projector-1", "lightbulb-9", "lightbulb-10", "fridge-1", "lightbulb-7", "lightbulb-8", "lightbulb-13", "lightbulb-12", "projector-2", "tv-2", "lightbulb-6", "tv-3", "smokeAlarm-2", "lightbulb-16", "ipcamera-4", "lightbulb-15", "printer-5", "laptop-6", "printer-6", "laptop-7", "lightbulb-17", "lightbulb-18", "lightbulb-19", "laptop-9", "printer-8", "laptop-8", "printer-7", "smokeAlarm-3"]
        
        if order == False:
            targetList.reverse()

    return targetList

def runSimulation(inputfile, simRunName, currentDir):
    """
    Initialise simulation by loading data (attacker, defender, device, and network) and creating new datasets.
    """

    #currentDir = os.getcwd()

    #inputfile = glob.iglob(os.path.join(currentDir, "*.input"))

    ts, topologyStyle, graphDensity, special, attacks, percentageOfVulnNodes, atkerNum, defenderNum, deviceTypeNum = readInput(inputfile)

    detectHPCmode = currentDir.split("/")
    repeatNum = 500 #for HPC

    if len(detectHPCmode) == 1:
        detectHPCmode = currentDir.split('\\')
        repeatNum = 5 #for local testing

    folderName = "none"
    
    entryPointNode = []#"iotdevice-1", "iotdevice-2", "iotdevice-3"]#["router"]
        
    specialChanges = {"Vuln" : {"Change": False, 
                                "Content": {"v1": 0.5, "v2": 0.5}, # 0.0 (None) -> 1.0 (all)
                                "Overlap": False
                                }, 
                    "Port": {"Change": False, 
                            "Content": {"p1": 0.5, "p2": 0.5},
                            "Overlap": False
                            }
                    }

    AtkerTimeDataDict = {"X" : {"AverageTime" : 0, 
                                        "scan" : {"available" : True, "proportion" : 0, "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                        "access" : {"available" : True, "proportion" : 0, "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                        "report" : {"available" : True, "proportion" : 0, "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None},
                                        "install" : {"available" : True, "proportion" : 0, "timeData" : None, "dist" : None, "pVal" : 0, "params" : None, "parameterX" : None}} 
    }

    IoTAttack = {"X" : {"AverageTime" : 0.00, 
                        "exploit" : [], 
                        "scanPort" : [],
                        "IP" : "",
                        "protocol" : "",
                        "cooperative" : False, 
                        "botCoop" : False, 
                        "scanningMethod" : "", # or "random"
                        "group" : "", 
                        "signature" : [], 
                        "content" : [],
                        "goal" : 0, 
                        "mode" : "", 
                        "attackData" : [], 
                        "accumulatedTime" : 0, 
                        "status" : 0,
                        "target" : None
                        }
                }

    loadAtkerInput(currentDir, simRunName, atkerNum, IoTAttack, AtkerTimeDataDict)
    IoTAttack.pop("X")
    AtkerTimeDataDict.pop("X")
    
    for x in IoTAttack:
        if attacks[0] == "9" or attacks[0] == "12":
            IoTAttack[x]["target"] = getTargetlist(special, topologyStyle, IoTAttack[x]["target"])
        else:
            IoTAttack[x].pop("target", None)

    #setup for IoT device
    IoTDeviceSetup = {"iotdevice": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "lightbulb": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "nvr": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "ipcamera": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "projector": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "router": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : "Cannot be compromised"
                                },
                "tv": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "printer": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "laptop": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "fridge": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                },
                "smokeAlarm": {"numbers" : 0,
                                "openPort" : {},
                                "otherValues" : None
                                }
                }

    loadDeviceInput(currentDir, simRunName, deviceTypeNum, IoTDeviceSetup)

    #Security Control
    IoTDefence = {
        "IDS" : {"operational" : False,
                "method" : "monitor network and generate warning message if detected anything suspicious",
                "log type" : [],#["all", "alert"], #Actions type: alert, log, pass, activate, dynamic, drop, reject, sdrop
                "triggerAttempt" : 0,
                "addNewRule": [],
                "rule" : {
                        }
                },
        "IPS" : {"operational" : False,
                "method" : "inspect traffic, detect malicious threat based on signature and proactively block malicious attacks",
                "rule" : {
                        }
                },
        "Firewall" : {"operational" : False,
                    "method" : "monitor and control network",
                    "mode" : 0, 
                    # 1 for pre-attack blacklist IP (specific IP address only);
                    # 2 for mid-attack firewall (with IDS and trigger);
                    # 3 for pre-attack blacklist Port Num (specific port num only);
                    "rule" : {
                        }
                },
        "Patching" : {"operational" : False,
                    "method" : "remove vulnerability",
                    "mode" : 0, 
                    # 1 for pre-attack patch type 1 (specific vuln only); example: [["iotdevice", "v2"]]
                    # 2 for pre-attack patch type 2 (full device); example: [["iotdevice", "all"]]
                    # 3 for mid-attack patch (with IDS); example: [["iotdevice", "v1"]] with a trigger
                    "vulnerability" : [], 
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
    if defenderNum > 0:
        loadDefenderInput(currentDir, simRunName, defenderNum, IoTDefence)
    
    iotatk = copy.deepcopy(IoTAttack)
    folderName = ts

    saveFolder = os.path.join(currentDir, folderName)

    tempfolderName = saveFolder.split("/")
    if len(tempfolderName) == 1:
        tempfolderName = saveFolder.split('\\')

    tempName = tempfolderName[-1].split('-I')

    ncpfilename = str(tempName[0])+"+ncp.c"
    sumTfilename = str(tempName[0])+"+summary.t"
    sumCfilename = str(tempName[0])+"+summary.c"

    file1 = os.path.join(saveFolder, sumTfilename)
    file5 = os.path.join(saveFolder, sumCfilename)
    file6 = os.path.join(saveFolder, ncpfilename)
    
    if not os.path.isdir(saveFolder):
        try:
            os.makedirs(saveFolder)
        except:
            pass
    
    for i in range(rank, repeatNum, num_procs): 
        print("\nSim No. ", i+1)
        saveSimDir = os.path.join(saveFolder, "Sim{}".format(i+1))

        if not os.path.isdir(saveSimDir):
            try:
                os.makedirs(saveSimDir)
            except:
                pass

        datasetDir = os.path.join(saveSimDir, "dataset")
        datasetFile = datasetDir+"\\"
        if not os.path.isdir(datasetDir):
            try:
                os.makedirs(datasetDir)
            except:
                pass

        AtkerTimeDataDictcopy = copy.deepcopy(AtkerTimeDataDict)
        createDataset(datasetFile, AtkerTimeDataDictcopy)
        loadDataset(datasetDir, AtkerTimeDataDictcopy)
        iotatkcopy = copy.deepcopy(iotatk)
        IoTDefencecopy = copy.deepcopy(IoTDefence)
        IoTDeviceSetupcopy = copy.deepcopy(IoTDeviceSetup)
        print("\nSimulation is running... Please wait...")
        officeDifSim = initialiseIoTNetwork("office", IoTDeviceSetupcopy, topologyStyle, iotatkcopy, IoTDefencecopy, AtkerTimeDataDictcopy, saveSimDir, saveFolder, entryPointNode, percentageOfVulnNodes, specialChanges, graphDensity) ## False for different nodes

        executeSim(officeDifSim)

        convertPNGtoGIF(saveSimDir) ## combine all png to become a gif
        remainingNum = repeatNum - i - 1
        if remainingNum > 0:
            print("\n" + str(remainingNum) + " simulation" + (" " if remainingNum == 1 else "(s) ") + "remaining...")
        else:
            print("\nAll " + str(repeatNum) + " simulation(s) are done... ")

    if os.path.isfile(file1) and os.path.isfile(file5) and os.path.isfile(file6):
        averageTimeToCompromiseNetwork(file1, file5, saveFolder)
        networkCompromisePercentageGraphForAllSims(file6, saveFolder)
    return None

if __name__ == '__main__':
    
    start = timer()
    print("START TIMER :: ", start, "\n")

    currentDir = os.getcwd()

    inputfile = glob.iglob(os.path.join(currentDir, "*.input"))

    for x in inputfile:
        text = x.split("/")
        if len(text) == 1:
            text = x.split('\\')
        
        text2 = text[-1].split('.input')

        simRunName = text2[0]
        print("==================================START=================================\n")
        print("Loading input files...")
        print(x)

        runSimulation(x, simRunName, currentDir)

    end = timer()
    print("\nEND TIMER :: ", end)
    print("TOTAL TIME SPENT :: ", timedelta(seconds=end-start))

