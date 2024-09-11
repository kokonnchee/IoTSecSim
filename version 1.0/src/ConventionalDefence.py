'''
This module constructs conventional defence techniques for IoTSecSim.

@author: Kok Onn Chee
'''
import numpy as np
import datetime
import os
from ipaddress import IPv4Address, IPv4Network, IPv6Address
from random import uniform, choice

from SaveToFile import *
from Network import *
from Node import *
from Vulnerability import *

class defenceMethods(object):
    def __init__(self):

        self.rulesetFW = {}
        self.rulesetIDS = {}
        self.rulesetIPS = {}
        self.memory = {}

    def intrusionDetectionSystem(self, trafficContent, logType, filepath):
        """
        Intrusion Detection System (IDS) - Model based on SNORT IDS
        Description: A device or software app that monitors a network for malicious activity. Will report the suspicious activity to users.
        Able to detect intrusion based on malware signature when attackers want to gain access or compromise a node.
        """

        """
        Rule format: Action - Protocol - Source/Destination IP's - Source/Destination Ports - Direction of the flow
        Example: alert udp !10.1.1.0/24 any -> 10.2.0.0/24 any
        
        alert icmp any any -> any any (msg:"ICMP Packet"; sid:477; rev:3;)

        snort log sample:
        [**] [1:477:3] ICMP Packet [**]
        [Priority: 0]
        04/30-07:54:41.759229 172.25.212.245 -> 172.25.212.153
        ICMP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:96 DF
        Type:8  Code:0  ID:16348   Seq:0  ECHO


        alert tcp any any -> any any (msg:"Exploit detected"; sid:1000001; content:"exploit";)

        Snort log sample:

        [**] [1:1000001:0] Exploit detected [**]
        [Priority: 0]
        04/30-07:54:38.312536 172.25.212.204:80 -> 192.168.255.110:46127
        TCP TTL:64 TOS:0x0 ID:19844 IpLen:20 DgmLen:505 DF
        ***AP*** Seq: 0xF936BE12  Ack: 0x2C9A47D8  Win: 0x7B  TcpLen: 20
        """
        """
        Actions type: alert, log, pass, activate, dynamic, drop, reject, sdrop
        Protocols type: TCP, UDP, ICMP, IP

        https://www.sbarjatiya.com/notes_wiki/index.php/Configuring_snort_rules#Types_of_action

        alert       Generate an alert using the selected alert method, and then log the packet. We can do different types of analysis on logged packets later on.
        log         Log the packet. Basically packet will get logged in snort log file and we can do different type of analysis on this logged packet later.
        pass        Ignore the packet. This is like ACCEPT target of iptables firewall rules.
        activate    Alert and then activate another dynamic rules. Dynamic rules are applied only when they are activated by some other rule. For example if we are checking for some HTTP GET related vulnerability, then we can first check whether connection is an HTTP GET connection and if it is, then activate HTTP GET related checks. This makes snort very efficient as many rules are checked only if some other rule activates them.
        dynamic     This rules are idle until activated by some other rule. After being activated they act as long rule. These are used to log packets only when some alert is triggered to avoid unnecessary logging of all packets most of which may not have any attack.
        drop        Block the packet and also log it.
        reject      Block the packet, log it and then also send TCP RST if connection is TCP based connection, or send ICMP unreachable packets if connection is UDP based connection.
        sdrop       Block the packet but do not log it. 

        * alert, log, pass, activate, and dynamic are available by default in snort.
        * drop, reject and sdrop are available when snort is used in inline mode.

        """

        if len(self.rulesetIDS) == 0: #always create a default ruleset 1st
            self.rulesetIDS = {"1000001" : {"Action" : "pass",
                                        "Protocol" : "any",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "<>", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "any",
                                        "msg" : "Default traffic",
                                        "content" : "nothing",
                                        "rev" : 1,
                                        "priority" : 0
                                        },
                                "1000002" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "23",
                                        "msg" : "Port Scanning 1",
                                        "content" : "|00 00 00 01|",
                                        "rev" : 1,
                                        "priority" : 1
                                        },
                                "1000003" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "80",
                                        "msg" : "Port Scanning 2",
                                        "content" : "|00 00 00 10|",
                                        "rev" : 1,
                                        "priority" : 1
                                        },
                                "1000004" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "23",
                                        "msg" : "Brute force attack 1",
                                        "content" : "|11 11 11 11|",
                                        "rev" : 1,
                                        "priority" : 5
                                        },
                                "1000005" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "80",
                                        "msg" : "Brute force attack 2",
                                        "content" : "|22 22 22 22|",
                                        "rev" : 1,
                                        "priority" : 5
                                        },
                                "1000006" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "23",
                                        "msg" : "Malware infection",
                                        "content" : "|99 99 99 99|",
                                        "rev" : 1,
                                        "priority" : 10
                                        },
                                "1000007" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "80",
                                        "msg" : "Malware infection2",
                                        "content" : "|78 90 12 34|",
                                        "rev" : 1,
                                        "priority" : 10
                                        }
                                }

        logFilename = os.path.join(filepath, "IDS log.log")
        alertFilename = os.path.join(filepath, "IDS Alert.txt")
        triggerAlert = False
        
        for x in self.rulesetIDS:
            i = 0
            temp = []
            if self.rulesetIDS[x]["Protocol"] == trafficContent[0] or self.rulesetIDS[x]["Protocol"] == "any":
                i += 1
            if self.rulesetIDS[x]["SourceIP"] == trafficContent[1] or self.rulesetIDS[x]["SourceIP"] == "any":
                i += 1
            if self.rulesetIDS[x]["SourcePort"] == trafficContent[2] or self.rulesetIDS[x]["SourcePort"] == "any":
                i += 1
            if self.rulesetIDS[x]["FlowDirection"] == trafficContent[3]:
                i += 1
            
            if type(self.rulesetIDS[x]["DestinationIP"]) is list:
                if trafficContent[4] in self.rulesetIDS[x]["DestinationIP"] or self.rulesetIDS[x]["DestinationIP"] == "any":
                    i += 1
            else:
                if self.rulesetIDS[x]["DestinationIP"] == trafficContent[4] or self.rulesetIDS[x]["DestinationIP"] == "any":
                    i += 1

            if self.rulesetIDS[x]["DestinationPort"] == trafficContent[5] or self.rulesetIDS[x]["DestinationPort"] == "any":
                i += 1
            if self.rulesetIDS[x]["content"] == trafficContent[6] or self.rulesetIDS[x]["content"] == "any" or trafficContent[6] in self.rulesetIDS[x]["content"]:
                i += 1
            
            susIp = self.checkIPaddress(trafficContent[1])
            
            if i == 7:
                triggerAlert = True
                timeNow = datetime.datetime.now()
                temp.append(self.rulesetIDS[x]["msg"])
                temp.append(self.rulesetIDS[x]["rev"])
                temp.append(self.rulesetIDS[x]["priority"])

                if logType[0] == "all":
                    self.printLog(str(x), trafficContent, temp, timeNow, logFilename)

                if len(logType) > 1:
                    for z in logType:
                        if z == "alert":
                            if self.rulesetIDS[x]["Action"] == "alert":
                                self.printLog(str(x), trafficContent, temp, timeNow, alertFilename)
                        elif z == "pass":
                            pass
                        else:
                            pass
        return triggerAlert

    def checkIPaddress(self, ip1):
        """
        Verify suspicious IP address
        """
        susIP = False
        iotNet = IPv4Network("192.168.2.0/24")
        ipList = list(iotNet)

        if ip1 not in ipList:
            susIP = True
        return susIP

    def checkPatchNote(self, itemName, node, patchNote):
        """
        Check if software patch is available for IoT node
        """
        vulPatchAvailable = False
        vulDisableText = []

        for x in patchNote:
            if itemName == str(x[0]):
                vulPatchAvailable = True
                vulDisableText.append(x[1])
        return vulPatchAvailable, vulDisableText

    def patchVulnerability(self, mode, patchNote, victimName, victimPort, nodes):
        """
        Patch the vulnerability on nodes
        """
        if mode == 1 or mode == 2:
            for x in nodes:
                temp1 = x.name.split("-")

                vulP, vulT = self.checkPatchNote(temp1[0], x, patchNote)

                #remove vul if patch successful
                if vulP == True:
                    if mode == 2:
                        removeAllVuln(x)
                    else:
                        removeVul(x, vulT)
        elif mode == 3:
            deviceName = []
            tempName = victimName.split("_")
            deviceName = tempName[1].split("-")
            vulDisableText = []

            for x in patchNote:
                if deviceName[0] in x:
                    vulDisableText.append(x[1])

            for x in nodes:
                temp1 = x.name.split("_")
                temp2 = temp1[1].split("-")
                if temp2[0] == deviceName[0]:
                    if victimPort in x.realPort:
                        for y in x.realPort[victimPort]['Vuln']:
                            if y in vulDisableText:
                                self.cleanse(x, victimPort, y)
        return None

    def cleanse(self, node, port, vuln):
        """
        Reset node status
        """
        #deep clean infected node
        for y in node.realPort:
            if node.realPort[y]['open'] == False:
                #print("yes", node.name)
                node.realPort[y]['open'] = True
                for x in node.con:
                    text = x.name.split('-')
                    if 'ag_CNC' in text or 'CNC' in text:
                        disconnectTwoWays(node, x)
                        x.listofBots.remove(node)
                        node.CNCNode.clear()
                        #break
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

        #patch other nodes
        temp = node.vuls.copy()

        for x in temp:
            if x.name == str(vuln):
                node.vuls.remove(x)

        if vuln in node.realPort[port]["Vuln"]:
            node.realPort[port]["Vuln"].remove(vuln)

        return None

    def printLog(self, sid, content, content2, time, filename):
        """
        alert icmp any any -> any any (msg:"ICMP Packet"; sid:477; rev:3;)

        snort log sample:
        [**] [1:477:3] ICMP Packet [**]
        [Priority: 0]
        04/30-07:54:41.759229 172.25.212.245 -> 172.25.212.153
        ICMP TTL:64 TOS:0x0 ID:0 IpLen:20 DgmLen:96 DF
        Type:8  Code:0  ID:16348   Seq:0  ECHO

        alert tcp any any -> any any (msg:"Exploit detected"; sid:1000001; content:"exploit";)

        Snort log sample:

        [**] [1:1000001:0] Exploit detected [**]
        [Priority: 0]
        04/30-07:54:38.312536 172.25.212.204:80 -> 192.168.255.110:46127
        TCP TTL:64 TOS:0x0 ID:19844 IpLen:20 DgmLen:505 DF
        ***AP*** Seq: 0xF936BE12  Ack: 0x2C9A47D8  Win: 0x7B  TcpLen: 20
        """
        
        msg = content2[0]
        rev = content2[1]
        priority = content2[2]

        protocol = content[0]
        srcIP = content[1]
        srcPort = content[2]
        direction = content[3]
        destIP = content[4]
        destPort = content[5]
        ttl = content[7] #time to live
        tos = None #type of service
        id = 1
        iplen = 0 #IpLen (20 in most cases where no IP options are specifed) is the IP header length. is a 4-bit value and is in increments of 4 bytes (ie, max header length = 15*4 = 60
        dgmlen = 0 #total datagram (packet) length. is a 16bit field in bytes


        createRecord("[**] [{0}:{1}:{2}] {3} [**]".format(str("1"), str(sid), str(rev), msg), filename)
        createRecord("[Priority: {0}]".format(str(priority)), filename)
        #createRecord("{0}-{1} {2}:{3} {4} {5}:{6}".format(str(date), str(time), str(srcIP), str(srcPort) direction, str(destIP), str(destPort)), filename)
        createRecord("{0} {1}:{2} {3} {4}:{5}".format(str(time), str(srcIP), str(srcPort), direction, str(destIP), str(destPort)), filename)
        #createRecord("{0} TIL:{1} TOS:{2} ID:{3} IpLen:{4} DgmLen:{5} DF".format(str(protocol), str(ttl), str(tos), str(id), str(iplen), str(dgmlen)), filename)
        createRecord("[Content: {0}]\n".format(str(content[6])), filename)

        return None

    def intrusionPreventionSystem(self, trafficContent, filepath):
        """
        Intrusion Prevention System (IPS) - Model based on SNORT IPS
        Description: A device or software app that monitors network traffic for malicious activity. By using a defined ruleset, it able to perform attack classification and invokes against matched rules.
        https://content.cisco.com/chapter.sjs?uri=/searchable/chapter/content/en/us/td/docs/ios-xml/ios/sec_data_utd/configuration/xe-16/sec-data-utd-xe-16-6-book/snort-ips.html.xml#concept_E2097F706DE64679A2229E807BDC95B1
        """
        found = False
        additionalMsg = None

        if len(self.rulesetIPS) == 0: #always create a default ruleset 1st
            self.rulesetIPS = {"1100001" : {"Action" : "pass",
                                        "Protocol" : "any",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "<>", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "any",
                                        "msg" : "Default traffic",
                                        "content" : "nothing",
                                        "rev" : 1,
                                        "priority" : 0
                                        },
                                        '''
                                "1100002" : {"Action" : "reject",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p1",
                                        "msg" : "Port Scanning 1",
                                        "content" : "|00 00 00 01|",
                                        "rev" : 1,
                                        "priority" : 1
                                        },
                                        
                                "1100003" : {"Action" : "alert",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p2",
                                        "msg" : "Port Scanning 2",
                                        "content" : "|00 00 00 10|",
                                        "rev" : 1,
                                        "priority" : 1
                                        },
                                        
                                "1100004" : {"Action" : "drop",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p1",
                                        "msg" : "Brute force attack 1",
                                        "content" : "|11 11 11 11|",
                                        "rev" : 1,
                                        "priority" : 5
                                        },
                                        
                                "1100005" : {"Action" : "drop",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p2",
                                        "msg" : "Brute force attack 2",
                                        "content" : "|22 22 22 22|",
                                        "rev" : 1,
                                        "priority" : 5
                                        },
                                        
                                "1100006" : {"Action" : "drop",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p1",
                                        "msg" : "Malware infection",
                                        "content" : "|99 99 99 99|",
                                        "rev" : 1,
                                        "priority" : 10
                                        },
                                        '''
                                "1100007" : {"Action" : "drop",
                                        "Protocol" : "TCP",
                                        "SourceIP" : "any",
                                        "SourcePort" : "any",
                                        "FlowDirection" : "->", #<> or ->
                                        "DestinationIP" : "any",
                                        "DestinationPort" : "p1",
                                        "msg" : "Malware infection2",
                                        "content" : "any",
                                        "rev" : 1,
                                        "priority" : 10
                                        }
                                }

        dropFilename = os.path.join(filepath, "IPS Drop.txt")
        alertFilename = os.path.join(filepath, "IPS Alert.txt")
        rejectFilename = os.path.join(filepath, "IPS Reject.txt")
        
        for x in self.rulesetIPS:
            i = 0
            temp = []
            if self.rulesetIPS[x]["Protocol"] == trafficContent[0] or self.rulesetIPS[x]["Protocol"] == "any":
                i += 1
            if self.rulesetIPS[x]["SourceIP"] == trafficContent[1] or self.rulesetIPS[x]["SourceIP"] == "any":
                i += 1
            if self.rulesetIPS[x]["SourcePort"] == trafficContent[2] or self.rulesetIPS[x]["SourcePort"] == "any":
                i += 1
            if self.rulesetIPS[x]["FlowDirection"] == trafficContent[3]:
                i += 1
            if self.rulesetIPS[x]["DestinationIP"] == trafficContent[4] or self.rulesetIPS[x]["DestinationIP"] == "any":
                i += 1
            if self.rulesetIPS[x]["DestinationPort"] == trafficContent[5] or self.rulesetIPS[x]["DestinationPort"] == "any":
                i += 1
            if self.rulesetIPS[x]["content"] == trafficContent[6] or self.rulesetIPS[x]["content"] == "any":
                i += 1
            if i == 7:
                timeNow = datetime.datetime.now()
                temp.append(self.rulesetIPS[x]["msg"])
                temp.append(self.rulesetIPS[x]["rev"])
                temp.append(self.rulesetIPS[x]["priority"])

                if self.rulesetIPS[x]["Action"] == "alert":
                    self.printLog(str(x), trafficContent, temp, timeNow, alertFilename)
                    found = False
                elif self.rulesetIPS[x]["Action"] == "drop":
                    self.printLog(str(x), trafficContent, temp, timeNow, dropFilename)
                    found = True
                elif self.rulesetIPS[x]["Action"] == "reject":
                    self.printLog(str(x), trafficContent, temp, timeNow, rejectFilename)
                    found = True
                    if self.rulesetIPS[x]["protocol"] == "TCP":
                        additionalMsg = "TCP RST"
                    elif self.rulesetIPS[x]["protocol"] == "UDP":
                        additionalMsg = "ICMP port unreachable"
                elif self.rulesetIPS[x]["Action"] == "sdrop":
                    found = True
                elif self.rulesetIPS[x]["Action"] == "pass":
                    found = False

        return found, additionalMsg

    def firewall(self, routerNode, trafficContent): 
        """
        Packet Filtering Firewall (1st gen FW) - Transport layer and network layer
        Use ruleset to monitor and control incoming and outgoing network
        Firewall is placed in initial connection and CNC connections
        """

        tgtBlocked = False
        if len(self.rulesetFW) == 0: #always create a default ruleset 1st
            self.rulesetFW = {"default" : {"action": "allow", 
                                        "Protocol" : "any",
                                        "SourceIP" : "any", 
                                        "SourcePort" : "any", 
                                        "DestinationIP" : "any", 
                                        "DestinationPort" : "any", 
                                        "msg" : "all allow"}
            }

        ###### need to add transport protocol
        if routerNode is not None:
            text = routerNode.name.split('ag_')
        
            for x in self.rulesetFW:
                i = 0
                if text[-1] in self.rulesetFW[x]["where"] or 'all' in self.rulesetFW[x]["where"]:
                    if self.rulesetFW[x]["Protocol"] == trafficContent[0] or self.rulesetFW[x]["Protocol"] == "any":
                        i += 1
                    if self.rulesetFW[x]["SourceIP"] == trafficContent[1] or self.rulesetFW[x]["SourceIP"] == "any":
                        i += 1
                    if self.rulesetFW[x]["SourcePort"] == trafficContent[2] or self.rulesetFW[x]["SourcePort"] == "any":
                        i += 1
                    if self.rulesetFW[x]["DestinationIP"] == trafficContent[3] or self.rulesetFW[x]["DestinationIP"] == "any":
                        i += 1
                    if self.rulesetFW[x]["DestinationPort"] == trafficContent[4] or self.rulesetFW[x]["DestinationPort"] == "any":
                        i += 1

                    if i == 5:
                        if self.rulesetFW[x]["Action"] == "block":
                            tgtBlocked = True
                        elif self.rulesetFW[x]["Action"] == "allow":
                            tgtBlocked = False
                        else:
                            print("Firewall error!!")

        return tgtBlocked

    def createNewRuleset(self, defMethod, newRuleName, newRuleset):
        """
        ruleset = {"default" : {"Action" : "allow", 
                                "Protocol" : "any",
                                "SourceIP" : "any", 
                                "SourcePort" : "any", 
                                "DestinationIP" : "any", 
                                "DestinationPort" : "any", 
                                "msg" : "anyone can access this network"}
        }
        """
        defMethod = defMethod.lower()
        if defMethod == "firewall":
            if newRuleName is not None:
                if newRuleName in self.rulesetFW:
                    pass
                else:
                    self.rulesetFW[newRuleName] = newRuleset
            elif len(self.rulesetFW) == 0: #always create a default ruleset 1st
                self.rulesetFW = {"default" : {"Action": "allow", 
                                                "Protocol" : "any",
                                                "SourceIP" : "any", 
                                                "SourcePort" : "any", 
                                                "DestinationIP" : "any", 
                                                "DestinationPort" : "any", 
                                                "msg" : "anyone can access this network",
                                                "where" : ['all']}
                }
        elif defMethod == "ids":
            
            if newRuleName is not None:
                if newRuleName in self.rulesetIDS:
                    pass
                else:
                    self.rulesetIDS[newRuleName] = newRuleset

            elif len(self.rulesetIDS) == 0: #always create a default ruleset 1st
                self.rulesetIDS = {"1000001" : {"Action" : "log",
                                            "Protocol" : "any",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "<>", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "any",
                                            "msg" : "Default traffic",
                                            "content" : "nothing",
                                            "rev" : 1,
                                            "priority" : 0
                                            },
                                    "1000002" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "23",
                                            "msg" : "Port Scanning",
                                            "content" : "|00 00 00 01|",
                                            "rev" : 1,
                                            "priority" : 1
                                            },
                                    "1000003" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "80",
                                            "msg" : "Port Scanning",
                                            "content" : "|00 00 00 10|",
                                            "rev" : 1,
                                            "priority" : 1
                                            },
                                    "1000004" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "23",
                                            "msg" : "Brute force attack",
                                            "content" : "|11 11 11 11|",
                                            "rev" : 1,
                                            "priority" : 5
                                            },
                                    "1000005" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "80",
                                            "msg" : "Brute force attack",
                                            "content" : "|23 23 23 23|",
                                            "rev" : 1,
                                            "priority" : 5
                                            },
                                    "1000006" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "23",
                                            "msg" : "Malware infection",
                                            "content" : "|99 99 99 99|",
                                            "rev" : 1,
                                            "priority" : 10
                                            },
                                    "1000007" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "80",
                                            "msg" : "Malware infection2",
                                            "content" : "|78 90 12 34|",
                                            "rev" : 1,
                                            "priority" : 10
                                            }
                                    }
            else:
                print("No ruleset found.")
                                
        elif defMethod == "ips":
            if newRuleName is not None:
                if newRuleName in self.rulesetIPS:
                    pass
                else:
                    self.rulesetIPS[newRuleName] = newRuleset
            elif len(self.rulesetIPS) == 0: #always create a default ruleset 1st
                self.rulesetIPS = {"1100001" : {"Action" : "pass",
                                            "Protocol" : "any",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "<>", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "any",
                                            "msg" : "Default traffic",
                                            "content" : "nothing",
                                            "rev" : 1,
                                            "priority" : 0
                                            },
                                    "1100002" : {"Action" : "reject",
                                           "Protocol" : "TCP",
                                           "SourceIP" : "any",
                                           "SourcePort" : "any",
                                           "FlowDirection" : "->", #<> or ->
                                           "DestinationIP" : "any",
                                           "DestinationPort" : "p1",
                                           "msg" : "Port Scanning 1",
                                           "content" : "|00 00 00 01|",
                                           "rev" : 1,
                                           "priority" : 1
                                           },
                                    "1100003" : {"Action" : "alert",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "p2",
                                            "msg" : "Port Scanning 2",
                                            "content" : "|00 00 00 10|",
                                            "rev" : 1,
                                            "priority" : 1
                                            },
                                            
                                    "1100004" : {"Action" : "drop",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "p1",
                                            "msg" : "Brute force attack 1",
                                            "content" : "|11 11 11 11|",
                                            "rev" : 1,
                                            "priority" : 5
                                            },
                                            
                                    "1100005" : {"Action" : "drop",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "p2",
                                            "msg" : "Brute force attack 2",
                                            "content" : "|22 22 22 22|",
                                            "rev" : 1,
                                            "priority" : 5
                                            },
                                            
                                    "1100006" : {"Action" : "drop",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "p1",
                                            "msg" : "Malware infection",
                                            "content" : "|99 99 99 99|",
                                            "rev" : 1,
                                            "priority" : 10
                                            },
                                            
                                    "1100007" : {"Action" : "drop",
                                            "Protocol" : "TCP",
                                            "SourceIP" : "any",
                                            "SourcePort" : "any",
                                            "FlowDirection" : "->", #<> or ->
                                            "DestinationIP" : "any",
                                            "DestinationPort" : "p2",
                                            "msg" : "Malware infection2",
                                            "content" : "|88 88 88 88|",
                                            "rev" : 1,
                                            "priority" : 10
                                            }
                                    }
            else:
                print("Mp ruleset found.")
            
        else:
            print("Unknown defence method.")

        return None

    def removeRuleset(self, defMethod, ruleName):
        """
        Remove rule in ruleset
        """
        defMethod = defMethod.lower()
        if defMethod == "firewall":
            if len(self.rulesetFW) > 0:
                self.rulesetFW.pop(ruleName)
            else:
                print("No firewall ruleset found.")
        elif defMethod == "ids":
            if len(self.rulesetIDS) > 0:
                self.rulesetIDS.pop(ruleName)
            else:
                print("No IDS ruleset found.")
        elif defMethod == "ips":
            if len(self.rulesetIPS) > 0:
                self.rulesetIPS.pop(ruleName)
            else:
                print("No IPS ruleset found.")
        else:
            print("Cannot remove no defence method.")

        return None

    def movingTargetDefence(self, net, mode, times):
        """
        Moving target defence method: Shuffle, Diversity, and Redundancy

        Shuffle: Can change network connection or IP address randomly with fixed/adaptive time interval.
        Diversity: Can provides different combinations in hardware and software settings.
        Redundancy: Create duplicates of network componenets with the exact function.
        """
        probability = 0.7

        if mode == "topology shuffling":
            net = self.randomShufflingNew(net, probability, times)
        elif mode == "IP shuffling":
            #pending for development
            pass
        else:
            pass

        return net

    def randomShufflingNew(self, net, probability, times):
        """
        Modified from Mengmeng Ge's code in RandomShufflingOptimization.py in order to fit with my new attack model based on Mirai botnet.
        Date added: 4 March 2021
        """
        shuffledNet = copyNet(net)

        ## need to add some code here/add new function to do shuffling in the middle of an attack

        temp = self.calculateNumbersofConnection(shuffledNet)

        for i in range(times):
            for node1 in shuffledNet.nodes:
                if node1.type == True: #True means its a real node; False means its a decoy node
                    randNum = uniform(0, 1)
                    temp1 = None
                    temp2 = None

                    if randNum > probability:
                        if len(node1.con) > 0:
                            temp1 = choice(node1.con) # neighbor node
                            stop = False

                            while stop == False:
                                temp2 = choice(shuffledNet.nodes) # randomly pick 1 node for shuffle
                                text = temp2.name.split('-')
                                if temp2 == node1 or 'attacker' in text or 'ag_attacker' in text or 'CNC' in text or 'ag_CNC' in text or temp2 == temp1:
                                    pass
                                else:
                                    stop = True

                            if stop == True: #shuffling
                                disconnectTwoWays(node1, temp1)
                                connectTwoWays(node1, temp2)
                
        temp0 = self.calculateNumbersofConnection(shuffledNet)

        return shuffledNet

    def calculateNumbersofConnection(self, net):
        """
        Calculate numbers of edges of a network
        """
        #num = 0
        num2 = 0

        for node in net.nodes:
            text = node.name.split('-')
            #if 'attacker' in text or 'ag_attacker' in text or 'CNC' in text or 'ag_CNC' in text:
            if node.canBeCompromised == False:
                pass
            else:
                num2 += len(node.con)
                #for x in node.con:
                #    num += 1

        print(num2)

        return num2

    def cyberDeceptionSetup(self, net, mode, model):
        """
        Cyber Deception: Add decoy node to deceive attacker, observe attacker's behaviour and activity, and collect attacker's data
        """
        if mode == "add decoy":
            decoyNameList, decoyNodeList, newNet  = self.addDecoyNode(net, model, False)
        elif mode == "convert into decoy":
            decoyNameList, decoyNodeList, newNet = self.convertNodeToDecoyNode(net, model)
        else:
            print("")

        return decoyNameList, decoyNodeList, newNet

    def addDecoyNode(self, net, model, mode):
        """
        Add additional decoy node to the network
        """
        tempList = []
        decoyNodeList = []
        decoyNameList = []
        total = model["smart"] + model["dummy"]
        modelList = []

        for i in range(model["smart"]):
            modelList.append("smart")
        for i in range(model["dummy"]):
            modelList.append("dummy")

        tempTotal = int(total)
        while (tempTotal > 0):
            x = choice(net.nodes)
            if x in tempList:
                pass
            elif x.canBeCompromised == False:
                pass
            else:
                tempList.append(x)
                tempTotal -= 1

        for i in range(total):
            dnode = decoyNode("decoy+"+tempList[i].name)
            dnode.type = False #"emulated" 
            dnode.model = choice(modelList)
            if mode == True:
                dnode.position = tuple(list(tempList[i].position))
            else:
                temp = list(tempList[i].position)
                dnode.position = tuple(temp[0]+50, temp[1]+50)
            
            decoyNameList.append(tempList[i].name)
            decoyNodeList.append(dnode)
            modelList.remove(dnode.model)
            #print(dnode.name, dnode.model)
            
        for i in range(0, len(decoyNameList)):
            net.nodes.append(decoyNodeList[i])
            for node in net.nodes:
                if node.name == decoyNameList[i]:
                    for x in node.con:
                        connectOneWay(x, decoyNodeList[i]) # connect one way only
                    break

        return decoyNameList, decoyNodeList, None

    def convertNodeToDecoyNode(self, net, model):
        """
        Convert existing node to decoy node 
        """
        decoyNameList, decoyNodeList, temp = self.addDecoyNode(net, model, True)

        tempNet = copyNet(net)
        tempList = []
        for x in decoyNameList:
            for y in tempNet.nodes:
                if x == y.name:
                    tempList.append(y)

        for i in range(0, len(tempList)):
            tempNet.nodes.remove(tempList[i]) if tempList[i] in tempNet.nodes else print("Its not here!")
            tempCon = tempList[i].con.copy()
            for x in tempCon:
                disconnectTwoWays(x, tempList[i])
            
        return decoyNameList, decoyNodeList, tempNet

    def decoyReports(self, content, content2, filepath):
        """
        Generate report for decoy node
        """
        filename = os.path.join(filepath, "Decoy Report.log")

        timeNow = datetime.datetime.now()
        action = content2[0]

        protocol = content[0]
        srcIP = content[1]
        srcPort = content[2]
        nodeID = content[3]
        malwareSig = content[4]
        exploit = content[5]
        vulnerability = content[6]
        details = content[7]
        cnc = content[8]

        createRecord("[**] [{0}] [**]".format(str(action)), filename)
        createRecord("[Protocol: {0}]".format(str(protocol)), filename)
        createRecord("[Time: {0}]".format(str(timeNow)), filename)
        createRecord("[Source IP: {0}:{1}]".format(str(srcIP), str(srcPort)), filename)
        createRecord("[Compromised by: Node: {0}; From: {1}]".format(str(nodeID), str(malwareSig)), filename)
        createRecord("[Exploit Code: {0}]".format(str(exploit)), filename)
        createRecord("[Vulnerability: {0}]".format(str(vulnerability)), filename)
        createRecord("[CNC: {0}; IP: {1}]".format(str(cnc), str(cnc.IPv4Add)), filename)
        createRecord("[Content: {0}]\n".format(str(details)), filename)

        return None