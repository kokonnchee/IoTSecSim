
'''
This module contains wordlist for credential exploitation. 

@author: Kok Onn Chee
'''

from random import random, choice
import os, glob

class wordlistGen(object):
    def __init__(self):

        self.mirai62CredentialList = [["root", "xc3511", 10], 
                                ["root", "vizxv", 9], 
                                ["root", "admin", 8], 
                                ["admin", "admin", 7], 
                                ["root", "888888", 6], 
                                ["root", "xmhdipc", 5], 
                                ["root", "default", 5], 
                                ["root", "juantech", 5], 
                                ["root", "123456", 5], 
                                ["root", "54321", 5], 
                                ["support", "support", 5], 
                                ["root", None, 4], 
                                ["admin", "password", 4], 
                                ["root", "root", 4], 
                                ["root", "12345", 4], 
                                ["user", "user", 3], 
                                ["admin", None, 3], 
                                ["root", "pass", 3], 
                                ["admin", "admin1234", 3], 
                                ["root", "1111", 3], 
                                ["admin", "smcadmin", 3], 
                                ["admin", "1111", 2], 
                                ["root", "666666", 2], 
                                ["root", "password", 2], 
                                ["root", "1234", 2], 
                                ["root", "klv123", 1], 
                                ["Administrator", "admin", 1], 
                                ["service", "service", 1], 
                                ["supervisor", "supervisor", 1], 
                                ["guest", "guest", 1], 
                                ["guest", "12345", 1], 
                                ["guest", "12345", 1], 
                                ["admin1", "password", 1], 
                                ["administrator", "1234", 1], 
                                ["666666", "666666", 1], 
                                ["888888", "888888", 1], 
                                ["ubnt", "ubnt", 1], 
                                ["root", "klv1234", 1], 
                                ["root", "Zte521", 1], 
                                ["root", "hi3518", 1], 
                                ["root", "jvbzd", 1], 
                                ["root", "anko", 4], 
                                ["root", "zlxx", 1], 
                                ["root", "7ujMko0vizxv", 1], 
                                ["root", "7ujMko0admin", 1], 
                                ["root", "system", 1], 
                                ["root", "ikwb", 1], 
                                ["root", "dreambox", 1], 
                                ["root", "user", 1], 
                                ["root", "realtek", 1], 
                                ["root", "00000000", 1], 
                                ["admin", "1111111", 1], 
                                ["admin", "1234", 1], 
                                ["admin", "12345", 1], 
                                ["admin", "54321", 1], 
                                ["admin", '123456', 1], 
                                ["admin", "7ujMko0admin", 1], 
                                ["admin", "4321", 1], 
                                ["admin", "pass", 1], 
                                ["admin", "meinsm", 1], 
                                ["tech", "tech", 1], 
                                ["mother", "fucker", 1]]

        self.simplifiedMiraiList = []

        self.carnaCredentialList = [["root", "root"], ["admin", "admin"], ["root", None], ["admin", None]]

        self.commonList = []

        self.strongList = [["admin", "+-XEpeMw1M%$CB%"], ["admin", "{xzhGNCqb$=(BS7"], ["admin", "~XFIL=%vQK^apX^"], ["admin", "0v_mzLML&VPcE&U"], ["admin", ".XMZ;.&aRj~L.%p"], ["admin", "@g9ufGO;a@=EWH="], ["admin", "7HKzsoS5&LvA}cp"], ["admin", "jBo)@11GHt_gZjZ"], ["admin", "n^Ce_@$)l03dIke"], ["admin", "UXjOdZ;pyh;a3tc"]]

        self.vulnList = []

        self.emptyList = []

    def attackerWordList(self, num, wordListName):
        '''
        This wordlist contains the 62 pairs of usernames and passwords employed by Mirai malware.
        '''
        selectedCredentialPairList = []
        fromList = []
        if wordListName.lower() == "mirai":
            if len(self.simplifiedMiraiList) == 0:
                self.getCredential(None, wordListName)
            fromList = self.simplifiedMiraiList.copy()
        elif wordListName.lower() == "carna":
            fromList = self.carnaCredentialList.copy()
        elif wordListName.lower() == "strong":
            if len(self.strongList) == 0:
                self.getCredential("strong password.txt", wordListName)
            fromList = self.strongList.copy()
        elif wordListName.lower() == "others":
            fromList = self.emptyList.copy()
        else:
            print("Wordlist not found!")

        #real wordlist from Mirai source code - 62 credential pairs [username, password, weight]
        num = int(num)

        if num < len(fromList) and num > 0:
            while (num > 0):
                x = choice(fromList)
                if x in selectedCredentialPairList:
                    pass
                else:
                    selectedCredentialPairList.append(x)
                    num -=1
        elif num == -1 or num > len(fromList):
            selectedCredentialPairList = fromList.copy()
        else:
            print("No need wordlist!!")
        
        return selectedCredentialPairList


    def setupCredentialForDevice(self, wordListName):
        '''
        Randomly setup a credential pair for an IoT device.
        '''
        
        x = []
        if wordListName.lower() == "mirai":
            if len(self.simplifiedMiraiList) == 0:
                self.getCredential(None, wordListName)
            x = choice(self.simplifiedMiraiList)
        elif wordListName.lower() == "carna":
            x = choice(self.carnaCredentialList)
        elif wordListName.lower() == "strong":
            if len(self.strongList) == 0:
                self.getCredential("strong password.txt", wordListName)
            x = choice(self.strongList)
        else:
            print("Wordlist not found!")

        return x[0], x[1]

    def getCredential(self, filename, wordListName):

        currentDir = os.getcwd()
        saveFolder = os.path.join(currentDir, "wordlist")

        proceed = True
        proceed2 = True
        wordListName = wordListName.lower()

        if wordListName == "common":
            proceed2 = False
            if len(self.commonList) > 0:
                proceed = False
        elif wordListName == "strong":
            proceed2 = False
            if len(self.strongList) > 0:
                proceed = False
        elif wordListName == "mirai":
            proceed = False
            if len(self.simplifiedMiraiList) > 0:
                proceed2 = False
        else:
            print("file name error")
            proceed = False

        if proceed == True:
            files1 = glob.iglob(os.path.join(saveFolder, filename))
            lines = []

            if files1 != None:
                for x in files1:
                    file1 = open(x, 'r')
                    lines = file1.readlines()
            if wordListName == "common":
                for x in lines:
                    text = str(x.strip())
                    text1 = text.split(':')
                    temp = []
                    if text1[0] == "":
                        temp.append(None)
                    else:
                        temp.append(str(text1[0]))

                    if text1[1] == "":
                        temp.append(None)
                    else:
                        temp.append(str(text1[1]))
                    self.commonList.append(temp)
            elif wordListName == "strong":
                for x in lines:
                    temp = []
                    temp.append("admin")
                    temp.append(str(x.strip()))
                    self.strongList.append(temp)
            else:
                print("get credential error")
        
        if proceed2 == True:
            for x in self.mirai62CredentialList:
                temp = []
                temp.append(x[0])
                temp.append(x[1])
                self.simplifiedMiraiList.append(temp)

        return None

    def getWordListLen(self, wordListName):

        num = 0

        if wordListName.lower() == "mirai":
            num = len(self.mirai62CredentialList)
        elif wordListName.lower() == "carna":
            num = len(self.carnaCredentialList)
        elif wordListName.lower() == "strong":
            if len(self.strongList) == 0:
                self.getCredential("strong password.txt", wordListName)
            num = len(self.strongList)
        elif wordListName.lower() == "others":
            num = len(self.emptyList)
        else:
            print("Wordlist not found!")

        return num

    def compareWordList(self, wl1, wl2):

        if wl1.lower() == "mirai":
            if len(self.simplifiedMiraiList) == 0:
                self.getCredential(None, wl1)
            tempwl1 = self.simplifiedMiraiList
        elif wl1.lower() == "carna":
            tempwl1 = self.carnaCredentialList
        elif wl1.lower() == "strong":
            if len(self.strongList) == 0:
                self.getCredential("strong password.txt", wl1)
            tempwl1 = self.strongList
        elif wl1.lower() == "others":
            tempwl1 = self.emptyList
        else:
            print("Wordlist not found!")

        if wl2.lower() == "mirai":
            if len(self.simplifiedMiraiList) == 0:
                self.getCredential(None, wl2)
            tempwl2 = self.simplifiedMiraiList
        elif wl2.lower() == "carna":
            tempwl2 = self.carnaCredentialList
        elif wl2.lower() == "strong":
            if len(self.strongList) == 0:
                self.getCredential("strong password.txt", wl2)
            tempwl2 = self.strongList
        elif wl2.lower() == "others":
            tempwl2 = self.emptyList
        else:
            print("Wordlist not found!")

        num = 0
        for x in tempwl1:
            for y in tempwl2:
                if x == y:
                    num += 1

        return None
