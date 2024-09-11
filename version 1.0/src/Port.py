'''
This module assigns specific port number to a node.

@author: Kok Onn Chee
'''

def assignPortNumberAndInfo(numbers, targetDict):
    """
    Assign information to port
    """
    fullPortDict = {
            'p1' : {
                'name' : "Port 1",
                'open' : True,
                'vulnerability' : ["v1"]
            },

            'p2' : {
                'name' : "Port 2",
                'open' : True,
                'vulnerability' : ["v2"]
            },

            'p3' : {
                'name' : "Port 3",
                'open' : True,
                'vulnerability' : ["v3"]
            },

            '23' : {
                'name' : "Telnet protocol - unencrypted text communications",
                'open' : True,
                'vulnerability' : ["default credential", "CVE111-11-111"]
            },
            '80' : {
                'name' : "Hypertext Transfer Protocol (HTTP)",
                'open' : True,
                'vulnerability' : ["default credential", "CVE111-11-111"]
            },
            '8008' : {
                'name' : "Hypertext Transfer Protocol (HTTP) - Alt 1",
                'open' : True,
                'vulnerability' : ["default credential", "CVE111-11-111"]
            },
            '8080' : {
                'name' : "Hypertext Transfer Protocol (HTTP) - Alt 2",
                'open' : True,
                'vulnerability' : ["default credential", "CVE111-11-111"]
            }
        }
    if targetDict is None:
        targetDict = {}

    for x in numbers:
        if x in fullPortDict:
            targetDict[x] = fullPortDict[x]
        else:
            targetDict[x] = dict(name = "Port "+str(x), open = True)
    return targetDict