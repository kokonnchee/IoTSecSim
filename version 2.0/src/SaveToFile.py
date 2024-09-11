'''
This module contains functions to open/load data from files and create/save data into files.

@author: Kok Onn Chee
'''

import os
import csv

def saveToFile(file_name, open_mode, metrics):
    """
    Save data to file
    """
    srcDir = os.getcwd()
    filename = os.path.join(srcDir, "{}.txt".format(file_name))
    file = open(filename, open_mode)
    file.writelines(" ".join(metrics))
    file.writelines('\n')
    file.close()
    return None

def openFile(file_name, open_mode):
    """
    Open a file
    """
    filename = "{}.txt".format(file_name)
    file = open(filename, open_mode)
    return file

def writeFile(file, content):
    """
    Write data to file
    """
    file.writelines(" ".join(content))
    file.writelines('\n')
    return None

def createRecord(data, filename):
    """
    Create record
    """
    if os.path.isfile(filename):
        file = open(filename, 'a+')
        file.writelines("".join(str(data)))
        file.writelines('\n')
        file.close()
    else:
        file = open(filename, 'w+')
        file.writelines("".join(str(data)))
        file.writelines('\n')
        file.close()
    return None

def createCSVFile(data, fieldName, filename):
    """
    Create CSV file to store phase time data
    """
    if os.path.isfile(filename):
        file = open(filename, 'a+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writerow({'Node': data[0], 'scanTime': data[1], 'accessTime': data[2], 'reportTime': data[3], 'infectionTime': data[4]})
        file.close()
    else:
        file = open(filename, 'w+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writeheader()
        writer.writerow({'Node': data[0], 'scanTime': data[1], 'accessTime': data[2], 'reportTime': data[3], 'infectionTime': data[4]})
        file.close()
    return None

def createSecurityMetricsCSVFile(data, filepath):
    """
    Create CSV file to store important data
    """
    filename = os.path.join(filepath, "Security Metrics.csv")
    fieldName = ['Number', 'Attacking Node', 'Target Node', 'Start Time', 'End Time', 'Duration', 'Comp By', 'Compromise Rate', 'Attack Success Probability', 'Attack Impact', 'Attack Risk', 'Time to Compromise One Node', 'Accumulated Time to Compromise All Nodes', 'Node Connection', 'NodeCS', 'NetCS']
    if os.path.isfile(filename):
        file = open(filename, 'a+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writerow({'Number': data[0],'Attacking Node': data[1], 'Target Node': data[2], 'Start Time': data[3], 'End Time': data[4], 'Duration': data[5], 'Comp By': data[6], 'Compromise Rate': data[7], 'Attack Success Probability': data[8], 'Attack Impact': data[9], 'Attack Risk': data[10], 'Time to Compromise One Node': data[11], 'Accumulated Time to Compromise All Nodes': data[12], 'Node Connection': data[13], 'NodeCS': data[14], 'NetCS': data[15]})
        file.close()
    else:
        file = open(filename, 'w+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writeheader()
        writer.writerow({'Number': data[0],'Attacking Node': data[1], 'Target Node': data[2], 'Start Time': data[3], 'End Time': data[4], 'Duration': data[5], 'Comp By': data[6], 'Compromise Rate': data[7], 'Attack Success Probability': data[8], 'Attack Impact': data[9], 'Attack Risk': data[10], 'Time to Compromise One Node': data[11], 'Accumulated Time to Compromise All Nodes': data[12], 'Node Connection': data[13], 'NodeCS': data[14], 'NetCS': data[15]})
        file.close()
    return None

def createGeneralCSVFile(data, filename):
    """
    Create general CSV file
    """
    if os.path.isfile(filename):
        file = open(filename, 'a+', newline='')
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(data)
        file.close()
    else:
        file = open(filename, 'w+', newline='')
        writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(data)
        file.close()
    return None

def createInOutTrafficCSVFile(num, data, filepath):
    """
    Create in out traffic CSV file
    """
    filename = os.path.join(filepath, "In Out Traffic Timeline.csv")

    fieldName = ['Number', 'Traffic Direction', 'Attacking Node', 'Target Node', 'Start Time', 'CompBy']# 'Duration', 'End Time']
    if os.path.isfile(filename):
        file = open(filename, 'a+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writerow({'Number': num, 'Traffic Direction': data[0], 'Attacking Node': data[1], 'Target Node': data[2], 'Start Time': data[3], 'CompBy': data[4]}) #, 'End Time': data[5]
        file.close()
    else:
        file = open(filename, 'w+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writeheader()
        writer.writerow({'Number': num, 'Traffic Direction': data[0], 'Attacking Node': data[1], 'Target Node': data[2], 'Start Time': data[3], 'CompBy': data[4]})#, 'End Time': data[5]})
        file.close()
    return None

def createInOutTrafficCSVFileSimple(num, data, filepath):
    """
    Create in out traffic simplified CSV file
    """
    filename = os.path.join(filepath, "In Out Traffic Timeline Simplified.csv")

    fieldName = ['Number', 'Traffic Direction', 'Start Time', 'CompBy']# 'End Time', 'Duration']
    if os.path.isfile(filename):
        file = open(filename, 'a+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writerow({'Number': num, 'Traffic Direction': data[0], 'Start Time': data[1], 'CompBy': data[2]})
        file.close()
    else:
        file = open(filename, 'w+', newline='')
        writer = csv.DictWriter(file, fieldnames=fieldName)
        writer.writeheader()
        writer.writerow({'Number': num, 'Traffic Direction': data[0], 'Start Time': data[1], 'CompBy': data[2]})
        file.close()
    return None




