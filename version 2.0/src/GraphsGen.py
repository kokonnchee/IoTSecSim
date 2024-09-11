'''
This module creates graphs/charts/plots to visualise the results.

@author: Kok Onn Chee
'''

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import os
import imageio
import re
import networkx as nx
import PIL
from matplotlib.gridspec import GridSpec
from Node import *

def generateMixedGraphs(time, namelist, healthyNodeNum, infectedNodesNum, rate):
    """
    Create Mixed Graph
    """
    xLabelName = []

    if max(healthyNodeNum) < 10:
        ylim1 = round(max(healthyNodeNum)+5.1, -1)
        ylim2 = round(max(rate)*1.1, 1)

    else:
        ylim2 = round(max(rate)*1.3, 2)
        ylim1 = 70

    r = []
    for i in range(0, time):
        r.append(i)
        xLabelName.append(str(i+1))
    red1 = []
    red2 = []
    red3 = []
    red4 = []
    red5 = []
    tempName = []
    for n in namelist:
        text = n.split("_")
        tempName.append(text[1])
    
    namelist = tempName

    ##flatten the nested list
    for x in infectedNodesNum:
        if len(namelist) == 1:
            for y in x[0::2]:
                red1.append(y)
        elif len(namelist) == 2:
            for y in x[0::2]:
                red1.append(y)
            for y in x[1::2]:
                red2.append(y)
        elif len(namelist) == 3:
            for y in x[0::3]:
                red1.append(y)
            for y in x[1::3]:
                red2.append(y)
            for y in x[2::3]:
                red3.append(y)
        elif len(namelist) == 4:
            for y in x[0::4]:
                red1.append(y)
            for y in x[1::4]:
                red2.append(y)
            for y in x[2::4]:
                red3.append(y)
            for y in x[3::4]:
                red4.append(y)
        elif len(namelist) == 5:
            for y in x[0::5]:
                red1.append(y)
            for y in x[1::5]:
                red2.append(y)
            for y in x[2::5]:
                red3.append(y)
            for y in x[3::5]:
                red4.append(y)
            for y in x[4::5]:
                red5.append(y)

    fig, ax = plt.subplots()

    barWidth = 1.0
    # Create green Bars
    ax.bar(r, healthyNodeNum, color='lightgreen', edgecolor='white', width=barWidth, label="Healthy Nodes")
    # Create orange Bars
    if len(namelist) == 1:
        ax.bar(r, red1, bottom=healthyNodeNum, color='orangered', edgecolor='white', width=barWidth, label=namelist[0])
    elif len(namelist) == 2:
        ax.bar(r, red1, bottom=healthyNodeNum, color='orangered', edgecolor='white', width=barWidth, label=namelist[0])
        ax.bar(r, red2, bottom=[i+j for i,j in zip(healthyNodeNum, red1)], color='lightsalmon', edgecolor='white', width=barWidth, label=namelist[1])
    elif len(namelist) == 3:
        ax.bar(r, red1, bottom=healthyNodeNum, color='orangered', edgecolor='white', width=barWidth, label=namelist[0])
        ax.bar(r, red2, bottom=[i+j for i,j in zip(healthyNodeNum, red1)], color='lightsalmon', edgecolor='white', width=barWidth, label=namelist[1])
        ax.bar(r, red3, bottom=[i+j+k for i,j,k in zip(healthyNodeNum, red1, red2)], color='maroon', edgecolor='white', width=barWidth, label=namelist[2])
    elif len(namelist) == 4:
        ax.bar(r, red1, bottom=healthyNodeNum, color='orangered', edgecolor='white', width=barWidth, label=namelist[0])
        ax.bar(r, red2, bottom=[i+j for i,j in zip(healthyNodeNum, red1)], color='lightsalmon', edgecolor='white', width=barWidth, label=namelist[1])
        ax.bar(r, red3, bottom=[i+j+k for i,j,k in zip(healthyNodeNum, red1, red2)], color='maroon', edgecolor='white', width=barWidth, label=namelist[2])
        ax.bar(r, red4, bottom=[i+j+k+l for i,j,k,l in zip(healthyNodeNum, red1, red2, red3)], color='sandybrown', edgecolor='white', width=barWidth, label=namelist[3])
    elif len(namelist) == 5:
        ax.bar(r, red1, bottom=healthyNodeNum, color='orangered', edgecolor='white', width=barWidth, label=namelist[0])
        ax.bar(r, red2, bottom=[i+j for i,j in zip(healthyNodeNum, red1)], color='lightsalmon', edgecolor='white', width=barWidth, label=namelist[1])
        ax.bar(r, red3, bottom=[i+j+k for i,j,k in zip(healthyNodeNum, red1, red2)], color='maroon', edgecolor='white', width=barWidth, label=namelist[2])
        ax.bar(r, red4, bottom=[i+j+k+l for i,j,k,l in zip(healthyNodeNum, red1, red2, red3)], color='sandybrown', edgecolor='white', width=barWidth, label=namelist[3])
        ax.bar(r, red5, bottom=[i+j+k+l+m for i,j,k,l,m in zip(healthyNodeNum, red1, red2, red3, red4)], color='darkkhaki', edgecolor='white', width=barWidth, label=namelist[4])
    ## need to add more if there are more than 5 attackers

    ax.set_xlabel("Time (Cycle)")
    ax.set_ylabel("No. of nodes")
    ax.legend(loc=2)
    ax.set_ylim(0, ylim1)

    ax2 = ax.twinx()
    ax2.plot(r, rate, linestyle='dashed', marker='D', label="Rate", color='darkblue')

    #add labels to point
    for x, y in zip(r, rate):
        label = "{:.2f}".format(y)
        ax2.annotate(label, (x, y), textcoords="offset points", xytext=(0,10), ha='center')

    ax2.set_ylabel("Rate")
    ax2.legend(loc=1)
    ax2.set_ylim(0, ylim2)

    plt.xticks(r, xLabelName)

    plt.title("Network Infection Rate")
    
    #save fig
    fig.savefig('Network Infection Rate.png', format='png', dpi=100, bbox_inches = 'tight')
    plt.close()

    return None

def generateLineGraphs(time, namelist, netCSList):
    """
    Create Line Graph
    """
    xLabelName = []

    r = []
    for i in range(0, time):
        r.append(i)
        xLabelName.append(str(i+1))
    tempName = []
    for n in namelist:
        text = n.split("_")
        tempName.append(text[1])
    
    namelist = tempName

    fig, ax = plt.subplots()
    
    tempList = []
    tempMax = []
    lenR = len(r)

    for i in range(0, len(netCSList)):
        num = len(netCSList[i])
        value = netCSList[i][-1]
        temp = netCSList[i].copy()

        tempMax.append(max(temp))
        if lenR > num:
            dif = lenR - num
            
            for i in range(0, dif):
                temp.append(value)
        tempList.append(temp)

    ylim1 = round(max(tempMax)+25.1, -1)

    netCSList = tempList.copy()

    for i in range(0, len(namelist)):
        #plot the line graph
        ax.plot(r, netCSList[i], linestyle='-', marker='D', label=namelist[i])

        #add labels to point
        for x, y in zip(r, netCSList[i]):
            label = "{:.2f}".format(y)
            plt.annotate(label, (x, y), textcoords="offset points", xytext=(0,10), ha='center')

    #set y axis label
    ax.set_ylim(0, ylim1)
    ax.set_xlabel("Time (Cycle)")
    ax.set_ylabel("NetCS")
    ax.legend(loc='upper left', bbox_to_anchor=(1,1), ncol=1)
    ax.grid()

    plt.xticks(r, xLabelName)
    plt.title("Network Compromisation Severity")

    #save fig
    fig.savefig('NetCS.png', format='png', dpi=100, bbox_inches = 'tight')
    plt.close()

    return None

def generateLineGraphs2(endnote, endtime, compby, netcslist):
    """
    Create Line Graph
    """
    for x, y, tex in zip(endtime, netcslist, compby):
        if str(tex) == "attacker-1":
            plt.scatter(x, y, marker='o', color='red', label='{0}'.format(tex))
        elif str(tex) == "attacker-2":
            plt.scatter(x, y, marker='o', color='blue', label='{0}'.format(tex))
        elif str(tex) == "attacker-3":
            plt.scatter(x, y, marker='o', color='gray', label='{0}'.format(tex))
        elif str(tex) == "attacker-4":
            plt.scatter(x, y, marker='o', color='brown', label='{0}'.format(tex))
        else:
            plt.scatter(x, y, marker='o', color='green', label='{0}'.format(tex))

    #add labels to point
    for x, y in zip(endtime, netcslist):
        label = "{:.2f}".format(y)
        plt.annotate(label, (x, y), textcoords="offset points", xytext=(0,5), ha='center', size=7)

    #dummy legend
    
    templist = list(dict.fromkeys(compby))

    plt.rcParams["figure.figsize"] = [16, 12]
    plt.legend(templist, scatterpoints=1, loc='upper right', bbox_to_anchor=(1.25, 1.00)) ## this is how to make legend~~
    
    plt.xlabel('Time(s)')
    plt.ylabel('NetCS')

    plt.title("Network Compromisation Severity")

    #save fig
    plt.savefig('NetCS.png', format='png', dpi=100, bbox_inches = 'tight')
    plt.close()

    return None

def generatePieChart(labels, sizes, labels2, sizes2, filename, chartTitle1, chartTitle2, color1, color2, filepath):
    """
    Create Pie Chart
    """
    # Make square figures and axes
    plt.figure(1, figsize=(10,5))
    the_grid = GridSpec(1, 2)

    if color1 is not None:
        cmap1 = plt.get_cmap(color1)
        colors1 = [cmap1(i) for i in np.linspace(0, 1, 8)]
    else:
        colors1 = ['#99ff99', '#ff9999', '#66b3ff', '#ffcc99']

    cmap2 = plt.get_cmap(color2)
    colors2 = [cmap2(i) for i in np.linspace(0, 1, 8)]

    plt.subplot(the_grid[0, 0], aspect=1, title='{}'.format(chartTitle1))

    network_pie = plt.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True, colors=colors1, radius=1.0, startangle=45)

    if labels2 is not None and sizes2 is not None:
        plt.subplot(the_grid[0, 1], aspect=1, title='{}'.format(chartTitle2))

        node_pie = plt.pie(sizes2, labels=labels2, autopct='%.0f%%', shadow=True, colors=colors2, radius=1.0, startangle=45)

    plt.suptitle('{}'.format(filename), fontsize=16)

    plt.subplots_adjust(top=0.8) #adjust size between titles 
    plt.axis('equal')
    plt.savefig(os.path.join(filepath, '{}.png'.format(filename)), format='png', dpi=100, bbox_inches = 'tight')
    plt.close()
    return None

def generateGeneralBarGraph(key, values, floatingLabelList, addonText, title, filename, xlabel, ylabel, color, saveFolder):
    """
    Create Bar Graph
    """
    xLabelName = key

    r = []
    for i in range(0, len(key)):
        r.append(i+1)

    fig = plt.figure(figsize=(10,10))

    cmap = plt.get_cmap(color)
    colors = [cmap(i) for i in np.linspace(0, 1, 8)]

    ax = fig.add_subplot(111)
    bar_width  = 0.35

    # Create green Bars
    ax.bar(r, values, color=colors, edgecolor='black', width=0.2)

    if floatingLabelList is not None:
        for x, y, z in zip(r, values, floatingLabelList):
            label = "{}".format(y)
            plt.annotate(label, (x, y), textcoords="offset points", xytext=(0,10), ha='center')
            plt.annotate((str(z)+str(addonText)), (x, y/2), textcoords="offset points", xytext=(0,0), ha='center', bbox=dict(boxstyle="round", fc="none", ec="gray"))
    else:
        for x, y in zip(r, values):
            label = "{}".format(y)
            plt.annotate(label, (x, y), textcoords="offset points", xytext=(0,10), ha='center')

    ylim1 = round(max(values)*1.1, 1)
    ax.set_ylim(0, ylim1)
    ax.set_xlim(0, len(r)+1)#this can avoid 1 bar width

    plt.xticks(r, xLabelName)
    
    if len(xlabel) > 0:
        ax.set_xlabel("{}".format(xlabel))
    if len(ylabel) > 0:
        ax.set_ylabel("{}".format(ylabel))
    plt.title("{}".format(title))
    if filename is None:
        fig.savefig(os.path.join(saveFolder, '{}.png'.format(title)), format='png', dpi=100, bbox_inches = 'tight')
    else:
        fig.savefig(os.path.join(saveFolder, '{}.png'.format(filename)), format='png', dpi=100, bbox_inches = 'tight')

    plt.close()

    return None

def generateGeneralPieChart(labels, sizes, filename, chartTitle1, color, percentage, filepath):
    """
    Create Pie Chart
    """
    # Make square figures and axes
    plt.figure(1, figsize=(10,10))
    the_grid = GridSpec(1, 1)

    if color is not None:
        cmap = plt.get_cmap(color)
        colors = [cmap(i) for i in np.linspace(0, 1, 8)]
    else:
        colors = ['#99ff99', '#ff9999', '#66b3ff', '#ffcc99']

    plt.subplot(the_grid[0, 0], aspect=1, title='{}'.format(chartTitle1))

    if percentage == True:
        p, tx, autotexts = plt.pie(sizes, labels=labels, autopct='%1.1f%%', shadow=True, colors=colors, radius=1.0, startangle=45)
    else:
        p, tx, autotexts = plt.pie(sizes, labels=labels, autopct="", shadow=True, colors=colors, radius=1.0, startangle=45)

        tempList = list(sizes)
        for i, a in enumerate(autotexts):
            a.set_text("{}".format(str(tempList[i])))

    plt.subplots_adjust(top=0.8) #adjust size between titles 
    plt.axis('equal')
    plt.savefig(os.path.join(filepath, '{}.png'.format(filename)), format='png', dpi=100, bbox_inches = 'tight')
    plt.close()
    return None

def generateGeneralAreaPlot(data, filename, filepath):
    """
    Create Network Compromise Percentage of All Sims Chart
    """
    df = pd.DataFrame(data)
    cmap = plt.get_cmap("tab10")
    colors = [cmap(i) for i in np.linspace(0, 1, 8)]
    ax = df.plot.area(x='xNum', stacked=True, title='Network Compromise Percentage of All Sims', color= colors)

    plt.legend(loc=2, fontsize='large')
    plt.savefig(os.path.join(filepath, '{}.png'.format(filename)), format='png', dpi=100, bbox_inches = 'tight')
    plt.close()

    return None

def createFullTimelineChart(net, dataList, filepath):
    """
    Create a full detailed network infection timeline chart
    """
    # ypos = 1
    # tempDict = {'startNode': [], 'startTime': []}
    # tempList = []
    # for x in net.nodes:
    #     text = x.name.split('-')
    #     if 'ag_CNC' in text:
    #         #print("CNC: ", x.timeline)
    #         pass
    #     else:
    #         if len(x.timeline) > 0:
    #             for y in x.timeline:
    #                 if type(y[0]) is list:
    #                     pass
    #                 else:
    #                     tempDict['startNode'].append(x.name)
    #                     tempDict['startTime'].append(y[2]-y[1])
    #         else:
    #             if ('ag_router' in text or 'router' in text) and x.canBeCompromised == False:
    #                 pass
    #             else:
    #                 tempList.append(x.name)
    
    # df = pd.DataFrame(tempDict)

    # ordered_df = df.sort_values(by='startTime')

    
    # orderedList = list(dict.fromkeys(ordered_df['startNode'])) #remove duplicated node
    # orderedList.extend(tempList)
    # tempList2 = []

    # ax = plt.axes()
    # ax.set_facecolor("whitesmoke")
    
    # for x in orderedList:
    #     for u in net.nodes:
    #         if str(x) == u.name:
    #             if len(u.timeline) > 0:
    #                 tempList3 = []
    #                 for y in u.timeline:
    #                     if y[0] == "SS":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='pink', edgecolor='black', width=y[1], linewidth=0.1)
    #                     elif y[0] == "AS":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='salmon', edgecolor='black', width=y[1], linewidth=0.1)
    #                     elif y[0] == "RS":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='tan', edgecolor='black', width=y[1], linewidth=0.1)
    #                     elif y[0] == "IS":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='red', edgecolor='black', width=y[1], linewidth=0.1)
    #                         tempList3.append(u.name)
    #                         tempList3.append(y[2]-y[1])
    #                         tempList2.append(tempList3)
    #                     elif y[0] == "SF":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='lime', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
    #                     elif y[0] == "AF":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='aqua', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
    #                     elif y[0] == "RF":
    #                         plt.barh(y=ypos, left=y[2]-y[1], color='limegreen', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
    #                     else:
    #                         print("No error!!3")
                            
    #                 ypos += 1

    # #for dummy legend
    # plt.barh(y=0, left=0, color='pink', edgecolor='black', linewidth=0.1, width=0, label='Scan Successful')
    # plt.barh(y=0, left=0, color='salmon', edgecolor='black', linewidth=0.1, width=0, label='Access Successful')
    # plt.barh(y=0, left=0, color='tan', edgecolor='black', linewidth=0.1, width=0, label='Report Successful')
    # plt.barh(y=0, left=0, color='red', edgecolor='black', linewidth=0.1, width=0, label='Install Successful')
    # plt.barh(y=0, left=0, color='lime', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Scan Fail')
    # plt.barh(y=0, left=0, color='aqua', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Access Fail')

    # my_range = range(1, len(orderedList)+1)

    # tempNameList = []
    # for x in orderedList:
    #     temp = x.split("_")
    #     tempNameList.append(temp[1])

    # plt.yticks(my_range, tempNameList)
    # plt.legend(loc='upper left', fontsize = 20)#, bbox_to_anchor=(1.25, 1.00))
    # plt.xlabel('Time(seconds)')
    # plt.ylabel('Propagating Node')
    # plt.savefig(os.path.join(filepath, 'Network Infection Full Timeline.pdf'), format='pdf', dpi=300, bbox_inches = 'tight')
    # plt.close()

    ypos = 1
    tempDict = {'startNode': [], 'startTime': []}
    tempList = []
    for x in net.nodes:
        text = x.name.split('-')
        if 'ag_CNC' in text or 'ag_server' in text:
            pass
        elif type(x) == intelligenceCenter:
            pass
        else:
            if len(x.timeline) > 0:
                for y in x.timeline:
                    if type(y[0]) == list:
                        pass
                    else:
                        tempDict['startNode'].append(x.name)
                        tempDict['startTime'].append(y[2]-y[1])
            else:
                if ('ag_router' in text or 'router' in text) and x.canBeCompromised == False:
                    pass
                else:
                    tempList.append(x.name)
    
    df = pd.DataFrame(tempDict)

    ordered_df = df.sort_values(by='startTime')

    
    orderedList = list(dict.fromkeys(ordered_df['startNode'])) #remove duplicated node
    orderedList.extend(tempList)
    tempList2 = []

    ax = plt.axes()
    ax.set_facecolor("whitesmoke")
    xmax = 0
    tempMax = 0
    for x in orderedList:
        for u in net.nodes:
            if str(x) == u.name:
                if len(u.timeline) > 0:
                    tempList3 = []
                    for y in u.timeline:
                        if y[0] == "SS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='pink', edgecolor='black', width=y[1], linewidth=0.1)
                        elif y[0] == "AS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='salmon', edgecolor='black', width=y[1], linewidth=0.1)#, hatch=2*"--"
                        elif y[0] == "RS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='tan', edgecolor='black', width=y[1], linewidth=0.1)#, hatch=2*"||"
                        elif y[0] == "IS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='red', edgecolor='black', width=y[1], linewidth=0.1)#, hatch=2*"//"
                            #to create dotted line to show which node is compromised
                            tempList3.append(u.name)
                            tempList3.append(y[2]-y[1])
                            tempList2.append(tempList3)
                        elif y[0] == "SF":
                            plt.barh(y=ypos, left=y[2]-y[1], color='lime', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
                        elif y[0] == "AF":
                            plt.barh(y=ypos, left=y[2]-y[1], color='aqua', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
                        elif y[0] == "RF":
                            plt.barh(y=ypos, left=y[2]-y[1], color='limegreen', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
                        elif y[0] == "IF":
                            plt.barh(y=ypos, left=y[2]-y[1], color='orange', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.1)
                        elif y[0] == "RB":
                            plt.barh(y=ypos, left=y[2]-y[1], color='black', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.5)
                        elif y[0] == "DS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='darkviolet', edgecolor='black', width=y[1], linewidth=0.5)
                        elif y[0] == "DF":
                            plt.barh(y=ypos, left=y[2]-y[1], color='skyblue', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.5)
                        elif y[0] == "PDoS":
                            plt.barh(y=ypos, left=y[2]-y[1], color='gray', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.5)
                        elif y[0] == "DEx":
                            plt.barh(y=ypos, left=y[2]-y[1], color='yellow', hatch=2*"\\\\", edgecolor='black', width=y[1], linewidth=0.5)
                        else:
                            pass
                        tempMax = y[2]
                        if tempMax > xmax:
                            xmax = tempMax
                    ypos += 1
    #for dummy legend
    plt.barh(y=0, left=0, color='pink', edgecolor='black', linewidth=0.1, width=0, label='Scan Successful')
    plt.barh(y=0, left=0, color='salmon', edgecolor='black', linewidth=0.1, width=0, label='Access Successful')
    plt.barh(y=0, left=0, color='tan', edgecolor='black', linewidth=0.1, width=0, label='Report Successful')
    plt.barh(y=0, left=0, color='red', edgecolor='black', linewidth=0.1, width=0, label='Install Successful')
    plt.barh(y=0, left=0, color='lime', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Scan Fail')
    plt.barh(y=0, left=0, color='aqua', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Access Fail')
    plt.barh(y=0, left=0, color='limegreen', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Report Fail')
    plt.barh(y=0, left=0, color='orange', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Install Fail')
    plt.barh(y=0, left=0, color='black', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Device Reboots')
    plt.barh(y=0, left=0, color='darkviolet', edgecolor='black', linewidth=0.1, width=0, label='DDoS Successful')
    plt.barh(y=0, left=0, color='skyblue', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='DDoS Fail')
    plt.barh(y=0, left=0, color='gray', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='PDoS Successful')
    plt.barh(y=0, left=0, color='yellow', hatch=2*"\\\\", edgecolor='black', linewidth=0.1, width=0, label='Data Exfiltrated')

    my_range = range(1, len(orderedList)+1)

    tempNameList = []
    for x in orderedList:
        temp = x.split("_")
        tempNameList.append(temp[-1])

    plt.yticks(my_range, tempNameList)
    plt.xticks(np.arange(0, int(xmax)+2, 1.0))
    plt.legend(loc='upper left', fontsize = 14)
    plt.xlabel('Time(seconds)')
    plt.ylabel('Propagating Node')
    #save fig
    plt.savefig(os.path.join(filepath, 'Network Infection Full Timeline.pdf'), format='pdf', dpi=300, bbox_inches = 'tight')
    plt.close()

    return None

def convertPNGtoGIF(filepath):
    """
    convert multiple PNG files to GIF file
    Link: https://stackoverflow.com/questions/753190/programmatically-generate-video-or-animated-gif-in-python
    """
    imgFolder = os.fsencode(filepath)

    filenames = []

    for x in os.listdir(imgFolder):
        fn = os.fsdecode(x)
        if fn.endswith('.png'):
            if fn.startswith('propagation'):
                filenames.append(fn)

    if len(filenames) > 0:
        if len(filenames) <= 50:
            filenames = naturalSort(filenames)
            images = [imageio.imread(os.path.join(filepath ,f)) for f in filenames]
            imageio.mimsave(os.path.join(filepath, 'full propagation.gif'), images, duration = 0.5)
        else:
            print("Save diskspace. GIF generation aborted.")
    else:
        print("GIF generation failed.")

    return None

def naturalSort(l):
    """
    sorting for humans: natural sort order
    Link: https://blog.codinghorror.com/sorting-for-humans-natural-sort-order/
    """
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    aplhanum = lambda key: [convert(c) for c in re.split('([0-9]+)', key)]
    return sorted(l, key = aplhanum)

def createLollipopPlot(data, filepath):
    """
    Create simple network infection timeline chart
    """
    cmap = plt.get_cmap('Set1')
    colors = [cmap(i) for i in np.linspace(0, 1, 8)]
    
    df = pd.DataFrame(data)

    ordered_df = df.sort_values(by='startTime')

    my_range=range(1,len(df.index)+1)

    ax = plt.axes()
    ax.set_facecolor("whitesmoke")

    plt.scatter(ordered_df['startTime'], my_range, color='green', alpha=1, label='Propagating Node')
    plt.scatter(ordered_df['endTime'], my_range, color='red', alpha=0.4 , label='Target Node')

    tempNameList = []
    for x in ordered_df['startNode']:
        temp = x.split("_")
        tempNameList.append(temp[1])

    plt.yticks(my_range, tempNameList)
    
    #added for label text beside the node
    for x, y, tex in zip(ordered_df['endTime'], my_range, ordered_df['endNode']):
        plt.text(x+0.35, y, simplifyText(tex), horizontalalignment='left', verticalalignment='center', fontdict={'color': 'black', 'size': 10})

    templist = list(dict.fromkeys(ordered_df['compBy']))
    xmax = 0
    tempMax = 0
    for x, y, z, tex in zip(ordered_df['startTime'], my_range, ordered_df['endTime'], ordered_df['compBy']):
        for i in range(len(templist)):
            if str(tex) == templist[i]:
                plt.hlines(y=y, xmin=x, xmax=z, color=colors[i], alpha=1)
        tempMax = z
        if tempMax > xmax:
            xmax = tempMax

    for i in range(len(templist)):
        plt.hlines(y=0, xmin=0, xmax=0, color=colors[i], alpha=1, label=str(templist[i]))

    plt.rcParams["figure.figsize"] = [16, 12]
    plt.legend(loc='upper left', fontsize = 20)
    plt.xticks(np.arange(0, int(xmax)+2, 1.0))
    plt.title("Network Infection Timeline", loc='left')
    plt.xlabel('Time(seconds)')
    plt.ylabel('Propagating Node')

    #save fig
    plt.savefig(os.path.join(filepath, 'Network Infection Timeline.pdf'), format='pdf', dpi=300, bbox_inches = 'tight')
    plt.close()

    tempList2 = []
    for x, y, z in zip(ordered_df['startNode'], ordered_df['endNode'], ordered_df['endTime']):
        tempList = []
        tempList.append(x)
        tempList.append(y)
        tempList.append(z)
        tempList2.append(tempList)

    return tempList2

def simplifyText(data):
    """
    Simplify a string
    """
    text = data.split("_")
    return text[1]

def combineImage(filename, newname, filepath):
    """
    from https://stackoverflow.com/questions/30227466/combine-several-images-horizontally-with-python
    Combines 2 images
    """

    list_im = filename

    imgs    = [ PIL.Image.open(i) for i in list_im ]
    # pick the image which is the smallest, and resize the others to match it (can be arbitrary image shape here)
    min_shape = sorted( [(np.sum(i.size), i.size ) for i in imgs])[0][1]
    imgs_comb = np.hstack([np.asarray(i.resize(min_shape)) for i in imgs])

    # save that beautiful picture
    imgs_comb = PIL.Image.fromarray( imgs_comb)
    imgs_comb.save(os.path.join(filepath, '{}.png'.format(newname)))    
    
    # for a vertical stacking it is simple: use vstack
    ##imgs_comb = np.vstack( (np.asarray( i.resize(min_shape) ) for i in imgs ) )
    ##imgs_comb = PIL.Image.fromarray( imgs_comb)
    ##imgs_comb.save( 'Trifecta_vertical.png' )

def createTreeGraph2(id, info, filename, color, filepath):
    """
    Revised version from createTreeGraph
    """
    temp = ""
    noChild = False
    G = nx.DiGraph()

    for key in info:
        if key == 'path':
            if len(info[key]) == 1:
                noChild = True
            for x in info[key]:

                if type(x) is list:
                    if len(x) > 1:
                        G.add_edges_from([(simplifyText(x[0]), simplifyText(x[1]))])
                    else:
                        temp = simplifyText(x[0])
                        #when there is no child node
                        if noChild == True:
                            G.add_node(temp)

    if noChild == True:
        pos = {temp: (0.5, 0)}
    else:
        pos = hierarchy_pos5(G, temp)
    nx.draw(G, pos=pos, with_labels=True, node_size=750, node_color=color, font_size=10) 

    tempFN = os.path.join(filepath, '{}.png'.format(simplifyText(str(id))))

    plt.savefig('{}'.format(tempFN), dpi=80, bbox_inches = 'tight')

    filename.append(tempFN)
    plt.close()

    return filename

def hierarchy_pos5(G, root, levels=None, width=1., height=1.): #improved version from hierarchy_pos2. adopted 2 lines from hierarchy_pos4 to prevent infinite recursion
    '''
    from: https://stackoverflow.com/questions/29586520/can-one-get-hierarchical-graphs-from-networkx-with-python-3/64516717#64516717
    If there is a cycle that is reachable from root, then this will see infinite recursion.
       G: the graph
       root: the root node
       levels: a dictionary
               key: level number (starting from 0)
               value: number of nodes in this level
       width: horizontal space allocated for drawing
       height: vertical space allocated for drawing
    '''
    
    TOTAL = "total"
    CURRENT = "current"
    def make_levels(levels, node=root, currentLevel=0, parent=None, parsed = []):
        """Compute the number of nodes for each level
        """
        if(node not in parsed): ##added 2 lines to prevent infinite recursion
            parsed.append(node) ##added 2 lines to prevent infinite recursion
            if not currentLevel in levels:
                levels[currentLevel] = {TOTAL : 0, CURRENT : 0}
            levels[currentLevel][TOTAL] += 1
            neighbors = list(G.neighbors(node))

            for neighbor in neighbors:
                if not neighbor == parent:
                    levels =  make_levels(levels, neighbor, currentLevel + 1, node, parsed = parsed)
        return levels

    def make_pos(pos, node=root, currentLevel=0, parent=None, vert_loc=0, parsed = []):
        if(node not in parsed):##added 2 lines to prevent infinite recursion
            parsed.append(node)##added 2 lines to prevent infinite recursion
            dx = 1/levels[currentLevel][TOTAL]
            left = dx/2
            pos[node] = ((left + dx*levels[currentLevel][CURRENT])*width, vert_loc)
            levels[currentLevel][CURRENT] += 1
            neighbors = list(G.neighbors(node))
            for neighbor in neighbors:
                if not neighbor == parent:
                    pos = make_pos(pos, neighbor, currentLevel + 1, node, vert_loc-vert_gap, parsed = parsed)
        return pos
    if levels is None:
        levels = make_levels({})
    else:
        levels = {l:{TOTAL: levels[l], CURRENT:0} for l in levels}

    vert_gap = height+1000 / (max([l for l in levels])+1)
    return make_pos({})

def createGraph(net, filename, filepath):
    """
    Plot a graph 
    """
    g = nx.Graph()

    pos1 = [[0, 1000], [1000, 1000], [1500, 1000], [2000, 1000], [2500, 1000]] 

    pos2 = [[0, -1500], [500, -1500], [1000, -1500], [1500, -1500], [2000, -1500], [2500, -1500]]

    pos3 = [[2000, 1000], [2500, 1000]]

    pos4 = [[500, 1500], [1500, 1500], [2000, 1500]]

    posServer = [[0, -2000], [500, -2000], [1000, -2000], [1500, -2000], [2000, -2000]]

    nodeColorList = []

    nodeSizeList = []
    nameMapping = {}
    shortName = []
    i = 0
    j = 0
    k = 0
    l = 0

    atkerList = []
    color1 = ["darkred", "darkcyan", "olive", "gold", "purple", "hotpink"]
    color2 = ["red", "aqua", "green", "yellow", "mediumpurple", "pink"]
    for node in net.nodes:
        text = node.name.split("-")
        if 'attacker' in text or 'ag_attacker' in text:
            atkerList.append(node.name)

    for node in net.nodes:
        text = node.name.split("-")
        nodeSize = len(node.con)*100
        if nodeSize == 0:
            nodeSize = 100
        temp = None
        temp2 = None
        shortName = node.name.split("_")

        if len(shortName) > 1:
            nameMapping[node.name] = str(shortName[1])
        else:
            nameMapping[node.name] = str(shortName[0])

        if len(node.position) > 0:
            p = node.position
            nodeSizeList.append(nodeSize)
        else:
            if "ag_server" in text:
                p = posServer[j].copy()
                nodeSizeList.append(5500)
                j += 1
            elif "Intelligence Center" in text:
                p = pos3[k].copy()
                nodeSizeList.append(2500)
                k += 1
            elif "ag_CNC" in text:
                p = pos4[l].copy()
                nodeSizeList.append(5500)
                l += 1
            else:
                p = pos1[i].copy()
                nodeSizeList.append(1300)
                i += 1
        
        if 'attacker' in text or 'ag_attacker' in text:
            for i in range(len(atkerList)):
                if node.name == atkerList[i]:
                    g.add_node(node.name, color=color1[i], size=500, shape="circle", pos=p)
        elif 'CNC' in text or 'ag_CNC' in text:
            g.add_node(node.name, color="orange", size=500, shape="circle", pos=p)
        elif 'server' in text or 'ag_server' in text:
            g.add_node(node.name, color="lightgreen", size=1000, shape="circle", pos=p)
        elif 'Intelligence Center' in text:
            g.add_node(node.name, color="skyblue", size=1500, shape="s", pos=p)
        else:
            if len(node.log) > 0:
                temp = node.log[1]
            
            if temp != None and node.conditionNow != "disable":
                for i in range(len(atkerList)):
                    textAtker = atkerList[i].split("ag_")
                    if temp == textAtker[1]:
                        g.add_node(node.name, size=nodeSize, color=color2[i], pos=p)
            elif node.conditionNow == "disable":
                g.add_node(node.name, size=nodeSize, color="black", pos=p)
            else:
                g.add_node(node.name, size=nodeSize, color="gray", pos=p)

        for conNode in node.con:
            text2 = conNode.name.split("-")
            if 'attacker' in text2 or 'ag_attacker' in text2:
                for i in range(len(atkerList)):
                    if conNode.name == atkerList[i]:
                        g.add_node(conNode.name)
            elif 'CNC' in text2 or 'ag_CNC' in text2:
                g.add_node(conNode.name)
            elif 'Intelligence Center' in text2:
                g.add_node(conNode.name)
            else:
                if len(conNode.log) > 0:
                    temp2 = conNode.log[1]
                
                if temp2 != None:
                    for i in range(len(atkerList)):
                        textAtker2 = atkerList[i].split("ag_")
                        if temp2 == textAtker2[1]:
                            g.add_node(conNode.name)
                else:
                    g.add_node(conNode.name)
            
            if len(conNode.log) > 0 and ('CNC' in text or 'ag_CNC' in text):
                temp3 = conNode.log[1]
                
                if temp3 != None:
                    for i in range(len(atkerList)):
                        textAtker3 = atkerList[i].split("ag_")
                        if temp3 == textAtker3[1]:
                            g.add_edge(conNode.name, node.name, weight=100, color=color2[i], style='dashed')
            else:
                text3 = node.name.split("-")
                if 'server' in text3 or 'ag_server' in text3:
                    g.add_edge(node.name, conNode.name, weight=100, color='limegreen', style='-')
                elif 'Intelligence Center' in text3:
                    g.add_edge(node.name, conNode.name, weight=100, color='lightskyblue', style='dotted')
                else:
                    g.add_edge(node.name, conNode.name, weight=100, color='gray') #, style='solid')

    pos = nx.get_node_attributes(g, 'pos')
    colors1 = nx.get_node_attributes(g, 'color')
    ns = nx.get_node_attributes(g, 'size')
    colors1 = list(colors1.values())
    ns = list(ns.values())
    edge_color_list = [ g[e[0]][e[1]]['color'] for e in g.edges() ]

    if len(nameMapping) > 0:
        nx.draw_networkx_labels(g, pos, nameMapping, font_size=9)
        nx.draw(g, pos, node_size=ns, node_color=colors1, edge_color=edge_color_list, style='dashed')
    else:
        nx.draw(g, pos, node_size=ns, node_color=colors1, edge_color=edge_color_list, with_labels=True, font_size=12, style='dashed')

    plt.rcParams["figure.figsize"] = [16, 12]
    tempFN = filename.split(" ")
    if "original" in tempFN:
        plt.savefig(os.path.join(filepath, '{}.pdf'.format(filename)), format='pdf', dpi=300, bbox_inches = 'tight')
    else:
        plt.savefig(os.path.join(filepath, '{}.png'.format(filename)), dpi=80, bbox_inches = 'tight')
    plt.close()

    return None

def flattenList(oldlist):
    """
    Flatten nested list 
    """
    flat_list = []
    for sublist in oldlist:
        for item in sublist:
            flat_list.append(item)
    # print(flat_list)