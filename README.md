# User Manual for IoTSecSim


## Introduction
IoTSecSim - A Framework for Modelling and Simulation of Security in Internet of Things

This project is focusing on building a framework for IoT security. This framework can **create IoT networks** with different settings and configurations on IoT devices and network topologies, **model malware attacks** against the emulated IoT networks and **evaluate relevant defences**. The simulation software is built with the aim to offer flexibility and adaptability to users. Also, it can be extended with new features and functionalities to simulate recently discovered malware attacks and defences.

Our main goals are:
1. to model IoT attacks and defences in emulated IoT networks; and 
2. to evaluate the impact of different defence techniques on IoT attacks by using multiple security metrics.

 

## Framework Illustration
![IoTSecSim framework](https://github.com/kokonnchee/IoTSecSim/blob/main/framework.png?raw=true)



## System Requirements
* [Python](https://www.python.org/downloads/) at least version 3.7
* [Visual Studio Code (VS Code)](https://code.visualstudio.com/)

### The following Python packages are required:
* `imageio`
* `matplotlib`
* `mpi4py`
* `networkx`
* `numpy`
* `pandas`
* `Pillow`
* `scipy`



## Installation Instructions
1. Download and install [Python](https://www.python.org/downloads/);
2. Download and install [Visual Studio Code (VS Code)](https://code.visualstudio.com/);
3. Download IoTSecSim as a ZIP from GitHub;
4. Extract the IoTSecSim zip file;
5. Open VS Code;
6. On the VS Code menu bar, choose File > Open Folder..., and then browse and select the **IoTSecSim** folder;
7. You can now view the code of IoTSecSim.



## Step-by-step on Using IoTSecSim
1. On the VS Code explorer bar (on the left), click on the "src" folder and select **"IoTSecSimMain.py"**;
2. If using **PRESET** input files (namely .input, .device, .atker, and .defender files) in IoTSecSim folder, please go to **Step 6**;
3. If use **SELF-CONFIGURED** input files, please go to **Step 4**;
4. On the VS Code explorer bar, select **"CreateInputFile.py"**;
5. Make any changes from **line 477 till 619** to configure attacker, device, network, and defence technique. 
6. On the VS Code top right corner, click **"Run Python File"**; 
7. Wait for the computation of the simulation.
8. Simulation is completed when you see the **"TOTAL TIME SPENT :: "** on the second last line on the internal Terminal of VS Code.
9. Browse the results of the simulation runs in a newly created folder in the IoTSecSim folder.



## Publication(s)
Kok Onn Chee, Mengmeng Ge, Guangdong Bai, and Dan Dongseong Kim, 
[IoTSecSim: A Framework for Modelling and Simulation of Security in Internet of Things](https://doi.org/10.1016/j.cose.2023.103534), 
_Computers & Security_ (2023): 103534.



## Future Update
Soon.



## About
This repository was created by [Kok Onn Chee](https://sites.google.com/view/kokonnchee).

### Authors
* [Kok Onn Chee](https://sites.google.com/view/kokonnchee)
* [Mengmeng Ge](https://sites.google.com/site/mengmengge88)
* [Guangdong Bai](https://baigd.github.io/)
* [Dan Dongseong Kim](https://sites.google.com/view/dsteam/)



## Contact Us
* Kok Onn Chee [email](mailto:kokonn.chee@uq.net.au?subject=[GitHub]IoTSecSim)
* Mengmeng Ge [email](mailto:mge43@uclive.ac.nz?subject=[GitHub]IoTSecSim)
* Guangdong Bai [email](mailto:g.bai@uq.edu.au?subject=[GitHub]IoTSecSim)
* Dan Dongseong Kim [email](mailto:dan.kim@uq.edu.au?subject=[GitHub]IoTSecSim)


