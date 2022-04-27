# IoTSecSim - A Framework for Modelling and Simulation of Security in Internet of Things

The project is focusing on building a framework of IoT security. Our main goals are:
1. to model IoT attacks and defences in an emulated IoT networks; and 
2. to evaluate the impact of different defence techniques on IoT attacks by using multiple security metrics.

This framework can **create IoT networks** with different settings and configurations on IoT devices and network topologies, **model malware attacks** against the emulated IoT networks and **evaluate relevant defences**. The simulation software is built with the aim to offer flexibility and adaptability to users. Also, it can be extended with new features and functionalities to simulate recent discovered malware attacks and defences.

## Framework Illustration
![IoTSecSim framework](https://github.com/kokonnchee/IoTSecSim/blob/main/framework.png?raw=true)

## Simulator
**IoTSecSimMain.py** is the starting point of our simulator. Minimum 3 inputs files (namely .input, .device, and .atker files) are needed to run the simulation without the defence. Defence can be added in simulation using the .defender file (4th input file). All input files can be created by running **CreateInputFile.py**. All parameters can be set or adjusted before the input file generation. All simulation results will be stored in a new folder.

## Requirements
Python version: 3.7

Python Packages:
* `imageio`
* `matplotlib`
* `mpi4py`
* `networkx`
* `numpy`
* `pandas`
* `Pillow`
* `scipy`

---

## Publication
In progress.

## Future Update
Soon.
