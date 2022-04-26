# IoTSecSim - A Framework for Modelling and Simulation of Security in Internet of Things

The project proposes a framework which focuses on IoT security. The main goals of our framework are:
1. to model and simulate cyber-attacks and defences in IoT networks; and 
2. to evaluate the effectiveness of different defence techniques with using various security metrics.

This framework supports **creation of IoT networks** with various types of IoT devices and network topologies, **modelling of malware attacks** against IoT networks and **evaluation of relevant defences**. The simulation software provides great flexibility and adaptability to users and can be extended with new modules to investigate newly discovered malware attacks and defences.
![IoTSecSim framework]()

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
