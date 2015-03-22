# Port Forwarder - A port forwarding application in C

Introduction
---------------
This application generically forwards any given TCP connection from a port to a specified host:port pair.
Forwards are state aware and add and remove themselves as necessary.

Installation
---------------
The application is compiled entirely with the provided makefile
It does require [LibConfRead](github.com/andrewburian/configreader) to be installed prior to making.

Configuration
---------------
All configuration is done via the `forwards.conf` file.
The configuration file is parsed using [LibConfRead](github.com/andrewburian/configreader) and follow its standard format
The root section requires the local IP address of the forwarder
Any following sections are forward definitions and require a local port, as well as the tohost and toport pair.

Running
---------------
Once the forwards configuration is set, simply execute the `portforward.exe` binary.
Any invalid or malformed forward sections will be ignored by the program, and a warning printed.
