# Dedalus

[Dedalus](https://gitlab.com/ealione/Dedalus)  is an implementation of a self healing distributed system for gathering real time statistics from a mesh network. 

Dedalus can be attached to an ad hoc network and used in order to track real time statistics, maintain and distribute event logs as well as directly control the nodes of the network from any connected clients. The main drive behind developing Dedalus was having a testbed for scheduling experiments and archiving the results as well as having the ability to control the network and provide a birds' eye view of the whole network.

Dedalus has the ability to work on more than one interfaces, meaning that it can either operate completely using the mesh network or if some other gateway is provided then use it as an auxiliary endpoint for answering to queries or pushing network messages for storing to a remote log file.

Dedalus is based on the majordomo protocol, is designed for resiliency and can operate in unstable networks. Worker nodes can be initialized before brokers or vice versa without any issues regarding connectivity. If connection is lost the message will persist until it’s delivered or a timeout occurs

## Using

Dedalus can be run in four main modes: 

**As a client** where we can connect to a broker instance and log or view information.

```bash
$ python dedalus client -a 127.0.0.1
```

Clients have only to respect the specific message formats and otherwise are not limited in their implementation details in any way. They can be created in most available programming languages and from any operating system. We are also not limited to the design of the client since it can be anything from a desktop application with a complete user interface, a mobile app, a terminal application or even a simple logger.

A typical message accepted by a Dedalus broker looks like the one below,

```python
['', dedalus_protocol, dedalus_service_a, wid, command_id, args]
```

The first argument is an empty space used by the broker to distinguish the sender id from the rest of the message. Followed by the protocol version we want to use and then the specific worker service we want to operate on, the worker id if it is required. Any specific command id and any command arguments as required.

**As a worker** where we can connect to a broker and register the node for a specific service, making ourselves available to serve client requests.

```bash
$ python dedalus worker -a 127.0.0.1
```

Workers are responsible for performing all of the required operations on each node. As soon as they find a running instance of a broker they will connect to it and make available one or more services that they can offer. Once the initial instllation phase has concluded they will be available to answer requests and monitor the node they are running on. 

Again they can be implemented in any of the available languages as long as the communication constrains are respected. 

Workers are exposed to a series of modules able to mainly do one of two things. Scan the current hardware and report back usage and network statistics or modules that are responsible for retrieving protocol specific information.

**As a broker** in order to accept messages from clients and workers.

```bash
$ python dedalus broker -a 127.0.0.1
```

A Dedalus broker is responsible for passing messages back and forth from all clients and workers connected to him as well as implement the needed queues for ensuring that all requests eventually will be served.

Brokers also are tasked with basic bookkeeping operations since they have to maintain lists of all active workers as well as test their connectivity and status. 

It also has its own service registered along with all other worker services and can operate as an asychronus backend server. 

**As a worker and a broker** at the same time.

```bash
$ python dedalus full -a 127.0.0.1 -s
```

This mode is intended for testing and debugging or for when we need to quickly run both a worker and a broker at the same node. We are not limited to only one worker as each new Dedalus entity will be spawned in its own thread.

## Building

You'll need [Python](https://www.python.org/) and [pip](https://github.com/pypa/pip) installed on your computer in order to build this app.

```bash
$ git clone git@gitlab.com:ealione/Dedalus.git
$ cd Dedalus
$ pip install -r requirements.txt
$ python setup install
```

## Testing

Unit tests can be run by using the following command where `<directory>` is the `/src` directory of the project

```bash
$ python -m unittest discover -s <directory> -p '*_test.py'
```
