# openconfig-stig-validator

Validates Security Requirements against modified OpenConfig format

## Directory Format

The directory provided to this tool should contain a `nodes.json` file that tells the tool where all the other files are located. This file's format will be explained below:

### `nodes.json` File Format

The `nodes.json` file should have the following structure:
- "map": String: Points to the filename (not including directory name) containing a map of the physical network connections (more on this later).
- "nodes": List: Contains a list of dictionaries, one for each openconfig node in the system. The format of each dictionary is below:
  - "name": String: The name of the node in the map file.
  - "filename": String: The filename for the configuration file for the node. May be in either JSON or XML format. Does not include the directory name. The read-only sections from the openconfig spec are optional.
  - "interfaces": List\[String\]: All of the interfaces that are available (even if unused) on the node.
- "clients": List: Contains a list of dictionaries with a format identical to the "nodes" key, except for the fact that this list corresponds to end devices (i.e. PCs) and the format of the file provided must be JSON. This list is optional and only provides the test plugins with useful additional data about the requirements this device poses on the rest of the network. 

### Map File Format

The map file provides the test code with the physical structure of the network connections between devices. The file is in DOT format, with only the first graph used. Each node/interface is referenced in the format `node_name:interface_name` where `node_name` refers to the name of the node specified in the `nodes.json` file and `interface_name` is the name of the interface from the `nodes.json` file.

## Configuration File Format

The configuration file is optional but also has a specific format. It is a json file that has the following structure:
- "tests": List\[String\]: The list of test names to run. This field is optional and defaults to all test loaded by the test runner.
- "plugins": List\[String\]: All file paths to the files containing non-standard plugins that you would like the runner to use. This field is optional and defaults to no additional plugins loaded.
