# AI Services Detection Nmap Script

## Overview

This Nmap script is designed to detect various Artificial Intelligence (AI) services running on web servers. It performs HTTP requests to the root directory and specific endpoints, identifying services by looking for unique strings in the responses.

## Features

- Scans common web service ports as well as custom AI service ports.
- Provides links to a repository for potential exploits for identified services.
- Identifies the following AI services:
  - MLflow
  - Ray Dashboard
  - H2O Flow
  - Kubeflow
  - ZenML
  - Triton Inference Server
  - Kedro
  - BentoML
  - TensorBoard
  - MLRun
  - MLServer
  - Weights & Biases
  - Aim
  - Neptune
  - Prefect

## Usage

Place the script in the `scripts` directory of your Nmap installation. Then, run Nmap with the `--script` option, specifying the name of this script.

```bash
nmap --script ai-tools.nse -p80,443,4141,4200,5000,5001,8000,8001,8080,8081,8237,8265,8888,43800,54321,54322 <target>
```

Replace `<target>` with the IP address or hostname of the system you wish to scan.

## Output

The script will output a message for each detected AI service, including a URL to check for known exploits.

Example output for a detected service:

```
PORT     STATE SERVICE REASON
8080/tcp open  http    syn-ack
| ai-services-detection:
|   MLflow service found!
|_  Check https://github.com/ProtectAI/AI-exploits for exploits.
```

## Script Requirements

- Nmap: 7.80 or higher
- Lua libraries: `http`, `shortport`, `stdnse`

## Author

- @DanMcInerney
- @byt3bl33d3r

## License

This script is released under the same license as Nmap. For more information, see [Nmap's legal documentation](https://nmap.org/book/man-legal.html).

## Categories

- `safe`
- `discovery`
```
