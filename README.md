<div align="center">

# AI Exploits

  <img width="250" src="https://github.com/protectai/ai-exploits/assets/5151193/aef11c4a-d758-45fe-aab8-c9df714cdbe5" alt="AI Exploits Logo">

</div>

The AI world has a security problem and it's not just in the inputs given to LLMs such as ChatGPT. Based 
on research done by [Protect AI](https://protectai.com) and independent security experts on the [Huntr](https://huntr.com) Bug Bounty Platform, there are far more impactful and practical attacks 
against the tools, libraries and frameworks used to build, train, and deploy machine learning models. Many of these 
attacks lead to complete system takeovers and/or loss of sensitive data, models, or credentials most often without the need
for authentication. 

With the release of this repository, [Protect AI](https://protectai.com) hopes to demystify to the Information Security community what practical attacks against AI/Machine Learning infrastructure look like in the real world and raise awareness to the amount of vulnerable components that currently exist in the AI/ML ecosystem. More vulnerabilities can be found here:
* [November Vulnerability Report](https://protectai.com/threat-research/november-vulnerability-report)
* [December Vulnerability Report](https://protectai.com/threat-research/december-vulnerability-report)
* [January Vulnerability Report](https://protectai.com/threat-research/january-vulnerability-report)
* [February Vulnerability Report](https://protectai.com/threat-research/february-vulnerability-report)
* [March Vulnerability Report](https://protectai.com/threat-research/march-vulnerability-report)
* [April Vulnerability Report](https://protectai.com/threat-research/april-vulnerability-report)
* [May Vulnerbility Report](https://protectai.com/threat-research/may-vulnerability-report)
* [June Vulnerbility Report](https://protectai.com/threat-research/june-vulnerability-report)
* [July Vulnerbility Report](https://protectai.com/threat-research/july-vulnerability-report)

## Overview

This repository, **ai-exploits**, is a collection of exploits and scanning templates for responsibly disclosed vulnerabilities affecting machine learning tools.

Each vulnerable tool has a number of subfolders containing three types of utilities: [Metasploit](https://github.com/rapid7/metasploit-framework) modules, [Nuclei](https://github.com/projectdiscovery/nuclei) templates
and CSRF templates. Metasploit modules are for security professionals looking to exploit the vulnerabilities and Nuclei templates are for scanning a large number of remote servers to determine if they're vulnerable.

## Demo

Video demonstrating running one of the Metasploit modules against Ray:

[![Exploit Demo](https://img.youtube.com/vi/5aSwPQKKhi4/0.jpg)](https://youtu.be/5aSwPQKKhi4)

## Setup & Usage

The easiest way to use the modules and scanning templates is to build and run the Docker image provided by the `Dockerfile` in this repository. The Docker image will have Metasploit and Nuclei already installed along with all the necessary configuration.

###  Docker

1. Build the image:

   ```bash
   git clone https://github.com/protectai/ai-exploits && cd ai-exploits
   docker build -t protectai/ai-exploits .
   ```

2. Run the docker image:
   
   ```bash
   docker run -it --rm protectai/ai-exploits /bin/bash
   ```

The latter command will drop you into a `bash` session in the container with `msfconsole` and `nuclei` ready to go.

### Using the Metasploit Modules

#### With Docker

Start the Metasploit console (the new modules will be available under the `exploits/protectai` category), load a module, set the options, and run the exploit.

   ```bash
   msfconsole
   msf6 > use exploit/protectai/ray_job_rce
   msf6 exploit(protectai/ray_job_rce) > set RHOSTS <target IP>
   msf6 exploit(protectai/ray_job_rce) > run
   ```

#### With Metasploit Installed Locally

Create a folder `~/.msf4/modules/exploits/protectai` and copy the exploit modules into it.

   ```bash
   mkdir -p ~/.msf4/modules/exploits/protectai
   cp ai-exploits/ray/msfmodules/* ~/.msf4/modules/exploits/protectai
   msfconsole
   msf6 > use exploit/protectai/<exploit_name.py>
   ```

### Using Nuclei Templates

Nuclei is a vulnerability scanning engine which can be used to scan large numbers of servers for known vulnerabilities in web applications and networks.

Navigate to nuclei templates folder such as `ai-exploits/mlflow/nuclei-templates`. In the Docker container these are stored in the `/root/nuclei-templates` folder. Then simply point to the template file and the target server.
   ```
   cd ai-exploits/mlflow/nuclei-templates
   nuclei -t mlflow-lfi.yaml -u http://<target>:<port>
   ```

### Using CSRF Templates

Cross-Site Request Forgery (CSRF) vulnerabilities enable attackers to stand up a web server hosting a malicious HTML page 
that will execute a request to the target server on behalf of the victim. This is a common attack vector for exploiting 
vulnerabilities in web applications, including web applications which are only exposed on the localhost interface and 
not to the broader network. Below is a simple demo example of how to use a CSRF template to exploit a vulnerability in a 
web application.

Start a web server in the csrf-templates folder. Python allows one to stand up a simple web server in any 
directory. Navigate to the template folder and start the server.

   ```bash
   cd ai-exploits/ray/csrf-templates
   python3 -m http.server 9999
   ```

Now visit the web server address you just stood up (http://127.0.0.1:9999) and hit F12 to open 
the developer tools, then click the Network tab. Click the link to ray-cmd-injection-csrf.html. You should see that 
the browser sent a request to the vulnerable server on your behalf.

## Contribution Guidelines

We welcome contributions to this repository. Please read our [Contribution Guidelines](CONTRIBUTING.md) for more information on how to contribute.

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
