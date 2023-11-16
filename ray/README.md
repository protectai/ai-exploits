# Ray Vulnerabilities and Exploits

## Overview
Ray is an open-source framework that allows for distributed training of machine learning models. Ray is designed to scale transparently from running on a single machine to large clusters and includes a web interface for ease of use. By default, Ray lacks authentication.

## Vulnerabilities

### CSRF (Cross-Site Request Forgery)

- **Description**: Ray's web interface may not implement proper CSRF protections, which could allow attackers to craft malicious web pages that, when visited by a logged-in user, could perform unauthorized actions on the web interface.
- **Impact**: An attacker could leverage CSRF vulnerabilities to execute commands, control jobs, or alter the state of the Ray cluster without the user's consent.

### RCE (Remote Code Execution)

- **Description**: Certain endpoints or features within Ray may be susceptible to RCE, allowing an attacker to execute arbitrary code on the cluster's nodes.
- **Impact**: If exploited, this could grant an attacker full control over the Ray cluster, potentially leading to data leakage, service disruption, or further exploitation of internal network resources.

### LFI (Local File Inclusion)

- **Description**: The Ray framework may include functions that improperly handle file paths, allowing attackers to include files located elsewhere on the server.
- **Impact**: This vulnerability can lead to the disclosure of sensitive information if system files or other files with sensitive data are read.

### SSRF (Server-Side Request Forgery)

- **Description**: Ray may be vulnerable to SSRF attacks where an attacker could abuse the functionality of the server to read or update internal resources.
- **Impact**: Attackers may leverage SSRF to send requests to internal systems behind the firewall which are not accessible from the external network.

## Utilities

### Metasploit Modules

- **ray_cpuprofile_cmd_injection**: Exploits command injection vulnerabilities within Ray's CPU profiling endpoints.
- **ray_job_rce**: Targets Remote Code Execution vulnerabilities in Ray's job submission features.
- **ray_lfi_static_file**: Utilizes Local File Inclusion vulnerabilities to read static files from the Ray server.

### CSRF Templates

- **ray-cmd-injection-csrf.html**: Demonstrates CSRF vulnerabilities that can lead to command injection in Ray.
- **ray-job-rce-csrf.html**: Shows how CSRF can be used to achieve Remote Code Execution by submitting a job in Ray.

### Nuclei Templates

- **ray-cpuprofile-cmd-injection**: Identifies command injection flaws in Ray's CPU profiling features.
- **ray-job-rce**: Scans for Remote Code Execution vulnerabilities within Ray's job management system.
- **ray-log-lfi**: Identifies Local File Inclusion vulnerabilities via log files in Ray.
- **ray-static-lfi**: Detects Local File Inclusion vulnerabilities within static file serving in Ray.

## Reports

- **Sierra Haex & @DanMcInerney**: https://huntr.com/bounties/d0290f3c-b302-4161-89f2-c13bb28b4cfe/
- **@DanMcInerney**: https://huntr.com/bounties/83dd8619-6dc3-4c98-8f1b-e620fedcd1f6/
- **@DanMcInerney**: https://huntr.com/bounties/5039c045-f986-4cbc-81ac-370fe4b0d3f8/

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.
