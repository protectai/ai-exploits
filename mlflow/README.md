# MLflow Vulnerabilities and Exploits

## Overview
MLflow is an open-source platform for managing the end-to-end machine learning lifecycle. It includes tools for tracking experiments, packaging code into reproducible runs, and sharing and deploying models. By default, MLflow lacks authentication.

## Vulnerabilities

### Arbitrary File Write

- **Description**: MLflow is vulnerable to unauthorized file writes through its artifact logging API. This can be exploited by an attacker to write files to arbitrary locations on the server hosting MLflow.
- **Impact**: This vulnerability could allow an attacker to overwrite system files or place malicious files on the server, potentially leading to code execution or other malicious activities. Example would be overwriting the SSH keys to gain access to the server.

### LFI (Local File Inclusion)

- **Description**: MLflow's API for retrieving model versions and registered models does not properly sanitize user input, leading to LFI vulnerabilities. This allows an attacker to read files from the server's filesystem.
- **Impact**: Attackers can exploit this to read sensitive files from the server, potentially leading to information disclosure and system compromise.

## Utilities

### Metasploit Modules

- **mlflow_file_write**: Exploits the arbitrary file write vulnerability to write files on the server.

### Nuclei Templates

- **mlflow-file-write**: Scans for vulnerabilities that allow unauthorized file writes in MLflow.
- **mlflow-model-versions-lfi**: Detects Local File Inclusion vulnerabilities in MLflow's model versions endpoint.

## Reports

 - **@DanMcInerney** - https://huntr.com/bounties/1fe8f21a-c438-4cba-9add-e8a5dab94e28/
 - **@kevin-mizu** - https://huntr.com/bounties/7cf918b5-43f4-48c0-a371-4d963ce69b30/
 - **Sierra Haex** - https://huntr.com/bounties/3e64df69-ddc2-463e-9809-d07c24dc1de4/
 - **@haxatron** - https://huntr.com/bounties/43e6fb72-676e-4670-a225-15d6836f65d3/
 - **@DanMcInerney** - https://huntr.com/bounties/ae92f814-6a08-435c-8445-eec0ef4f1085/

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.