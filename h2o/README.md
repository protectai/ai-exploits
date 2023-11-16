# H2O Vulnerabilities and Exploits

## Overview
H2O-3 is a low-code machine learning platform that enables data scientists and analysts to build and deploy machine 
learning models using an easy web interface by just importing their data. A default, out of the box installation has no 
authentication and is exposed to the network.

## Vulnerabilities

### CSRF (Cross-Site Request Forgery)

- **Description**: H2O is vulnerable to CSRF due to the lack of proper CSRF protection. Attackers can exploit this vulnerability to perform unwanted actions on a web application in which the user is currently authenticated.
- **Impact**: This could lead to unauthorized actions being taken on behalf of the authenticated user.

### RCE (Remote Code Execution)

- **Description**: H2O allows the importation of POJO models which are Java code objects. This can be exploited to execute arbitrary Java code on the server, leading to Remote Code Execution (RCE).
- **Impact**: Since H2O does not require authentication by default and is exposed to the network, it can be compromised remotely, allowing an attacker to take full control of the server.

### LFI (Local File Inclusion)

- **Description**: There is a Local File Inclusion (LFI) vulnerability in H2O, where a remote API call can be made to read the entire file system on the server.
- **Impact**: This vulnerability allows an attacker to read sensitive files from the server, leading to information disclosure and potentially further exploitation.

## Utilities

### Metasploit Modules

- **h2o_pojo_import_rce**: Exploits the RCE vulnerability to gain a remote shell on the server.
- **h2o_importfiles_lfi**: Exploits the LFI vulnerability to read files from the server's file system.
- **h2o_typeahead_api**: Exploits the ability of H2O to list files and folders on the vulnerable server.

### CSRF Template

- **h2o-rce-csrf** - A pre-crafted HTML template that can be used to demonstrate the CSRF to RCE vulnerability in H2O.

### Nuclei Template

- **h2o-importfiles-lfi**: Identifies LFI vulnerabilities through the import files functionality in H2O.
- **h2o-apl**: Scans for the arbitrary path lookup endpoints in H2O.
- **h2o-dashboard**: Looks for H2O dashboard endpoints that may be unprotected.
- **h2o-pojo-rce**: Scans for the RCE vulnerability via POJO model importation in H2O.

## Reports

 - **@DanMcInerney** - https://huntr.com/bounties/380fce33-fec5-49d9-a101-12c972125d8c/
 - **@p0cas** - https://huntr.com/bounties/9881569f-dc2a-437e-86b0-20d4b70ae7af/
 - **Sierra Haex** - https://huntr.com/bounties/83dd17ec-053e-453c-befb-7d6736bf1836/

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.