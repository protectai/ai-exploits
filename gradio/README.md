# Gradio Vulnerabilities and Exploits

Gradio is the fastest way to demo your machine learning model with a friendly web interface so that anyone can use it.

## Vulnerabilities

### Local File Inclusion

- **Description**: Gradio < 4.3.0 is vulnerable to an LFI in the `/component_server` API endpoint.
- **Impact**: This vulnerability allows an attacker to read files off the filesystem remotely.

## Reports

- **@ozelis**: https://huntr.com/bounties/4acf584e-2fe8-490e-878d-2d9bf2698338

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.