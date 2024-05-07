# BentoML Vulnerabilities and Exploits

BentoML is a model serving framework that offers a unified standard for AI inference, model packaging, and serving optimizations.

## Vulnerabilities

### Remote Code Execution

- **Description**: BentoML < 1.2.5 is vulnerable to RCE via Python object deserialization.
- **Impact**: This vulnerability could allows an attacker to gain Remote Code Execution on the server running the BentoML inference server.

## Reports

- **@pinkdraconian**: https://huntr.com/bounties/349a1cce-6bb5-4345-82a5-bf7041b65a68

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.