# Flask/FastAPI Vulnerabilities and Exploits

Flask and FastAPI are vulnerable to a Regex Denial of Service (ReDoS).
The request needs to be submitted to a POST API endpoint that attempts the read the request body.

FastAPI is only vulnerable when processing Form data and not JSON.

## Vulnerabilities

### ReDOS

- **Description**: FastAPI < 0.109.0 is vulnerable to a ReDoS when preocessing form data. Flask is still vulnerable.
- **Impact**: An attacker could send a custom-made `Content-Type` option that is very difficult for the RegEx to process, consuming CPU resources.

## Reports

- **@nicecatch2000**: https://huntr.com/bounties/6745259d-d16e-4fe5-97fe-113b64d6134f/

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.