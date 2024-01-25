# NVIDIA Triton Vulnerabilities & Exploits

## Overview

Triton Inference Server is an open source inference serving software that streamlines AI inferencing. Triton enables teams to deploy any AI model from multiple deep learning and machine learning frameworks, including TensorRT, TensorFlow, PyTorch, ONNX, OpenVINO, Python, RAPIDS FIL, and more.

## Vulnerabilities

See this [blog](https://protectai.com/threat-research/triton-inference-server-arbitrary-file-overwrite) for a more in-depth technical description of the vulnerabilities.

### Metasploit Modules

- **triton_file_write**: Exploits a file overwrite vulnerability when Triton is started with the non-default ```--model-control explicit``` flag
- **triton_model_rce**: Allows you to obtain remote code execution on the server hosting Triton by (ab)using it's Python model backend when Triton is started with the non-default ```--model-control explicit``` flag

## Reports
- **l1k3beef**: https://huntr.com/bounties/b27148e3-4da4-4e12-95ae-756d33d94687/

## Disclaimer

The vulnerabilities and associated exploits provided in this repository are for educational and ethical security testing purposes only.

## Contribution

Contributions to improve the exploits or documentation are welcome. Please follow the contributing guidelines outlined in the repository.

## License

All exploits and templates in this repository are released under the Apache 2.0 License.
