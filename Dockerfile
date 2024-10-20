FROM golang:latest

RUN apt-get update \
    && apt-get -y install python3 python3-setuptools python3-pip python3-requests

WORKDIR /root

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall \
    && chmod 755 msfinstall \
    && ./msfinstall

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/opt/metasploit-framework/embedded/framework/lib/msf/core/modules/external/python

COPY **/msfmodules/*.py /root/.msf4/modules/exploits/protectai/
COPY **/nuclei-templates/*.yaml /root/nuclei-templates/
