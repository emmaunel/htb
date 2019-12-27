## s/o to https://github.com/hilalh/docker-kali-pentest/blob/master/Dockerfile

FROM kalilinux/kali-linux-docker
ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm-256color

# do APT update
RUN apt-get -y update && apt-get -y dist-upgrade && apt-get -y autoremove && apt-get clean
# install system essentials
RUN apt-get install build-essential curl file git openvpn bridge-utils kali-linux-nethunter net-tools seclists zsh -y
RUN apt-get install sudo -y

ARG PASSWORD

# create a new user
RUN adduser --quiet --disabled-password --shell /bin/bash --home /home/noob --gecos "User" noob
RUN echo "noob:${PASSWORD}" | chpasswd
RUN usermod -aG sudo noob

# switch to new user
USER noob
WORKDIR /home/noob

# copy necessary files for VPN and tunneling
COPY *.ovpn tunnel.sh ./