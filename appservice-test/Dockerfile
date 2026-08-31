FROM python:3.11-slim
RUN apt-get update && apt-get install -y openssl curl openssh-server && \
    mkdir -p /var/run/sshd && \
    echo 'root:Docker!' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
EXPOSE 2222 80
CMD ["/bin/sh", "-c", "service ssh start && tail -f /dev/null"]
