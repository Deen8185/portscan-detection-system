#!/usr/bin/env bash
# One-time installation of the lab software inside Ubuntu (WSL). Run as root:
#     sudo bash lab/install_lab.sh
#
# Target services: vsftpd (FTP, 21), OpenSSH (22), nginx (HTTP, 80),
# MariaDB (MySQL, 3306). Capture and scanning: tcpdump, nmap.
# Normal-traffic clients: curl, ssh, mariadb client, lftp.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq tcpdump nmap openssh-server nginx mariadb-server vsftpd \
    curl lftp sshpass nftables python3-venv python3-pip unzip

# Python CICFlowMeter, used to turn captures into flow records
python3 -m venv /opt/cicflowmeter
/opt/cicflowmeter/bin/pip install -q cicflowmeter==0.5.0

# MariaDB must listen on the lab network, not only on 127.0.0.1
sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' /etc/mysql/mariadb.conf.d/50-server.cnf

# A lab-only user for normal FTP, SSH and database sessions
id labuser >/dev/null 2>&1 || useradd -m -s /bin/bash labuser
echo 'labuser:lab-only-password' | chpasswd
mysql -e "CREATE DATABASE IF NOT EXISTS campus; \
          CREATE USER IF NOT EXISTS 'labuser'@'%' IDENTIFIED BY 'lab-only-password'; \
          GRANT ALL ON campus.* TO 'labuser'@'%'; FLUSH PRIVILEGES;"
echo "<h1>Department intranet (lab)</h1>" > /var/www/html/index.html
mkdir -p /var/www/html/files /home/labuser/shared
for f in timetable notes report; do
    head -c $(( (RANDOM % 900 + 100) * 1024 )) /dev/urandom > "/var/www/html/files/$f.pdf"
    cp "/var/www/html/files/$f.pdf" "/home/labuser/shared/$f.pdf"
done
chown -R labuser:labuser /home/labuser/shared
# Allow FTP uploads for the lab user
sed -i 's/^#\?write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
mysql campus -e "CREATE TABLE IF NOT EXISTS results (id INT AUTO_INCREMENT PRIMARY KEY, student VARCHAR(40), score INT);"

for s in vsftpd ssh nginx mariadb; do systemctl enable --now "$s" >/dev/null; systemctl restart "$s"; done
echo "Installed. Now run: sudo bash lab/setup_lab.sh"
