#!/bin/bash 

sudo passwd kali

sudo apt-get update && sudo apt-get upgrade  -y

ssh-keygen -t ed25519 -C "richardcurteis@gmail.com"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

cat ~/.ssh/id_ed25519.pub

read -p "Copy pubkey to git... "

sudo apt install curl  -y
sudo apt install git  -y
sudo apt install wget  -y
sudo wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar
sudo mv jython-standalone-2.7.2.jar /opt/jython-standalone-2.7.2.jar
sudo apt install tmux -y
sudo apt install rlwrap  -y
sudo apt install netcat ncat  -y
sudo apt install python3-pip  -y
sudo apt install flameshot  -y
sudo apt install zip  -y
sudo apt install virtualenv  -y
sudo apt-get install jq  -y
sudo apt-get install telnet  -y
sudo apt-get install npm  -y

sudo apt-get install -y libssl-dev libffi-dev python-dev build-essential  -y
sudo apt-get install mingw-w64 binutils-mingw-w64 g++-mingw-w64 -y

wget https://golang.org/dl/go1.17.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.17.3.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

sudo service postgresql start
sudo msfdb init

curl https://gist.githubusercontent.com/prachauthit/595cd3596267b303cc77fe0409c33530/raw/9de5070df1fb1adfc2f6db2b4966c516ec931700/ippsec-tmux -o ~/.tmux.conf

curl https://gist.githubusercontent.com/richardcurteis/66777e446d23ca3b4bfc622f85b7a2d7/raw/28b7e048eab3b392dddff605250384a5a9917546/python-https-simple-server.py -o simple-https-server.py 
mkdir SimpleHTTPSServer
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
mv simple-https-server.py SimpleHTTPSServer/simple-https-server.py
mv server.pem SimpleHTTPSServer/server.pem

wget https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64
sudo dpkg -i code_1.59.0-1628120042_amd64.deb

wget https://launchpad.net/~giuspen/+archive/ubuntu/ppa/+build/21797903/+files/cherrytree_0.99.39-4_amd64.deb
sudo  dpkg -i  cherrytree_0.99.39-4_amd64.deb

wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.2/jython-standalone-2.7.2.jar
sudo mv jython-standalone-2.7.2.jar /opt/jython-standalone-2.7.2.jar

mkdir ~/repos
cd ~/repos
git clone git@github.com:pwntester/ysoserial.net.git
git clone git@github.com:frohoff/ysoserial.git
git clone git@github.com:danielmiessler/SecLists.git
git clone git@github.com:SecureAuthCorp/impacket.git
git clone git@github.com:swisskyrepo/PayloadsAllTheThings.git
git clone git@github.com:GrrrDog/Java-Deserialization-Cheat-Sheet.git
git clone git@github.com:Realize-Security/MaliciousWordpressWebshell.git
git clone git@github.com:richardcurteis/TLS_SSL_Checks_sh.git
git clone git@github.com:richardcurteis/password_spraying.git
git clone git@github.com:richardcurteis/goBrute.git

git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
poetry install
cd ../../

git clone git@github.com:BishopFox/sliver.git
sudo mv sliver /opt
cd /opt/sliver
./go-assets.sh
make
cd /home/kali

cp /usr/share/wordlists/rockyou.gz .
gunzip gunzip rockyou.gz/rockyou.gz
mv /usr/share/wordlists/rockyou.txt ~/repos

wget https://github.com/ffuf/ffuf/releases/download/v1.3.1/ffuf_1.3.1_linux_amd64.tar.gz
gunzip ffuf_1.3.1_linux_amd64.tar.gz
tar xvf ffuf_1.3.1_linux_amd64.tar
mv ffuf_1.3.1_linux_amd64/ffuf /opt/ffuf
sudo rm -rf /usr/bin/ffuf
sudo ln -s /opt/ffuf /usr/bin/ffuf

wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
sudo mv aquatone_linux_amd64_1.7.0/aquatone /opt/aquatone
sudo ln -s /opt/aquatone /usr/bin/aquatone

sudo apt-get update; \
  sudo apt-get install -y apt-transport-https && \
  sudo apt-get update -y && \
  sudo apt-get install -y dotnet-sdk-5.0


pip3 install requests
pip3 install flask

USER=`whoami`
sudo chown -R $USER:$USER .
chown -R $USER:$USER /opt

sudo apt autoremove -y
