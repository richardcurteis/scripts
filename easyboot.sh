apt-get update && apt-get upgrade 

apt install curl
apt install wget

apt-get install -y libssl-dev libffi-dev python-dev build-essential

wget https://golang.org/dl/go1.16.7.linux-amd64.tar.gz
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.7.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

service postgresql start
msfdb init

apt install tmux
apt install rlwrap
apt install netcat nc ncat
apt install python3-pip
apt install openjdk-8-jre
apt install flameshot
apt install zip
apt install virtualenv
apt-get install jq


curl https://gist.githubusercontent.com/prachauthit/595cd3596267b303cc77fe0409c33530/raw/9de5070df1fb1adfc2f6db2b4966c516ec931700/ippsec-tmux -o .tmux.conf

curl https://gist.githubusercontent.com/dergachev/7028596/raw/abb8bd2b53501ff7125b93e8d975e77ffd756bf1/simple-https-server.py -o simple-https-server.py 
mkdir SimpleHTTPSServer
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
mv simple-https-server.py SimpleHTTPSServer/simple-https-server.py
mv server.pem SimpleHTTPSServer/server.pem

wget https://code.visualstudio.com/sha/download?build=stable&os=linux-deb-x64
dpkg -i code_1.59.0-1628120042_amd64.deb

wget https://launchpad.net/~giuspen/+archive/ubuntu/ppa/+build/21797903/+files/cherrytree_0.99.39-4_amd64.deb
dpkg -i  cherrytree_0.99.39-4_amd64.deb

ssh-keygen -t ed25519 -C "richardcurteis@gmail.com"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519

git clone git@github.com:pwntester/ysoserial.net.git
git clone git@github.com:frohoff/ysoserial.git
git clone git@github.com:danielmiessler/SecLists.git
git clone git@github.com:SecureAuthCorp/impacket.git
git clone --recursive https://github.com/byt3bl33d3r/CrackMapExec
cd CrackMapExec
poetry install
cd ..

unzip /usr/share/wordlists/rockyou.zip
cp /usr/share/wordlists/rockyou.txt .

wget https://github.com/ffuf/ffuf/releases/download/v1.3.1/ffuf_1.3.1_linux_amd64.tar.gz
gunzip ffuf_1.3.1_linux_amd64.tar.gz
tar xvf ffuf_1.3.1_linux_amd64.tar
mv ffuf_1.3.1_linux_amd64/ffuff /opt/ffuff
ln -s /opt/ffuff /usr/bin/ffuff

wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip aquatone_linux_amd64_1.7.0.zip
mv aquatone_linux_amd64_1.7.0/aquatone /opt/aquatone
ln -s /opt/aquatone /usr/bin/aquatone

apt-get update; \
  sudo apt-get install -y apt-transport-https && \
  sudo apt-get update && \
  sudo apt-get install -y dotnet-sdk-5.0


pip3 install requests
pip3 install flask

chown -R `whoami`:`whoami` .
