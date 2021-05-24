# on master
sudo yum -y install git
sudo python3 -m pip install boto3
sudo python3 -m pip install pyspark
sudo python3 -m pip install --upgrade pyyaml
sudo chmod -R 777 /tmp
git clone https://github.com/gregrahn/tpch-kit
cd ~/tpch-kit/dbgen
make
cd ~
git clone https://github.com/PasaLab/OLAPBenchmark

# on slaves
sudo yum -y install git
git clone https://github.com/PasaLab/OLAPBenchmark

# on all machines
sudo yum -y install collectd
wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
sudo rpm -U ./amazon-cloudwatch-agent.rpm

# on master
cd ~/OLAPBenchmark
python3 main.py generate

# on all machines
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/home/hadoop/OLAPBenchmark/cloud/cwaconfig.json

# on master
cd ~/OLAPBenchmark
python3 main.py run

# on all machines
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a stop
