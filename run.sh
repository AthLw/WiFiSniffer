g++ packet_sniff.cpp -o sniff -ltins -ljsoncpp

sudo touch Rate.json
sudo touch Users.txt
sudo touch Occupancy.json

python plot_airtime.py 1 > /dev/null &
sleep 1

sudo ./sniff
