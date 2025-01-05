sudo ifconfig mon0 down
sudo iw dev mon0 del
sudo ifconfig wlx00c0cab67f3d down
sudo iw dev wlx00c0cab67f3d set type monitor
sudo iw wlx00c0cab67f3d interface add mon0 type monitor
sudo ifconfig mon0 up
