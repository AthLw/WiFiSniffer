IP=10.77.70.150
PORT=$1

delay=$(ping $IP -t 5 | tail -1 | awk '{print $(NF-1)}' | awk -F '/' '{print $2}')

echo $delay

throughput=$(iperf3 -c $IP -p "$PORT" -t 20 | tail -3 | head -1| awk '{print $(NF-2)}')

echo $throughput


