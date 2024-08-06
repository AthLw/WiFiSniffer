# About

This is a testbed used to sniff wifi packets, including WiFi6(802.11ax). And We can also record serveral users' airtime occupancy.

This project is dependant on [libtins](https://github.com/mfontanini/libtins), and we modify it to support parsing 802.11 frame.

# Install

### Dependancy

We have run this program in Ubuntu 20.04.

1. libtins

https://github.com/mfontanini/libtins

2. jsoncpp

https://github.com/open-source-parsers/jsoncpp

3. matplotlib

pip install matplotlib

### Install

```shell
bash ./install.sh
```

> Note: Before running program, you should confirm that the configuration has been modified. The configuration includes `SNIFF_ADDR`, `SNIFF_IFACE` and `AIRTIME_WINDOW` in `Constant.h` file. And `max_users` in `plot_airtime.py` could be changed, but the max users in our program should not exceed 10.(which is determined by the number of predefine colors.)

### Run

```shell
bash ./run.sh
```

# Other issues

1. WiFi sniffer uses file to interact with python plot script in this testbed, because it doesn't need too low latency now. We will take `shared memory` for consideration if necessarily.