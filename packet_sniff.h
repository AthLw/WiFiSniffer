#ifndef __MY_PACKET_SNIFF__
#define __MY_PACKET_SNIFF__

#include <chrono>
#include <iostream>
#include <string>
#include <tins/tins.h>
#include <unordered_set>
#include <queue>

using namespace Tins;
using namespace std;
using namespace chrono;

typedef Dot11::address_type address_type;
#define SNIFF_ADDR "4c:10:d5:3b:bf:0f"
#define EXPERIED_TIME 1000 // 1ms

struct TransferDuration {
    address_type addr;
    time_point<high_resolution_clock> start;
    time_point<high_resolution_clock> end;
    TransferDuration(address_type addr, time_point<high_resolution_clock> t_now):addr(addr),start(t_now) {};
};

struct COMP {
    bool operator()(TransferDuration &p1, TransferDuration &p2) {
        return p1.start != p2.start ? p1.start > p2.start : p1.end > p2.end;
    }
};

class MySniffer {
public:
    MySniffer(const string &iface);
    ~MySniffer();
    bool callback(PDU &pdu);
    auto& get_addr_set();
    auto& get_time_heap();
    bool start_record_duration(address_type addr);
    bool try_end_record_duration();
private:
    void mangement_handler(const Dot11& pdu, const RadioTap& radio);
    void data_handler(const Dot11 &pdu, const RadioTap& radio);
    void control_handler(const Dot11 &pdu, const RadioTap& radio);
    int64_t pkt_count;
    TransferDuration *cur_tf;
    vector<TransferDuration> duration_records;
    unordered_multiset<address_type> addr_set;
    priority_queue<TransferDuration, vector<TransferDuration>, COMP> time_minheap;
};

#endif