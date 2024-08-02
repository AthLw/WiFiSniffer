#ifndef __MY_PACKET_SNIFF__
#define __MY_PACKET_SNIFF__

#include <chrono>
#include <fstream>
#include <iostream>
#include <string>
#include <tins/tins.h>
#include <unordered_set>
#include <unordered_map>
#include <queue>

using namespace Tins;
using namespace std;
using namespace chrono;

typedef Dot11::address_type address_type;
#define SNIFF_ADDR "4c:10:d5:3b:bf:0f"
#define EXPERIED_TIME 1000 // 1ms
#define AIRTIME_WINDOW 100000 //100ms
#define RATE_FILE "Rate.txt"
#define USERS_FILE "Users.txt"
#define OCCUPANCY_FILE "Occupancy.json"

struct AirtimeOccupy {
    address_type addr;
    chrono::microseconds airtime;
    AirtimeOccupy(address_type addr, microseconds air): addr(addr), airtime(air) {}
};

struct TransferDuration {
    address_type addr;
    time_point<high_resolution_clock> start;
    time_point<high_resolution_clock> end;
    int64_t start_pkt_no;
    int64_t end_pkt_no;
    TransferDuration(address_type addr, time_point<high_resolution_clock> t_now):addr(addr),start(t_now),start_pkt_no(0),end_pkt_no(0) {};
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
    unordered_map<address_type ,microseconds> get_airtime();
    void write_airtime();
private:
    void mangement_handler(const Dot11& pdu, const RadioTap& radio);
    void data_handler(const Dot11 &pdu, const RadioTap& radio);
    void control_handler(const Dot11 &pdu, const RadioTap& radio);
    int64_t pkt_count;
    unsigned rate;
    TransferDuration *cur_tf;
    vector<TransferDuration> duration_records;
    unordered_set<address_type> active_users;
    unsigned active_user_number;
    unordered_multiset<address_type> addr_set;
    priority_queue<TransferDuration, vector<TransferDuration>, COMP> time_minheap;
    PacketWriter writer;
    fstream rate_fs;
    fstream users_fs;
    fstream occupancy_fs;
};

#endif