#include <tins/tins.h>
#include <chrono>

#include "packet_sniff.h"

using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

MySniffer::MySniffer(const string &iface) :cur_tf(nullptr), pkt_count(0) {
    // time_minheap = priority_queue<pair<address_type, time_point<high_resolution_clock>>, vector<pair<address_type, time_point<high_resolution_clock>>>, MySniffer>(*this);
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);
    config.set_rfmon(true);

    Sniffer sniffer(iface, config);
    // FileSniffer sniffer("/home/litonglab/Downloads/file.cap");
    sniffer.sniff_loop(make_sniffer_handler(this, &MySniffer::callback));
}

MySniffer::~MySniffer() {
    for (auto i = duration_records.begin(); i != duration_records.end(); i++) 
        cout << i->addr << " last " << duration_cast<chrono::microseconds>(i->end - i->start).count() << " us." << endl;
}

auto& MySniffer::get_addr_set() {
    return this->addr_set;
}

auto& MySniffer::get_time_heap() {
    return this->time_minheap;
}

bool MySniffer::start_record_duration(address_type addr) {
    if (cur_tf)
        return false;
    cur_tf = new TransferDuration(addr, chrono::high_resolution_clock::now());
    return true;
}

bool MySniffer::try_end_record_duration() {
    if (!cur_tf)
        return false;
    cur_tf->end = chrono::high_resolution_clock::now();
    duration_records.push_back(std::move(*cur_tf));
    cur_tf = nullptr;
    return true;
}

bool MySniffer::callback(PDU &pdu) {
    const Dot11& dot11_header = pdu.rfind_pdu<Dot11>();
    const uint8_t dot11_type = dot11_header.type();
    const RadioTap &radio = pdu.rfind_pdu<RadioTap>();
    ++pkt_count;
    if (pkt_count > 100000)
        return false;

    switch (dot11_type) {
        case 0:
            mangement_handler(dot11_header, radio);
            break;
        case 1:
            control_handler(dot11_header, radio);
            break;
        case 2:
            data_handler(dot11_header, radio);
            break;
        default:
            cout << "Novalid packet: " << dot11_type << endl;
            break;
    }
    return true;
}

void MySniffer::mangement_handler(const Dot11& pdu, const RadioTap& radio) {
    const uint8_t dot11_subtype = pdu.subtype();
    const Dot11ManagementFrame &manage_frame = pdu.rfind_pdu<Dot11ManagementFrame>();
    if (cur_tf && (manage_frame.addr1() == SNIFF_ADDR || manage_frame.addr2() == SNIFF_ADDR || manage_frame.addr3() == SNIFF_ADDR))
        try_end_record_duration();
    RadioTap::PresentFlags flags = radio.present();
    if ((flags & RadioTap::RATE) && (flags & RadioTap::ANTENNA)) {
        uint8_t rate = radio.rate();
// #ifdef DEBUG
//         if (rate)
//             cout << "Rate in radio is: " << to_string(rate/2)
//                 << ". Antenna is: " << to_string(radio.antenna())
//                 //  << ". MCS is: " << radio.mcs().mcs 
//                 << ". manage subtype: " << to_string(dot11_subtype)
//                 << endl;
// #endif
    }
    switch(dot11_subtype) {
        default:
            break;
    }
}

void MySniffer::control_handler(const Dot11 &pdu, const RadioTap& radio) {
    const uint8_t &dot11_subtype = pdu.subtype();
    const Dot11Control &control_frame = pdu.rfind_pdu<Dot11Control>();
    if (control_frame.addr1() == SNIFF_ADDR)
        try_end_record_duration();
    if (dot11_subtype == 11) { // 11 represents to RTS frame
        const Dot11RTS &rts_frame = control_frame.rfind_pdu<Dot11RTS>();
        // addr1()--> dst addr, target--> src
        // cout << "Got RTS frame " << rts_frame.addr1() << " " << rts_frame.target_addr() << endl;
        if (rts_frame.addr1() == SNIFF_ADDR) {
            start_record_duration(rts_frame.target_addr());
        } else if (rts_frame.target_addr() == SNIFF_ADDR) {
            start_record_duration(rts_frame.addr1());
        }
    }    
}

static void remove_expired_records(MySniffer &snif) {
    auto t_now = chrono::high_resolution_clock::now();
    auto &time_heap = snif.get_time_heap();
    auto &addr_set = snif.get_addr_set();
    while (!time_heap.empty())
    {
        auto &temp = time_heap.top();
        int64_t time_diff = chrono::duration_cast<chrono::microseconds>(t_now-temp.start).count();
        if (time_diff >= EXPERIED_TIME) {
            addr_set.erase(addr_set.find(temp.addr));
            time_heap.pop();
        }
        else
            break;
    }
}

void MySniffer::data_handler(const Dot11 &pdu, const RadioTap& radio) {
    const uint8_t &dot11_subtype = pdu.subtype();
    const Dot11Data &data_frame = pdu.rfind_pdu<Dot11Data>();
    // const RadioTap::mcs_type &tempmsc = radio.mcs();
    RadioTap::PresentFlags flags = radio.present();
    
    if (data_frame.bssid_addr() == SNIFF_ADDR) {
        if (cur_tf && cur_tf->addr != data_frame.src_addr() && cur_tf->addr != data_frame.dst_addr())
            try_end_record_duration();
        remove_expired_records(*this);
        time_minheap.emplace(data_frame.src_addr(), chrono::high_resolution_clock::now());
        addr_set.insert(data_frame.src_addr());
        // cout << "There are " << addr_set.size() << " in 1ms." <<endl;
        // addr_set.insert(data_frame.dst_addr());
        if ((flags & RadioTap::RATE) && (flags & RadioTap::ANTENNA)) {
            uint8_t rate = radio.rate();
            if (!rate) {
                cout << to_string(dot11_subtype) << "not have rate, its header size is: " << radio.header_size() << endl;
            }
#ifdef DEBUG
            if (rate)
            cout << "Rate in radio is: " << to_string(rate/2)
                << ". Antenna is: " << to_string(radio.antenna())
                //  << ". MCS is: " << radio.mcs().mcs 
                << ". data subtype: " << to_string(dot11_subtype)
                << endl;
#endif
        }
#ifdef DEBUG
        cout << "SA: " << data_frame.src_addr() << endl
         << "DA: " << data_frame.dst_addr() << endl
         << "BSSID: " << data_frame.bssid_addr() << endl
         << "Addr1: " << data_frame.addr1() << endl
         << "Addr2: " << data_frame.addr2() << endl
         << "Addr3: " << data_frame.addr3() << endl;
    
    if (!addr_set.empty())
        for (auto i = addr_set.begin(); i != addr_set.end(); i++)
            cout << *i << " in address set." << endl;
#endif
    }
}

int main() {
    MySniffer mysniffer("mon0");
    return 0;
}