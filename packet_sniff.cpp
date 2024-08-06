#include <tins/tins.h>
#include <chrono>
#include <json/json.h>

#include "packet_sniff.h"

using namespace std;
using namespace Tins;

typedef Dot11::address_type address_type;

MySniffer::MySniffer(const string &iface) :cur_tf(nullptr), pkt_count(0), rate(0), active_user_number(0), writer(WRITE_FILE, DataLinkType<RadioTap>()) {
    SnifferConfiguration config;
    config.set_immediate_mode(true);
    config.set_promisc_mode(true);
    config.set_rfmon(true);

    Sniffer sniffer(iface, config);
    // FileSniffer sniffer(INPUT_PCAP_FILE);
    sniffer.sniff_loop(make_sniffer_handler(this, &MySniffer::callback));
}

MySniffer::~MySniffer() {
    if (rate_fs.is_open())
        rate_fs.close();
    if (users_fs.is_open())
        users_fs.close();
    if (occupancy_fs.is_open())
        occupancy_fs.close();
#ifdef DEBUG
    for (auto i = duration_records.begin(); i != duration_records.end(); i++) 
        cout << i->addr << "transfer from " << i->start_pkt_no << " to " << i->end_pkt_no << ", last " << duration_cast<chrono::microseconds>(i->end - i->start).count() << " us." << endl;
#endif
}

auto& MySniffer::get_addr_set() {
    return this->addr_set;
}

auto& MySniffer::get_time_heap() {
    return this->time_minheap;
}

unordered_map<address_type, microseconds> MySniffer::get_airtime() {
    auto t_now = chrono::high_resolution_clock::now();
    unordered_map<address_type, microseconds> statistics;
    bool single_user = false;
    active_user_number = 0;
    active_users.clear();
    if (cur_tf) {
        auto cur_tf_duration = duration_cast<microseconds>(t_now-cur_tf->start).count();
        if (cur_tf_duration > AIRTIME_WINDOW) {
            single_user = true;
            cur_tf_duration = AIRTIME_WINDOW;
        }
        if (cur_tf_duration > 0) {
            ++active_user_number;
            active_users.emplace(cur_tf->addr);
            statistics[cur_tf->addr] = microseconds(cur_tf_duration);
        }
    }
    if (!single_user) {
        for (auto i = duration_records.rbegin(); i!= duration_records.rend(); i++) {
            auto temp_duration = duration_cast<microseconds>(t_now-i->end).count();
            auto window_left = t_now-microseconds(AIRTIME_WINDOW);
            if (temp_duration > AIRTIME_WINDOW)
                break;
            else {
                if (active_users.find(i->addr) == active_users.end())
                    ++active_user_number;
                active_users.emplace(i->addr);
                auto dur = duration_cast<microseconds>(i->end-window_left);
                if (i->start > window_left)
                    dur = duration_cast<microseconds>(i->end-i->start);
                if (dur.count() <= 0)
                    continue;
                if (statistics.find(i->addr) != statistics.end())
                    statistics[i->addr] += dur;
                else
                    statistics[i->addr] = dur;
            }
        }
    }
    return statistics;
}

void MySniffer::write_airtime() {
    auto statistics = get_airtime();
    double avg_rate = (double)(active_user_number > 0 ? rate/active_user_number : rate);
#ifdef DEBUG
    cout << "rate: " << avg_rate
        << ", active_user_number: " << active_user_number;
        // << ", active_user: " << active_users
#endif
    users_fs.open(USERS_FILE, ios::out);
    users_fs << active_user_number;
    users_fs.close();
    Json::Value temp_rate_map;
    Json::Value occupy;
    for (auto i = statistics.begin(); i != statistics.end(); i++) {
        auto key = i->first.to_string();
        if (rate_map.find(key) != rate_map.end())
            temp_rate_map[key] = (double)(active_user_number > 0 ? rate_map[key]/active_user_number : rate_map[key]);
        occupy[key] = ((double)(i->second.count())/AIRTIME_WINDOW)*100;
    }
    Json::FastWriter writer;
    if (!occupy.empty()) {
        occupancy_fs.open(OCCUPANCY_FILE, ios::out);
        occupancy_fs << writer.write(occupy);
        occupancy_fs.close();
    }
    if (!temp_rate_map.empty()) {
        rate_fs.open(RATE_FILE, ios::out);
        rate_fs << writer.write(temp_rate_map);
        rate_fs.close();
    }
#ifdef DEBUG
    cout << ". Airtime occupation: "
         << occupy.toStyledString() << endl;
#endif
}

bool MySniffer::start_record_duration(address_type addr) {
    if (cur_tf)
        if (cur_tf->addr == addr) {
            cur_tf->start = chrono::high_resolution_clock::now();
            cur_tf->start_pkt_no = pkt_count;
            return true;
        }
        else 
            return false;
    cur_tf = new TransferDuration(addr, chrono::high_resolution_clock::now());
    cur_tf->start_pkt_no = pkt_count;
    return true;
}

bool MySniffer::try_end_record_duration() {
    if (!cur_tf)
        return false;
    cur_tf->end = chrono::high_resolution_clock::now();
    cur_tf->end_pkt_no = pkt_count;
    duration_records.push_back(std::move(*cur_tf));
    cur_tf = nullptr;
    return true;
}

bool MySniffer::callback(PDU &pdu) {
    const Dot11& dot11_header = pdu.rfind_pdu<Dot11>();
    const uint8_t dot11_type = dot11_header.type();
    const RadioTap &radio = pdu.rfind_pdu<RadioTap>();
    ++pkt_count;

#ifdef TEST
    if (pkt_count > 1000000)
        return false;
    writer.write(pdu);
#endif

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
    write_airtime();
    return true;
}

void MySniffer::mangement_handler(const Dot11& pdu, const RadioTap& radio) {
    const uint8_t dot11_subtype = pdu.subtype();
    const Dot11ManagementFrame &manage_frame = pdu.rfind_pdu<Dot11ManagementFrame>();
    if (cur_tf && (manage_frame.addr1() == SNIFF_ADDR || manage_frame.addr2() == SNIFF_ADDR || manage_frame.addr3() == SNIFF_ADDR))
        try_end_record_duration();
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
    RadioTap::PresentFlags flags = radio.present();
    
    if (data_frame.bssid_addr() == SNIFF_ADDR) {
        if (cur_tf && cur_tf->addr != data_frame.src_addr() && cur_tf->addr != data_frame.dst_addr())
            try_end_record_duration();
        remove_expired_records(*this);
        time_minheap.emplace(data_frame.src_addr(), chrono::high_resolution_clock::now());
        addr_set.insert(data_frame.src_addr());
        if (flags & RadioTap::HE) { // HE information is present
            RadioTap::he_type he_info = radio.he();
            unsigned mcs_index = ((he_info.data3 & 0x0F00) >> 8);
            unsigned ru_alloc = he_info.data5 & 0x000F;
            /* RU allocation value
            0: 20, 1: 40, 2: 80, 3: 160/80+80, 
            4: 26tone RU, 5: 52tone RU, 6: 106-tone RU, 7: 242-tone RU, 
            8: 484-tone RU, 9: 996-tone RU, 10: 2x996-tone RU
            */
            unsigned gi = ((he_info.data5 & 0x0030) >> 4); // 0: 0.8us, 1: 1.6us, 2: 3.2us, 3: reserved
            unsigned ss_num = he_info.data6 & 0x000F; // 0: unknown, 1: 1, etc..
            if (ss_num != 0 && (gi >= 0 && gi < 3) && (ru_alloc >= 0 && ru_alloc <= 10) && (mcs_index >= 0 && mcs_index <= 11)) {
                rate = ss_num * IEEE80211AX_MCS_TABLE[mcs_index][ru_alloc][gi];
                rate_map[data_frame.src_addr()] = rate;
#ifdef DEBUG
                cout << "Get rate " << rate <<" from 802.11ax packet: " << pkt_count << ", mcs_index: " << mcs_index << ", ru_alloc: " << ru_alloc << ", gi: " << gi << ", ss_num: " << ss_num << endl;
#endif
            }
        } else if ((flags & RadioTap::RATE) && (flags & RadioTap::ANTENNA)) {
            uint8_t temp_rate = radio.rate();
            // 8-11 refer to QosData frame
            if (dot11_subtype >= 8 && dot11_subtype <= 11) {
                rate = temp_rate/2;
                rate_map[data_frame.src_addr()] = rate;
            }
#ifdef DEBUG
            if (temp_rate)
                cout << "Rate in radiotap is: " << to_string(temp_rate/2)
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
    MySniffer mysniffer(SNIFF_IFACE);
    return 0;
}