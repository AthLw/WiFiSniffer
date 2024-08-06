#ifndef __MYSNIFF_CONSTANTS__
#define __MYSNIFF_CONSTANTS__

#define SNIFF_ADDR "4c:10:d5:3b:bf:0f"
#define EXPERIED_TIME 1000 // 1ms
#define AIRTIME_WINDOW 1000000 // 1s
#define RATE_FILE "Rate.json"
#define USERS_FILE "Users.txt"
#define OCCUPANCY_FILE "Occupancy.json"
#define WRITE_FILE "sniffer_records.pcap"
#define INPUT_PCAP_FILE "80211ax.pcap"
#define SNIFF_IFACE "mon0"

double IEEE80211AX_MCS_TABLE[12][10][3] = {
    {
        {8.6, 8.1, 7.3},
        {17.2, 16.3, 14.6},
        {36, 34, 30.6},
        {72.1, 68.1, 61.3},
        {0.9, 0.8, 0.8},
        {1.8, 1.7, 1.5},
        {3.8, 3.5, 3.2},
        {8.6, 8.1, 7.3},
        {17.2, 16.3, 14.6},
        {36, 34, 30.6}
    },
    {
        {17.2, 16.3, 14.6},
        {34.4, 32.5, 29.3},
        {72.1, 68.1, 61.3},
        {144.1, 136.1, 122.5},
        {1.8, 1.7, 1.5},
        {3.5, 3.3, 3},
        {7.5, 7.1, 6.4},
        {17.2, 16.3, 14.6},
        {34.4, 32.5, 29.3},
        {72.1, 68.1, 61.3}
    },
    {
        {25.8, 24.4, 21.9},
        {51.6, 48.8, 43.9},
        {108.1, 102.1, 91.9},
        {216.2, 204.2, 183.8},
        {2.6, 2.5, 2.3},
        {5.3, 5, 4.5},
        {11.3, 10.6, 9.6},
        {25.8, 24.4, 21.9},
        {51.6, 48.8, 43.9},
        {108.1, 102.1, 91.9}
    },
    {
        {34.4, 32.5, 29.3},
        {68.8, 65, 58.5},
        {144.1, 136.1, 122.5},
        {288.2, 272.2, 245},
        {3.5, 3.3, 3},
        {7.1, 6.7, 6},
        {15, 14.2, 12.8},
        {34.4, 32.5, 29.3},
        {68.8, 65, 58.5},
        {144.1, 136.1, 122.5}
    },
    {
        {51.6, 48.8, 43.9},
        {103.2, 97.5, 87.8},
        {216.2, 204.2, 183.8},
        {432.4, 408.3, 367.5},
        {5.3, 5, 4.5},
        {10.6, 10, 9},
        {22.5, 21.3, 19.1},
        {51.6, 48.8, 43.9},
        {103.2, 97.5, 87.8},
        {216.2, 204.2, 183.8}
    },
    {
        {68.8, 65, 58.5},
        {137.6, 130, 117},
        {288.2, 272.2, 245},
        {576.5, 544.4, 490},
        {7.1, 6.7, 6},
        {14.1, 13.3, 12},
        {30, 28.3, 25.5},
        {68.8, 65, 58.5},
        {137.6, 130, 117},
        {288.2, 272.2, 245}
    },
    {
        {77.4, 73.1, 65.8},
        {154.9, 146.3, 131.6},
        {324.3, 306.3, 275.6},
        {648.5, 612.5, 551.3},
        {7.9, 7.5, 6.8},
        {15.9, 15, 13.5},
        {33.8, 31.9, 28.7},
        {77.4, 73.1, 65.8},
        {154.9, 146.3, 131.6},
        {324.3, 306.3, 275.6}
    },
    {
        {86, 81.3, 73.1},
        {172.1, 162.5, 146.3},
        {360.3, 340.3, 306.3},
        {720.6, 680.6, 612.5},
        {8.8, 8.3, 7.5},
        {17.6, 16.7, 15},
        {37.5, 35.4, 31.9},
        {86, 81.3, 73.1},
        {172.1, 162.5, 146.3},
        {360.3, 340.3, 306.3}
    },
    {
        {103.2, 97.5, 87.8},
        {206.5, 195, 175.5},
        {432.4, 408.4, 367.5},
        {864.7, 816.7, 735},
        {10.6, 10, 9},
        {21.2, 20, 18},
        {45, 42.5, 38.3},
        {103.2, 97.5, 87.8},
        {206.5, 195, 175.5},
        {432.4, 408.3, 367.5}
    },
    {
        {114.7, 108.3, 97.5},
        {229.4, 216.7, 195},
        {480.4, 453.7, 408.3},
        {960.8, 907.4, 816.7},
        {11.8, 11.1, 10},
        {23.5, 22.2, 20},
        {50, 47.2, 42.5},
        {114.7, 108.3, 97.5},
        {229.4, 216.7, 195},
        {480.4, 453.7, 408.3}
    },
    {
        {129, 121.9, 109.7},
        {258.1, 243.8, 219.4},
        {540.4, 510.4, 459.4},
        {1080.9, 1020.8, 918.8},
        {13.2, 12.5, 11.3},
        {26.5, 25, 22.5},
        {56.3, 53.1, 47.8},
        {129, 121.9, 109.7},
        {258.1, 243.8, 219.4},
        {540.4, 510.4, 459.4}
    },
    {
        {143.4, 135.4, 121.9},
        {286.8, 270.8, 243.8},
        {600.5, 567.1, 510.4},
        {1201, 1134.3, 1020.8},
        {14.7, 13.9, 12.5},
        {29.4, 27.8, 25},
        {62.5, 59, 53.1},
        {143.4, 135.4, 121.9},
        {286.8, 270.8, 243.8},
        {600.5, 567.1, 510.4}
    }
};

#endif