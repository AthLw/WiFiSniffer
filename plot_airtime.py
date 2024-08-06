#--encoding: utf-8--#
import json
import time
import matplotlib.pyplot as plt
from shutil import copyfile
from datetime import datetime, timedelta

def read_rate(file_path):
    with open(file_path, 'r') as file:
        try:
            temp = file.readlines()
            if temp:
                temp = temp[0].strip()
                rate = json.loads(temp)
            else:
                rate = {}
        except ValueError as e:
            rate = {}
            print("read rate json file error: {}, file content: {}".format(e, temp))
        return rate

def read_users(file_path):
    with open(file_path, 'r') as file:
        temp = file.read().strip()
        print("users: {}".format(temp))
        try:
            users = int(temp)
        except ValueError:
            pass
            users = 0
    return users

def read_occupancy(file_path):
    with open(file_path, 'r') as file:
        try:
            temp = file.readlines()
            if temp:
                temp = temp[0].strip()
                occupancy = json.loads(temp)
            else:
                occupancy = {}
        except ValueError as e:
            occupancy = {}
            print("read json file error: {}, file content: {}".format(e, temp))
    return occupancy

# 文件路径（根据实际情况修改）
rate_file_path = 'Rate.json'
users_file_path = 'Users.txt'
occupancy_file_path = 'Occupancy.json'

max_users = 6
WINDOW = 6
interval = 1 # sample data every 1 second

# 初始化数据
times = []
rates = []
users = []
occupancies = []
for _ in range(max_users):
    rates.append([])
    occupancies.append([])
addrs = []
addrs_rate = []
colors = ['red', 'green', 'yellow', 'blue', 'deeppink', 'grey', 'black', 'purple', 'gold', 'brown']

# 初始化图表
plt.ion()  # 打开交互模式
fig, axs = plt.subplots(3, 1, figsize=(10, 8))  # 三个子图

while True:
    #try:
        # 读取最新数据
        rate = read_rate(rate_file_path)
        user = read_users(users_file_path)
        occupancy = read_occupancy(occupancy_file_path)
        current_time = datetime.now()

        # 更新数据
        times.append(current_time)
        data_len = len(times)
        users.append(user)
        if rate:
            rate_notnull_list = []
            for k,v in rate.items():
                now_users = len(addrs_rate)
                if k not in addrs_rate and now_users < max_users:
                    addrs_rate.append(k)
                    rates[now_users].append(v)
                    rate_notnull_list.append(now_users)
                else:
                    rindex = addrs_rate.index(k)
                    if rindex >= 0:
                        rates[rindex].append(v)
                        rate_notnull_list.append(rindex)
            for i in range(max_users):
                if i not in rate_notnull_list:
                    rates[i].append(0)
        else:
            for r in rates:
                r.append(0)
        
        if occupancy:
            notnull_list = []
            for k,v in occupancy.items():
                now_users = len(addrs)
                if k not in addrs and now_users < max_users:
                    addrs.append(k)
                    occupancies[now_users].append(v)
                    notnull_list.append(now_users)
                else:
                    index = addrs.index(k)
                    if index >= 0:
                        occupancies[index].append(v)
                        notnull_list.append(index)
            for i in range(max_users):
                if i not in notnull_list:
                    occupancies[i].append(0)
        else:
            for o in occupancies:
                o.append(0)
        # 删除超过10分钟的数据
        time_threshold = current_time - timedelta(minutes=WINDOW)
        while times and times[0] < time_threshold:
            times.pop(0)
            for i in range(max_users):
                rates[i].pop(0)
            users.pop(0)
            for i in range(max_users):
                occupancies[i].pop(0)

        # 更新图表
        for ax in axs:
            ax.clear()
        
        for i in range(len(addrs)):
            axs[0].plot(times, rates[i], label=addrs[i], color=colors[i])
        axs[0].set_xlabel('Time')
        axs[0].set_ylabel('Rate')
        axs[0].legend()
        
        axs[1].plot(times, users, label='Users')
        axs[1].set_xlabel('Time')
        axs[1].set_ylabel('Users')
        axs[1].legend()
        
        for i in range(len(addrs)):
            axs[2].plot(times, occupancies[i], label=addrs[i], color=colors[i])
        axs[2].set_xlabel('Time')
        axs[2].set_ylabel('Occupancy')
        axs[2].legend()
        
        fig.autofmt_xdate()  # 自动格式化日期
        plt.draw()
        plt.pause(interval)  # 暂停1秒

    #except Exception as e:
    #    print(f"读取数据时发生错误: {e}")
    #    break

plt.ioff()
plt.show()

