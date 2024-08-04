#--encoding: utf-8--#
import json
import time
import matplotlib.pyplot as plt
from shutil import copyfile
from datetime import datetime, timedelta

def read_rate(file_path):
    with open(file_path, 'r') as file:
        temp = file.read().strip()
        print("rate: {}".format(temp))
        try:
            temp = float(temp)
            rate = temp
        except ValueError:
            pass
            rate = 0
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
            occupancy = json.load(file)
        except ValueError as e:
            occupancy = {}
            print("read json file error: {}".format(e))
            copyfile(file_path, "/home/litonglab/Downloads/sniff_802/fake.json")
    return occupancy

# 文件路径（根据实际情况修改）
rate_file_path = 'Rate.txt'
users_file_path = 'Users.txt'
occupancy_file_path = 'Occupancy.json'

max_users = 4

# 初始化数据
times = []
rates = []
users = []
occupancies = [[],[],[],[]]
addrs = []
colors = ['red', 'green', 'yellow', 'blue']

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
        rates.append(rate)
        users.append(user)
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
        time_threshold = current_time - timedelta(minutes=10)
        while times and times[0] < time_threshold:
            times.pop(0)
            rates.pop(0)
            users.pop(0)
            occupancies.pop(0)

        # 更新图表
        for ax in axs:
            ax.clear()
        
        axs[0].plot(times, rates, label='Rate')
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
        plt.pause(0.5)  # 暂停1秒

    #except Exception as e:
    #    print(f"读取数据时发生错误: {e}")
    #    break

plt.ioff()
plt.show()

