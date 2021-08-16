# This is athena sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3 as boto3
import pandas as pd
import numpy as np
import random
import yaml

import gl


def print_hi(name):
    name = input('please enter your name: ')
    print('hello,', name)
    # Use athena breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press ⌘F8 to toggle the breakpoint.

    data = np.zeros((1000, 1000))
    for i in range(len(data)):  # 这里速度比较慢，因为随机给1000*1000的数组赋值
        for j in range(len(data[0])):
            data[i][j] = random.randint(1, 20)  # 赋值的范围是1-20中的任意一个
    data_m = pd.DataFrame(data)
    data_m = data_m[1].value_counts()  # 注意value_counts函数统计一个series上的数据情况
    data_m = data_m.sort_index()  # 给统计后的数据排序
    print(data_m)
    data_m.query()


def try_boto():
    s = 'abc'
    if s.startswith('x' or 'athena'):
        print('hello')
    client = boto3.client('ec2', region_name='us-west-2')
    filters = [
        # {
        #     'Name': 'tag:Owner',
        #     'Values': [default_owner]
        # },
        # {
        #     'Name': 'tag:kyligence:cloud:vm-type',
        #     'Values': [vm_type]
        # },
        {
            'Name': 'instance-state-name',
            'Values': ['running', 'stopped']
        }
    ]
    response = client.describe_instances(Filters=filters, DryRun=False, MaxResults=1000)
    print(response)


from multiprocessing import Pool, Process
import os, time, random

from multiprocessing import Pool
import os, time, random

from subprocess import Popen
import time


def spider(page):
    time.sleep(page)
    print(f"crawl task{page} finished")
    return page


if __name__ == '__main__':
    pool = ThreadPoolExecutor(max_workers=3)

# Press the green button in the gutter to run the script.
# if __name__ == '__main__':

# from threading import Timer
#
#
# def hello():
#     print("hello, world")
#
#
# t = Timer(10.0, hello)
# t.start()
#
# print("xxx")

# import yaml

#
# with open("workloads/test_workload/historical_partitions.yaml", encoding="UTF-8") as file:
#     content = yaml.load(file, Loader=yaml.FullLoader)
#
# dict = {'a':1, 'b':2, 'c':3}
#
# gl.x = 10
# loggger = Logger('','')
# try_boto()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/

