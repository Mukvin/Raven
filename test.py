# This is athena sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3 as boto3
import pandas as pd
import numpy as np
import yaml
from jinja2 import Template

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


def foo():
    print('foo')


def hi():
    print('hi')
    pool = ThreadPoolExecutor(max_workers=3)
    pool.submit(foo).result()
    pool.submit(foo).result()
    pool.shutdown()


hook_exec_pool = ThreadPoolExecutor(max_workers=10)

import engines.athena.engine

engine = engines.athena.engine.Engine()


def zoo():
    engine.accept_query("raven_test_workload_db", "select * from raven_test_workload_db.orders")
    logging.info("query done")


def zoo2():
    # engine.accept_query("select * from raven_test_workload_db.orders")
    logging.info("query done")


def testConfig(config):
    config['2'] = 2



def load_tables_into_kc(kylin_instance):
    d = os.path.dirname(os.path.dirname(os.path.dirname('/Users/hongbin.ma/PycharmProjects/testPython/engines/kc/kc.py')))
    with open(f"{d}/workloads/{gl.global_conf['WORKLOAD']}/query_script_pm.yaml") as file:
        query_script = yaml.load(file, Loader=yaml.FullLoader)
        db = query_script['database']
    response = boto3.client('glue').get_tables(
        DatabaseName=db
    )
    x = [1, 2]
    y = next(iter(x))

    ddl_template = """
    CREATE DATABASE IF NOT EXISTS {{tables[0]['DatabaseName']}};
    USE {{tables[0]['DatabaseName']}};

    {% for table in tables %}
    CREATE EXTERNAL TABLE IF NOT EXISTS {{table['DatabaseName']}}.{{table['Name']}}
    (
    {% for column in table['StorageDescriptor']['Columns'] %}
    {{column['Name']}} {{column['Type']}}
    {% if not loop.last %}, {% endif %}
    {% endfor %}
    )
    STORED AS PARQUET
    LOCATION {{table['StorageDescriptor']['Location']}};
    {% endfor %}
    """

    tm = Template(ddl_template)
    ddl = tm.render(tables=response['TableList'])
    print(ddl)


if __name__ == '__main__':
    load_tables_into_kc(None)


    def wrapper(f):
        def wrapper_function(*args, **kwargs):
            """这个是修饰函数"""
            return f(*args, **kwargs) + 1

        return wrapper_function


    @wrapper
    def wrapped(x):
        """这个是被修饰的函数"""
        print('wrapped')
        return x + 1


    print(wrapped(1))
    print(wrapped.__doc__)  # 输出`这个是修饰函数`
    print(wrapped.__name__)  # 输出`wrapper_function`


    def partial(func, *args, **keywords):
        def newfunc(*fargs, **fkeywords):
            newkeywords = keywords.copy()
            newkeywords.update(fkeywords)
            return func(*args, *fargs, **newkeywords)

        newfunc.func = func
        newfunc.args = args
        newfunc.keywords = keywords
        return newfunc


    try:
        s = 1
    except IOError:
        pass
    else:
        x = 2


    def add(x: int, y: int):
        return x + y


    # 这里创造了一个新的函数add2，只接受一个整型参数，然后将这个参数统一加上2
    add2 = partial(add, y=2)

    add2(3)  # 这里将会输出5

    import re

    s = "where\n\tl_shipdate < date '1998-12-01'"
    m = re.search(r'(l_shipdate|o_orderdate|l_receiptdate) (<>|>|<|>=|<=|between) date', s)
    if m:
        s = s.replace(m.group(), f'cast({m.group(1)} as Date) {m.group(2)} date')

    for i in range(22000):
        print(i)
    mu, sigma = 0, 1  # mean and standard deviation
    s = np.random.normal(mu, sigma, 1000)
    import matplotlib.pyplot as plt

    count, bins, ignored = plt.hist(s, 30, density=True)
    plt.plot(bins, 1 / (sigma * np.sqrt(2 * np.pi)) *
             np.exp(- (bins - mu) ** 2 / (2 * sigma ** 2)),
             linewidth=2, color='r')
    plt.show()

    import logging.config

    logging.config.fileConfig('logging.conf')

    engine.accept_query("raven_test_workload_db", "select * from raven_test_workload_db.orders")
    hook_exec_pool.submit(zoo)
    # time.sleep(10)
    engine.destroy()
    # hook_exec_pool.shutdown()

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
