import logging
import os
import re

import yaml
from os import listdir
from os.path import isfile, join

if __name__ == '__main__':
    generate_path = '/Users/hongbin.ma/code/tpch-kit/dbgen/scale100_queries'
    query_count = 22000
    guassian_dist = True


    def readfile(f):
        with open(f) as sql_file:
            s = sql_file.read()

        # some queries look like xxxxx; limit -1; , clean them
        s = s.replace(';', ' ', -1).replace('limit -1', ' ', -1)

        # some queries look like l_shipdate > date'2011-01-01', transform them
        while True:
            m = re.search(r'(l_shipdate|o_orderdate|l_receiptdate) (<>|>|<|>=|<=|between) date', s)
            if m:
                s = s.replace(m.group(), f'cast({m.group(1)} as Date) {m.group(2)} date')
            else:
                break

        # some query (1.sql) has a "(3)", remove it
        s = s.replace('(3)', ' ', -1)

        # extract(year from l_shipdate)
        s = s.replace('extract(year from l_shipdate)', 'extract(year from cast(l_shipdate as Date))', -1)
        s = s.replace('extract(year from o_orderdate)', 'extract(year from cast(o_orderdate as Date))', -1)
        s = s.replace('extract(year from l_receiptdate)', 'extract(year from cast(l_receiptdate as Date))', -1)

        # in some queries (15.sql) exists 'create view', this is unsupported by many engines, just replace with a dummy
        if 'create view' in s:
            return "select count(*) from lineitem"
        return s


    queries = [{"sql": readfile(join(generate_path, f)), "id": f}
               for f in listdir(generate_path) if
               isfile(join(generate_path, f)) and f.endswith('sql')]

    # generate random Gaussian values
    from random import seed
    from random import gauss

    # seed random number generator
    seed(1)
    # generate some Gaussian values
    at_seconds = []
    while True:
        if len(at_seconds) >= query_count:
            break

        if guassian_dist:
            value = gauss(0, 1)
            if 2.5 > value > -2.5:  # -2.5 < value < 2.5 chance is about 97%
                at_seconds.append((value + 2.5) * 3600)  # distributed in 5 hours
        else:
            at_seconds.append(len(at_seconds))  # this is for testing

    at_seconds.sort()

    todo = []
    for i in range(query_count):
        todo.append({"id": queries[i]["id"], "at_second": at_seconds[i], "sql": queries[i]["sql"]})

    # print(todo)

    script = {"max_worker_num": 10000, "database": "raven_tpch_100_db", "queries": todo}
    result = yaml.dump(script)
    with open(f"../temp.txt", 'x') as file:
        yaml.dump(script, file)
