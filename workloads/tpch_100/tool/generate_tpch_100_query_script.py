import logging
import os

import yaml
from os import listdir
from os.path import isfile, join

if __name__ == '__main__':
    generate_path = '/Users/hongbin.ma/code/tpch-kit/dbgen/scale100_queries_sample'
    query_count = 22


    def readfile(f):
        with open(f) as sql_file:
            s = sql_file.read()
        return str(s).replace(';', ' ', -1).replace('limit -1', ' ', -1)


    queries = [readfile(join(generate_path, f)) for f in listdir(generate_path) if
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
        value = gauss(0, 1)
        if 2.5 > value > -2.5:  # -2.5 < value < 2.5 chance is about 97%
            at_seconds.append((value + 2.5) * 3600)  # distributed in 5 hours
    at_seconds.sort()

    todo = []
    for i in range(query_count):
        todo.append({"id": (i + 1), "at_second": at_seconds[i], "sql": queries[i]})

    script = {"max_worker_num": 10000, "database": "raven_tpch_100_db", "queries": todo}
    result = yaml.dump(script)
    with open(f"../temp.txt", 'x') as file:
        yaml.dump(script, file)
