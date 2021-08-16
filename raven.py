import collections

import boto3 as boto3
import pandas as pd
import numpy as np
import copy
import random
import sys
import time
import yaml
import string
import logging
import logging.config
import subprocess
import gl
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Timer
import threading
import argparse
import importlib

engine_name = ''
engine = None
timeline = {}

# toggles passed by command line
no_init_glue_tables = False
no_load_historical_partitions = False
no_prepare_historical_data = False
no_load_incr_partitions = False


def run():
    logging.info(f"Initializing Glue with historical data ...")
    if not no_init_glue_tables:
        init_glue_tables()
    if not no_load_historical_partitions:
        load_historical_partitions()

    # Launch the engine
    global engine_name
    engine_name = gl.global_conf['ENGINE']
    logging.info(f"Launching the engine {engine_name} ...")
    engine_module = importlib.import_module(f'engines.{engine_name}')
    global engine
    engine = engine_module.Engine()
    engine.launch_cluster()

    logging.info(f"Preparing historical data using engine {engine_name}, this may very long time ...")
    if not no_prepare_historical_data:
        engine.prepare_historical_data()

    global timeline
    with open(f"workloads/{gl.global_conf['WORKLOAD']}/timeline.yaml") as file:
        timeline = yaml.load(file, Loader=yaml.FullLoader)

    logging.info("Setting up timers for all events ...")
    for event in timeline['events']:
        t = Timer(3600.0 * event['at_hour'], timed_exec, [event])
        t.start()
    logging.info("Main thread completes")


def get_event_at_hour(event_name):
    for e in timeline['events']:
        if e["name"] == event_name:
            return e['at_hour']


def check_query_script(am_or_pm, query_script, at_second_max):
    for todo in query_script['queries']:
        assert todo[
                   'at_second'] <= at_second_max, f'at_second for query {todo["id"]} in query_script_{am_or_pm} too big'
        assert todo['at_second'] >= 0, f'at_second for query {todo["id"]} in query_script_{am_or_pm} less than 0'


def query(sql):
    try:
        q_start = time.time()
        engine.accept_query(sql)
        q_end = time.time()
        return q_end - q_start
    except:
        return -1


def timed_exec(e):
    # use a sub process to call engine's callback without being affected
    subprocess.Popen(['python', f'engines/{engine_name}/{e["name"]}.py'])

    if e['name'] == 'ON_ETL_FINISH' and not no_load_incr_partitions:
        load_inr_partitions()

    # we will play all queries twice, once in AM, once in PM
    if e['name'] in ('ON_PM_QUERY_START', 'ON_AM_QUERY_START'):
        am_or_pm = 'am' if e['name'] == 'ON_AM_QUERY_START' else 'pm'
        with open(f"workloads/{gl.global_conf['WORKLOAD']}/query_script_{am_or_pm}.yaml") as file:
            query_script = yaml.load(file, Loader=yaml.FullLoader)

        check_query_script(am_or_pm, query_script,
                           3600 * (get_event_at_hour(f'ON_{str(am_or_pm).upper()}_QUERY_FINISH') -
                                   get_event_at_hour(f'ON_{str(am_or_pm).upper()}_QUERY_START')))

        pool = ThreadPoolExecutor(max_workers=query_script['max_worker_num'])
        query_time_zero = time.time()
        todos = collections.deque(query_script['queries'])
        todo_num = len(todos)
        logging.info(f"{todo_num} queries start being submitted in {am_or_pm} ...")
        futures = []
        result_book = gl.AM_times if e['name'] == 'ON_AM_QUERY_START' else gl.PM_times
        while len(todos) > 0:
            sql_and_time = todos.popleft()
            diff = sql_and_time['at_second'] - (time.time() - query_time_zero)
            if diff > 0:
                time.sleep(diff)
            logging.info(
                f"Query {sql_and_time['id']}, expected at second {sql_and_time['at_second']}," +
                f" actual at second {time.time() - query_time_zero}")
            futures += [pool.submit(query, sql_and_time['sql'])]
        for future in as_completed(futures):
            result_book += [future.result()]
        assert len(result_book) == todo_num
        logging.info(f"{todo_num} queries are finished, all query durations: {result_book}")


def init_glue_tables():
    cf_r = boto3.resource('cloudformation')
    random_identity = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    with open(f"workloads/{gl.global_conf['WORKLOAD']}/glue_tables_cf_template.yaml") as file:
        glue_tables_cf_template = file.read()
    logging.info(f'Creating tables in glue ...')
    stack_name = f'raven-stack-{random_identity}'
    cf_r.create_stack(
        StackName=stack_name,
        TemplateBody=glue_tables_cf_template,
        Tags=gl.aws_format_tags
    )

    while True:
        r = cf_r.Stack(stack_name)
        if 'progress' in str(r.stack_status).lower():
            logging.info(f'stack {stack_name} status: {r.stack_status}, check later after 5s')
            time.sleep(5)
        else:
            assert r.stack_status == 'CREATE_COMPLETE', \
                f'cloud formation stack {stack_name} failed to deploy, please check CloudFormation stacks page'
            break


def load_historical_partitions():
    load_partitions('historical')


def load_inr_partitions():
    load_partitions('incr')


def load_partitions(historical_or_incr):
    glue = boto3.client("glue")
    with open(f"workloads/{gl.global_conf['WORKLOAD']}/{historical_or_incr}_partitions.yaml") as file:
        historical_partitions = yaml.load(file, Loader=yaml.FullLoader)

    # partition_column_template = {
    #     'Name': 'string',
    #     'Type': 'string',
    #     # 'Comment': 'string',
    #     # 'Parameters': {
    #     #     'string': 'string'
    #     # }
    # }
    partition_input_template = {
        'Values': [
            'string',
        ],
        # 'LastAccessTime': datetime(2015, 1, 1),
        'StorageDescriptor': {
            # 'Columns': [
            #
            # ],
            'Location': 'string',
            'InputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
            'OutputFormat': 'org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat',
            # 'Compressed': True | False,
            # 'NumberOfBuckets': 123,
            'SerdeInfo': {
                #     'Name': 'string',
                'SerializationLibrary': 'org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe'
                #     'Parameters': {
                #         'string': 'string'
                #     }
            },
            # 'BucketColumns': [
            #     'string',
            # ],
            # 'SortColumns': [
            #     {
            #         'Column': 'string',
            #         'SortOrder': 123
            #     },
            # ],
            # 'Parameters': {
            #     'string': 'string'
            # },
            # 'SkewedInfo': {
            #     'SkewedColumnNames': [
            #         'string',
            #     ],
            #     'SkewedColumnValues': [
            #         'string',
            #     ],
            #     'SkewedColumnValueLocationMaps': {
            #         'string': 'string'
            #     }
            # },
            # 'StoredAsSubDirectories': True | False,
            # 'SchemaReference': {
            #     'SchemaId': {
            #         'SchemaArn': 'string',
            #         'SchemaName': 'string',
            #         'RegistryName': 'string'
            #     },
            #     'SchemaVersionId': 'string',
            #     'SchemaVersionNumber': 123
            # }
        },
        # 'Parameters': {
        #     'string': 'string'
        # },
        # 'LastAnalyzedTime': datetime(2015, 1, 1)
    }
    for db_dict in historical_partitions['databases']:
        for table_dict in db_dict['tables']:
            partition_input_list = []
            for partition_dict in table_dict['partitions']:
                temp = copy.deepcopy(partition_input_template)
                values = []
                for key in partition_dict:
                    values += [str(partition_dict[key])]
                temp['Values'] = values
                location = table_dict['partition_location_template']
                for v in values:
                    location = str(location).replace('%value%', str(v), 1)
                temp['StorageDescriptor']['Location'] = location
                partition_input_list += [temp]

            logging.info(
                f"Creating {len(partition_input_list)} partitions" +
                f" for table {db_dict['name']}.{table_dict['name']} ...")
            r = glue.batch_create_partition(
                DatabaseName=db_dict['name'],
                TableName=table_dict['name'],
                PartitionInputList=partition_input_list
            )
            assert not r['Errors'] or len(r['Errors']) == 0


if __name__ == '__main__':
    logging.config.fileConfig('logging.conf')
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-init-glue-tables", required=False, action='store_true', default=False,
                        dest='no_init_glue_tables')
    parser.add_argument("--no-load-historical-partitions", required=False, action='store_true', default=False,
                        dest='no_load_historical_partitions')
    parser.add_argument("--no-prepare-historical-data", required=False, action='store_true', default=False,
                        dest='no_prepare_historical_data')
    parser.add_argument("--no-load-incr-partitions", required=False, action='store_true', default=False,
                        dest='no_load_incr_partitions')
    args = parser.parse_args()

    no_init_glue_tables = args.no_init_glue_tables
    no_load_historical_partitions = args.no_load_historical_partitions
    no_prepare_historical_data = args.no_prepare_historical_data
    no_load_incr_partitions = args.no_load_incr_partitions

    run()
