import logging
import os
import time

import boto3
import yaml
from jinja2 import Template

import gl
from . import utils
from .aws import AWS
from .instance import KylinInstance


def launch_kc_ke(kc_config) -> KylinInstance:
    tags = gl.global_conf['TAGS']
    kc_config['Tags'] = tags

    # launch KC
    if kc_config['cloud_addr'] is None:
        cloud_addr, stack_name = AWS.aws_cloud(kc_config)
    else:
        cloud_addr = kc_config['cloud_addr']

    # launch kc cluster
    kylin_instance = KylinInstance(kc_config,
                                   host=cloud_addr,
                                   port='8079',
                                   home=None,
                                   mode='ALL')
    assert kylin_instance.client.await_kc_running(
        check_action=kylin_instance.client.get_kc_license,
        timeout=1800,
        check_times=10
    )

    # update LICENSE
    with open(kc_config['license_path']) as f:
        kc_license = f.read()
    retry = 5
    while retry > 0:
        try:
            kylin_instance.client.update_license(kc_license)
            break
        except Exception as err:
            logging.error('%s and sleep 10s', err)
            retry -= 1
            time.sleep(10)

    # create and start workspace
    if kc_config.get('cluster_id') is None:
        cluster_id = AWS.aws_workspace(kylin_instance, **kc_config)
        logging.info(f'workspace cluster_id is {cluster_id}')
    else:
        cluster_id = kc_config['cluster_id']

    # create project
    if not kc_config.get('skip_create_project'):
        create_project(kylin_instance)
        load_tables_into_project(kylin_instance)
    else:
        pass

    # disable cache
    utils.update_ke_config(kylin_instance, cluster_id, ke_config='kylin.query.cache-enabled=false')
    # let a query with T1 inner join T2 match a model whose join relation ship is T1 inner join T2 inner join T3
    # so that we can reduce the number of models
    utils.update_ke_config(kylin_instance, cluster_id, ke_config='kylin.query.match-partial-inner-join-model=true')

    # set default project for queries not specifying db
    kylin_instance.client.default_database('newworkspace', 'newproject', get_db_name())

    return kylin_instance


def create_project(kylin_instance):
    # there is a bug in KC now:  https://olapio.atlassian.net/browse/KC-9327
    # even if the status of workspace is RUNNING,
    # so we need to retry
    logging.debug('waiting create project successfully')
    start_time = time.time()
    wait_time = 300
    while time.time() - start_time < wait_time:
        try:
            resp = kylin_instance.client.create_project('newworkspace', 'newproject')
            if resp['code'] == '500':
                raise Exception
            break
        except Exception as err:
            logging.error(f"{err} and sleep 10s")
            time.sleep(10)
    logging.debug('project created')


def get_db_name():
    d = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    with open(f"{d}/workloads/{gl.global_conf['WORKLOAD']}/query_script_pm.yaml") as file:
        query_script = yaml.load(file, Loader=yaml.FullLoader)
        db = query_script['database']
    return db


def load_tables_into_project(kylin_instance):
    response = boto3.client('glue').get_tables(
        DatabaseName=get_db_name()
    )

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
       LOCATION '{{table['StorageDescriptor']['Location']}}';
       {% endfor %}
       """

    tm = Template(ddl_template)
    ddl = tm.render(tables=response['TableList'])
    response1 = kylin_instance.client.ddl_create_table('newworkspace', 'DEFAULT', ddl)
    assert not any(filter(lambda x: x['failed'], response1['datas'])), 'ddl create table failed'
    tables = [table['Name'] for table in response['TableList']]
    response2 = kylin_instance.client.load_table('newworkspace', 'newproject', datasource_type=9, tables=tables)
    assert sorted(response2['loaded']) == response2(tables), 'load table failed'
