import json
import os
import copy
import re
from datetime import datetime, timedelta
import logging
import time
import functools

# from fixture._internal import deploy
# from fixture.datasources import init_cloud_instance
# from tests.lightning import InstanceTag, platform_mysql_password, get_cloud_prefix, quard_bucket, ki_size
from .common import InstanceTag


def await_with_retry(waiting_time=10, interval=20, raise_exp_when_timeout=True):
    def wrapper_job(func):
        @functools.wraps(func)  # func保留原始的信息
        def wrapper(*args, **kwargs):
            timeout = waiting_time * 60
            start = time.time()
            while time.time() - start < timeout:
                return_value = func(*args, **kwargs)
                if return_value:
                    return return_value
                logging.debug(
                    f'{func.__name__} is not get target value, will sleep {interval} seconds')
                time.sleep(interval)
            timeout_message = f'{func.__name__} is out of waiting_time = {waiting_time} seconds'
            logging.error(timeout_message)
            if raise_exp_when_timeout:
                raise Exception(timeout_message)

        return wrapper

    return wrapper_job


# @allure.step('check workspace permission')
def check_workspace_permission(instance, workspace_name, name, permission):
    time.sleep(5)
    user_permission = instance.client.get_workspace_permission(workspace=workspace_name)
    resp = list(filter(lambda msg: msg['name'] == name and msg['permission'] == permission,
                       user_permission['value']))
    assert resp, f"check permission failure to {name}"


# @allure.step('check project permission')
def check_project_permission(instance, workspace_name, project_name, name, permission):
    user_permission = instance.client.get_workspace_project_permission(workspace=workspace_name,
                                                                       project_name=project_name)
    resp = list(
        filter(lambda msg: msg['name'] == name or msg['name'] == name.upper() and msg['permission'] == permission,
               user_permission['value']))
    assert resp, f"check project permission failure to {name}"


# @allure.step('delete all model')
def delete_all_model(instance, workspace_name, project):
    """
    delete all model
    :param instance:
    :param workspace_name: string, the name of workspace
    :param project: string, the name of project
    :return:
    """

    resp = instance.client.get_model(workspace_name, project)
    for msg in resp['value']:
        instance.client.delete_model(workspace_name, project, msg['name'])
    resp = instance.client.get_model(workspace_name, project)
    assert not resp['value'], 'failed to delete models'


def upload_file_operation(instance, cloud_instance, shared_datadir, file_name, file_location):
    bucket_name = instance.kc_config['s3bucket']
    local_file = os.path.join(shared_datadir, file_name)
    cloud_instance.upload_file(bucket_name, local_file, f'{file_location}/{file_name}')
    check_file_exists(instance, cloud_instance, file_path=f'{file_location}/{file_name}')
    time.sleep(5)


# @allure.step('check file exists')
@await_with_retry(waiting_time=2, interval=10)
def check_file_exists(instance, cloud_instance, file_path):
    bucket_name = instance.kc_config['s3bucket']
    delimiter = file_path.split('/')[0]
    file_name = cloud_instance.list_file(bucket_name=bucket_name, delimiter=delimiter, prefix=file_path,
                                         container_name=bucket_name, name_starts_with=file_path)
    return file_name[0] == file_path


def clean_file_operation(instance, cloud_instance, file_name, file_location):
    bucket_name = instance.kc_config['s3bucket']
    object_name = f'{file_location}/{file_name}'
    cloud_instance.delete_object(bucket_name, object_name)


@await_with_retry(waiting_time=20)
def await_diagnosis_generated(instance, uuid):
    resp = instance.client.get_diagnosis_status(uuid)
    return resp['datas']


# @allure.step('pack diagnosis when test failed')
def pack_diagnosis_when_test_failed(instance, env, cloud_instance, workspace_name, cluster_id, local_file=None):
    workspace_status = instance.client.get_workspace_status(workspace_name, instance.platform)
    modules = ['ENGINE', 'CLOUD', 'ALLUXIO'] if workspace_status == 'RUNNING' else ['CLOUD']
    end_time = datetime.now()
    start_time = end_time - timedelta(days=1)
    end_time = int(end_time.timestamp() * 1000)
    start_time = int(start_time.timestamp() * 1000)
    uuid = instance.client.pack_diagnosis(cluster_id, modules, start_time=start_time, end_time=end_time)
    export_path = await_diagnosis_generated(instance, uuid)[0]['exportPath']
    cloud_workspace_name = export_path.split('/')[4]
    object_name = f"packages/{'/'.join(export_path.split('/')[-3:])}"
    if not local_file:
        local_file = os.path.join(env.diagnose_package_root, f'packages/{instance.platform}_{cloud_workspace_name}.zip')
    instance_info = cloud_instance.get_instance_info(vm_type=InstanceTag.KC.value, workspace_name=workspace_name)
    vm_name = instance_info[InstanceTag.KC.value][0][1]
    script = f'rsync -a /data1/kyligence_cloud/diag_tmp/{cloud_workspace_name} /data1/packages/'
    cloud_instance.exec_script_instance_and_return(vm_name, script)

    buckets = cloud_instance.list_buckets()
    last_bucket = next(filter(lambda msg: msg['Name'].startswith(instance.identifier), buckets))['Name']
    cloud_instance.download_fileobj(bucket_name=last_bucket, object_name=object_name, fileobj=local_file)


# @allure.step('get storage account and key')
def get_storage_account_and_key(instance, cloud_instance):
    """
    :param instance:
    :param cloud_instance
    :return:
    """
    resp = cloud_instance.list_buckets()
    account_name = next(filter(lambda msg: msg.tags.get('identifier', '').startswith(instance.identifier), resp)).name
    account_key = cloud_instance.get_storage_accounts_list_keys(account_name).keys[0].value
    return account_name, account_key


# @allure.step('build index step')
def build_index_step(instance, workspace_name, project_name, model_name, job_names):
    logging.debug('build index')
    instance.client.build_index(workspace_name, project_name, model_name=model_name)
    assert instance.client.await_job_name_exist(workspace_name, project_name, job_names)
    list_jobs = instance.client.get_job_list(workspace_name, project_name, key=model_name)['value']
    return list_jobs[0]['id']


def update_model_status_and_check(instance, workspace_name, project_name, model_name, status):
    model_uuid = instance.client.get_model(workspace_name, project_name, model_name)['value'][0]['uuid']
    instance.client.update_model_status(workspace_name, project_name, model_uuid, status)
    model_status = instance.client.get_model(workspace_name, project_name, model_name)
    assert model_status['value'][0]['status'] == status, 'fix broken model failed'


# @allure.step('load table')
def ddl_create_table_step(instance, workspace_name, datadir, sql_file='ddl.sql', location_file='location.json',
                          throw=True, data_key=None, database=None, cloud_prefix=None,
                          cloud_object_prefix=None, is_replace=False, replace_dict=None):
    cloud_prefix = re.findall(r'(.*)[C,G]', instance.platform)[0] if not cloud_prefix else cloud_prefix
    if not is_replace:
        with open(os.path.join(datadir, sql_file)) as ddl:
            if os.path.exists(os.path.join(datadir, location_file)):
                with open(os.path.join(datadir, location_file)) as location:
                    sql = ddl.read()
                    location = json.load(location)
                    if not data_key:
                        ddl_create_sql = sql.format(**location[cloud_prefix.lower()])
                    else:
                        ddl_create_sql = sql.format(location[cloud_prefix.lower()][data_key])
            else:
                ddl_create_sql = ddl.read()
    else:
        replace_dict = replace_dict if replace_dict else dict()
        if not cloud_object_prefix:
            with open(os.path.join(datadir, location_file), 'r') as f:
                prefix_info = json.load(f)
                cloud_object_prefix = prefix_info.get(cloud_prefix.lower())
        replace_dict[r'{object_storage_prefix}'] = cloud_object_prefix
        if database:
            replace_dict[r'{database}'] = database
        ddl_create_sql = replace_text(datadir, sql_file, replace_dict)

    resp = instance.client.ddl_create_table(workspace_name, 'DEFAULT', ddl_create_sql)
    if throw:
        assert not any(filter(lambda x: x['failed'], resp['datas'])), 'ddl create table failed'
    return resp


# @allure.step('load table step')
def load_table_step(instance, workspace, project, databases, tables, need_sampling=False):
    """
    :param instance
    :param workspace
    :param project
    :param databases, list
    :param tables, list, ['database.table', ...]
    :param need_sampling: bool
    """
    resp = instance.client.load_table(workspace, project, datasource_type=9, databases=databases,
                                      need_sampling=need_sampling, tables=tables)
    assert sorted(resp['loaded']) == sorted(tables), 'load table steps failed'
    loaded_tables = get_loaded_tables(instance, workspace, project)
    assert sorted(loaded_tables) == sorted(tables)


# @allure.step('create model step')
def create_model_and_load_index_step(instance, workspace_name, project_name, model_name, datadir, model='model.json',
                                     index='index.json', transform=True):
    with open(os.path.join(datadir, model), 'r') as model_file, \
            open(os.path.join(datadir, index), 'r') as index_file:
        model_desc_data = json.load(model_file)
        model_desc_data['alias'] = model_name
        model_desc_data['project'] = project_name
        agg_groups = json.load(index_file)
        instance.client.create_model(workspace_name, model_desc_data)
        time.sleep(5)
        resp = instance.client.get_model(workspace_name, project_name)
        assert resp['value'][0]['name'] == model_name, f"failed to create model"
        model_id = resp['value'][0]['uuid']

        logging.debug('load index')
        add_agg_index_step_with_origin_name(instance, workspace_name,
                                            project_name, model_id, agg_groups, transform=transform)
    return model_id


# @allure.step('add table indices step')
def add_table_indices_step(instance, workspace_name, project_name, model_id, col_order):
    logging.debug('add table index')
    resp = instance.client.add_table_indices(workspace_name, project_name, model_id, col_order=col_order)
    assert resp, 'add table indices failed'


# @allure.step('resize worker')
def resize_worker(instance, workspace_name, cloud, cluster_id, upper_limit, lower_limit, work_node_count):
    logging.debug('resize worker')
    instance.client.resize_worker(cluster_id, upper_limit, lower_limit, work_node_count)
    assert instance.client.await_all_workspace([workspace_name], cloud, ['RUNNING'])


# @allure.step('get loaded tables in current project')
def get_loaded_tables(instance, workspace_name, project_name):
    loaded_tables = []
    workspace_id = instance.client.get_cluster_id(workspace_name, instance.platform)
    table_list = instance.client.get_project_tables(workspace_id, project_name)
    for db_table in table_list['databases']:
        db_name = db_table['dbname']
        loaded_tables.extend([f"{db_name}.{item['name']}" for item in db_table['tables']])
    return loaded_tables


def get_database_conn_info(instance, cloud_instance, vm_type, script):
    instance_info = cloud_instance.get_instance_info(vm_type=vm_type)
    vm_name = instance_info[vm_type][0][1]
    resp = cloud_instance.exec_script_instance_and_return(vm_name, script)
    datasource_url = re.findall('spring.datasource.url=.*//(.*?):', resp)[0]
    user_name = re.findall('username=(.*?)\n', resp)[0]
    mysql_password = instance.kc_config['RDSPassword']
    return f'mysql -u{user_name} -p{mysql_password} -h{datasource_url} '


def stop_workspace(instance, workspace_name):
    instance.client.stop_workspace(workspace_name)
    assert instance.client.await_all_workspace([workspace_name], instance.platform, expected_status=['STOPPED'])


def stop_workspaces(instance, workspace_names):
    if not isinstance(workspace_names, list) and not instance(workspace_names, tuple):
        raise RuntimeError('workspace_names {} is not list or is not tunple'.format(workspace_names))
    if not workspace_names:
        logging.debug('workspace_names is {}, do not need to stop'.format(workspace_names))
        return
    for ws_name in workspace_names:
        instance.client.stop_workspace(ws_name)
    assert instance.client.await_all_workspace(workspace_names, instance.platform, expected_status=['STOPPED'])


def start_workspace(instance, workspace_name):
    workspace_id = instance.client.get_workspace_id(workspace_name, instance.platform)
    instance.client.start_workspace(workspace_name)
    assert instance.client.await_all_workspace([workspace_name], instance.platform, expected_status=['RUNNING'])
    res = instance.client.await_kc_running(check_action=instance.client.get_project_list, workspace_id=workspace_id)
    assert res, 'can not access ke'


def start_workspaces(instance, workspace_names):
    if not isinstance(workspace_names, list) and not instance(workspace_names, tuple):
        raise RuntimeError('workspace_names {} is not list or is not tunple'.format(workspace_names))
    if not workspace_names:
        logging.debug('workspace_names is {}, do not need to start'.format(workspace_names))
        return
    for ws_name in workspace_names:
        instance.client.start_workspace(ws_name)
    assert instance.client.await_all_workspace(workspace_names, instance.platform, expected_status=['RUNNING'])


def get_all_workspace_status(instance, cloud=None):
    cloud = 'AzureChinaCloud' if cloud is None else cloud
    workspaces = instance.client.get_workspace_list(cloud)['content']
    workspaces_status = {}
    for workspace in workspaces:
        workspaces_status[workspace['project']] = workspace['cluster']['status']
    return workspaces_status


def await_all_workspaces_to_finished_status(instance, cloud=None):
    workspaces_status = get_all_workspace_status(instance, cloud)
    if not workspaces_status:
        return
    for name, status in workspaces_status.items():
        if status in {'ERROR', 'RESTART_TIMEOUT'}:
            raise RuntimeError("The workspace {}'s status is error, can't operate it".format(name))
    discarded_middle_status = {'DELETING'}
    running_or_stopped_middle_status = {'CREATING', 'QUERY_SHRINKING', 'QUERY_STRETCHING', 'AUTO_SHRINKING',
                                        'AUTO_STRETCHING', 'RESTARTING', 'CONFIGURING', 'RESIZING',
                                        'ENGINE_SHRINKING', 'ENGINE_STRETCHING', 'STOPPING', 'BACKUPPING'}
    await_discarded_ws_names = list(filter(lambda ws_name: workspaces_status[ws_name] in discarded_middle_status,
                                           workspaces_status.keys()))
    await_running_or_stopped_ws_names = list(filter(lambda ws_name: workspaces_status[ws_name] in
                                                                    running_or_stopped_middle_status,
                                                    workspaces_status.keys()))
    assert instance.client.await_delete_workspace(await_discarded_ws_names, cloud)
    assert instance.client.await_all_workspace(await_running_or_stopped_ws_names, cloud, ['RUNNING', 'STOPPED'])


def stop_all_running_workspace(instance, cloud=None):
    await_all_workspaces_to_finished_status(instance, cloud)
    workspaces_status = get_all_workspace_status(instance, cloud)
    running_workspaces = list(filter(lambda ws_name: workspaces_status[ws_name] == 'RUNNING',
                                     workspaces_status.keys()))
    stop_workspaces(instance, running_workspaces)
    return running_workspaces


# @allure.step('await delete workspace step')
def await_delete_workspace(instance, workspace_name, cloud):
    instance.client.delete_workspace(workspace_name)
    assert instance.client.await_delete_workspace([workspace_name], cloud)


# @allure.step('load ke special config')
def load_ke_config(instance, workspace_name, ke_config):
    cluster_id = instance.client.get_cluster_id(workspace_name, cloud=instance.platform)
    logging.debug('update KE config and restart KE')
    update_ke_config(instance, cluster_id, ke_config)
    restart_ke(instance, workspace_name, cluster_id)


def update_ke_config(instance, cluster_id, ke_config):
    resp = instance.client.update_ke_config(cluster_id, ke_config)
    assert not resp['datas'], f'update ke config {ke_config} failure'


def restart_ke(instance, workspace_name, cluster_id):
    logging.debug('update KE config and restart KE')
    instance.client.restart_ke(cluster_id)
    assert instance.client.await_workspace_running(workspace_name, cloud=instance.platform), 'resize start failure'
    workspace_id = instance.client.get_workspace_id(workspace_name, instance.platform)
    res = instance.client.await_kc_running(check_action=instance.client.get_project_list, workspace_id=workspace_id)
    assert res, 'can not access ke'


def add_agg_index_step_with_origin_name(instance, workspace_name, project_name, model_id,
                                        agg_groups, load_data=False, transform=False):
    """
    add agg index in model
    :param instance: KylinInstance
    :param project_name: string, project name
    :param model_id: string, model uuid
    :param agg_groups: string, agg index list
    :param load_data: bool, build agg index when True
    :param transform: bool, transfer dimension name to id when True
    :return:
    """
    logging.info(f'add agg index step start')

    def _transform(trans_dict, agg_groups):
        agg_groups_copy = copy.deepcopy(agg_groups)
        for item in agg_groups_copy:
            item['includes'] = [trans_dict[i] for i in item['includes']]
            item['measures'] = [trans_dict[i] for i in item['measures']]
            for key in ('hierarchy_dims', 'joint_dims', 'mandatory_dims'):
                if item.get('select_rule').get(key):
                    if isinstance(item['select_rule'][key][0], str):
                        item['select_rule'][key] = [trans_dict[i] for i in item['select_rule'][key]]
                    elif isinstance(item['select_rule'][key][0], list):
                        for i in range(len(item['select_rule'][key])):
                            item['select_rule'][key][i] = [trans_dict[i] for i in item['select_rule'][key][i]]

        return agg_groups_copy

    if transform:
        list_models = instance.client.get_model(workspace_name, project_name)
        model = [m for m in list_models['value'] if m['uuid'] == model_id]
        assert model
        trans_dict = {d['column']: d['id'] for d in model[0]['simplified_dimensions']}
        trans_dict.update({d['name']: d['id'] for d in model[0]['simplified_measures']})
        agg_groups = _transform(trans_dict, agg_groups)

    add_agg_resp = instance.client.add_aggregate_indices(workspace_name, project_name, model_id,
                                                         agg_groups, load_data=load_data)
    assert add_agg_resp['type'], f"create agg index failed. model id {model_id}"
    logging.info(f'add agg index step end')


def resize_engine(instance, workspace_name, cluster_id, edge_node_count):
    instance.client.resize_engine(cluster_id, edge_node_count=edge_node_count)
    assert instance.client.await_workspace_running(workspace_name, cloud=instance.platform), 'resize engine failure'


def generate_diagnosis(instance, cluster_id, modules, start_time=None, end_time=None):
    if not start_time and not end_time:
        end_time = datetime.now()
        start_time = end_time - timedelta(days=1)
        end_time = int(end_time.timestamp() * 1000)
        start_time = int(start_time.timestamp() * 1000)
    uuid = instance.client.pack_diagnosis(cluster_id, modules, start_time=start_time, end_time=end_time)
    assert await_diagnosis_generated(instance, uuid), 'generate diagnosis failed'


def load_sample_data_by_kc(instance, cluster_id, project_name):
    resp = instance.client.load_sample_data(project_name, cluster_id)
    assert not resp['data'], 'load sample data by kc failed'


# @allure.step('await all workspaces in static status')
def check_workspaces_status_before_update_password(instance, expected_status=['RUNNING']):
    """
    We must ensure all workspaces in our expected status, than we can update password
    param instance:
    param expected_status: list, expected status, expected_status=['STOPPED', 'RUNNING']
    """
    logging.debug(f"await all workspaces in expected status: {expected_status}")
    workspace_list = instance.client.get_workspace_list(instance.platform)
    workspace_names = [items['project'] for items in workspace_list['content']]
    resp = instance.client.await_all_workspace(workspace_names, instance.platform, expected_status)
    assert resp, f"await all workspaces in special status failed, can not change password other than {expected_status}"


def restart_kc_service(instance, cloud_instance, check_action=None):
    restart_kc_script = 'docker restart kyligence_cloud'
    instance_info = cloud_instance.get_instance_info(vm_type=InstanceTag.KC.value)
    for vm_name in instance_info[InstanceTag.KC.value]:
        resp = cloud_instance.exec_script_instance_and_return(vm_name[1], restart_kc_script)
        logging.debug('On {} exec {} result is {}'.format(vm_name, restart_kc_script, resp))
    time.sleep(30)
    res = instance.client.await_kc_running(check_action=check_action)
    assert res, 'can not access KC'


def delete_loaded_table(instance, workspace_name, cluster_id, project, database_name, table):
    instance.client.delete_loaded_table(cluster_id, project, database_name, table)
    resp = get_loaded_tables(instance, workspace_name, project)
    assert f'{database_name}.{table}' not in resp


# @allure.step('query hit index step')
def query_hit_index_step(instance, workspace_name, project_name, model_name, query_sql, query_result=None):
    logging.debug('query hit index')
    resp = instance.client.execute_query(workspace_name, project_name, query_sql)
    assert not resp['pushDown'] and resp['realizations'][0]['modelAlias'] == model_name, 'no hit index'
    if query_result:
        assert resp['results'] == query_result, f"expect {resp['results']} = {query_result}, but not"


# @allure.step('query push_down step')
def query_push_down_step(instance, workspace_name, project_name, query_sql, query_result=None):
    logging.debug('query pushdown')
    resp = instance.client.execute_query(workspace_name, project_name, query_sql)
    assert resp['pushDown'], 'query should be pushDown'
    if query_result:
        assert resp['results'] == query_result, f"expect {resp['results']} = {query_result}, but not"


def get_worksapce_by_name(instance, workspace_name):
    workspaces = instance.client.get_workspace_list(instance.platform)['content']
    return next(filter(lambda ws: ws['project'] == workspace_name, workspaces))


def get_workspace_endpoint(instance, workspace_name, endpoint_name=None):
    """
    Get workspace endpoint
    :param instance: instance client
    :param workspace_name: workspace name
    :param endpoint_name: endpoint type, like: LB_ENDPOINT, KE_ENDPOINT,
    SPARK_MASTER_BUILD_ENDPOINT, SPARK_MASTER_QUERY_ENDPOINT, KE_PRIVATE_IPS,
    SPARK_MASTER_PRIVATE_IPS_QUERY, SPARK_MASTER_PRIVATE_IP_BUILD,
    KI_PRIVATE_IPS, KI_ENDPOINT, MDX_ENDPOINT
    :return:
    """
    tar_ws = get_worksapce_by_name(instance, workspace_name)
    ws_endpoints = tar_ws['cluster']['endpoints']
    if endpoint_name:
        return next(filter(lambda ep: ep['name'] == endpoint_name.upper(), ws_endpoints))['url']
    else:
        return ws_endpoints



def replace_text(datadir, origin_file, replace_dict, new_file=None):
    with open(os.path.join(datadir, origin_file), 'r') as f:
        replace_str = f.read()
        for k, v in replace_dict.items():
            replace_str = re.sub(k, v, replace_str)
    if new_file:
        with open(os.path.join(datadir, new_file), 'w') as f:
            f.write(replace_str)
    return replace_str


def refresh_or_merge_segment_step(instance, workspace_name, project_name, model_name, segment_id, job_names,
                                  type='REFRESH'):
    instance.client.refresh_or_merge_segment(workspace_name, project_name, model_name, segment_id, type=type)
    assert instance.client.await_job_name_exist(workspace_name, project_name,
                                                job_names=job_names)
    list_jobs = instance.client.get_job_list(workspace_name, project_name)['value']
    job_id = list_jobs[0]['id']
    return job_id


def select_instance_to_stop(instance, cloud_instance, instance_name, vm_type, workspace_name):
    """
    select instance, and stop it
    :param instance:
    :param cloud_instance :
    :param instance_name: the name of instance
    :return:
    """
    await_instance_status(cloud_instance, vm_type, instance_name, expect_status=['running', 'ACTIVE'],
                          workspace_name=workspace_name)
    cloud_instance.stop_cloud_instance(resource_group=instance.resource_group, vm_name=instance_name)


def select_instance_to_start(instance, cloud_instance, instance_name):
    """
    select instance, and start it
    :param instance:
    :param cloud_instance :
    :param instance_name: the name of instance
    :return:
    """
    cloud_instance.start_cloud_instance(resource_group=instance.resource_group, vm_name=instance_name)


@await_with_retry(waiting_time=10, interval=60)
def await_instance_status(cloud_instance, vm_type, vm_name, expect_status, workspace_name=None):
    if isinstance(vm_type, str):
        vm_type = [vm_type]
    if workspace_name:
        resp = cloud_instance.get_instance_info(vm_type=vm_type, workspace_name=workspace_name)
    else:
        resp = cloud_instance.get_instance_info(vm_type=vm_type)
    if not resp:
        return False
    for info in resp[vm_type[0]]:
        if info[1] == vm_name and info[2] in expect_status:
            return True
