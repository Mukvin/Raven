import base64
import functools
import logging
import os
import time
import json
from retrying import retry
import requests
import rsa
from enum import Enum

from .basic import BasicHttpClient
from .common import InstanceTypeAttr


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
                    f'{func.__name__} is not getting target value, will sleep {interval} seconds')
                time.sleep(interval)
            timeout_message = f'{func.__name__} is out of waiting_time = {waiting_time} seconds'
            logging.error(timeout_message)
            if raise_exp_when_timeout:
                raise Exception(timeout_message)

        return wrapper

    return wrapper_job


def check_error_and_retry(waiting_time=5, interval=20, expect_error=TimeoutError):
    def wrapper_check(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            timeout = waiting_time * 60
            start_time = time.time()
            resp = None
            while time.time() - start_time < timeout:
                try:
                    resp = func(*args, **kwargs)
                    break
                except expect_error:
                    logging.debug(f'Request occur {expect_error.__name__}, retry after {interval}s')
                    time.sleep(interval)
            if time.time() - start_time > timeout:
                logging.debug(f'Request error after {timeout}s, raise TimeoutError')
                raise TimeoutError
            return resp

        return wrapper

    return wrapper_check


def await_worksapce_and_retry(waiting_time=10, interval=20, retry_times=1, raise_exp_when_timeout=True):
    """
    This decorator only use to workspace interface, please use utile.await_and_retry if want to use to other interface
    """

    def wrapper_job(func):
        @functools.wraps(func)  # func保留原始的信息
        def wrapper(*args, **kwargs):
            lightning_client = args[0]
            ws_names = args[1] if isinstance(args[1], list) else [args[1]]
            platform = args[2]
            if 'await' not in func.__name__:
                origin_status = None
            else:
                origin_status = dict()
                for ws_name in ws_names:
                    origin_status[ws_name] = [lightning_client.get_workspace_status(ws_name, platform), retry_times]
            logging.debug(f'Origin status is {origin_status}')
            timeout = waiting_time * 60
            start = time.time()
            while time.time() - start < timeout:
                try:
                    return_value = func(*args, **kwargs)
                    if return_value:
                        return return_value
                    err_ws = list()
                    for ws_name in ws_names:
                        ws_status = lightning_client.get_workspace_status(ws_name, platform)
                        if ws_status is None and origin_status[ws_name][0] == 'DELETING':
                            pass
                        elif ws_status == 'ERROR':
                            logging.debug(f'{ws_name} status is {ws_status}')
                            if origin_status[ws_name][0] == 'CREATING' and origin_status[ws_name][1] > 0:
                                logging.debug(f'Can retry {origin_status[ws_name][1]} times, retry start {ws_name}')
                                lightning_client.start_workspace(ws_name)
                                origin_status[ws_name][1] = origin_status[ws_name][1] - 1
                                start = time.time()
                            elif origin_status[ws_name][0] == 'DELETING' and origin_status[ws_name][1] > 0:
                                logging.debug(f'Can retry {origin_status[ws_name][1]} times, retry delete {ws_name}')
                                lightning_client.delete_workspace(ws_name)
                                origin_status[ws_name][1] = origin_status[ws_name][1] - 1
                                start = time.time()
                            else:
                                logging.debug(f'Stop retry {ws_name}')
                                if isinstance(args[1], list):
                                    logging.debug(f'Remove {ws_name} from {args[1]}')
                                    args[1].remove(ws_name)
                                    err_ws.append(ws_name)
                                    if len(args[1]) == 0:
                                        return False
                                else:
                                    timeout = 0
                    logging.debug(
                        f'{func.__name__} is not get target value, will sleep {interval} seconds')
                except requests.HTTPError as http_error:
                    logging.error(f'Exec {func.__name__} accur an requests.HTTPError {http_error}, '
                                  f'will sleep {interval} seconds')
                    if 'Access is denied' in http_error.args[0]:
                        raise requests.HTTPError(http_error.args[0], request=http_error.request,
                                                 response=http_error.response, )
                    if 'throw_err' in kwargs and kwargs.get('throw_err'):
                        raise requests.HTTPError(http_error.args[0], request=http_error.request,
                                                 response=http_error.response, )
                except requests.exceptions.ReadTimeout as e:
                    logging.error(f'{func.__name__} timeout and the error message is {e}, '
                                  f'do not need to retry, wait {interval} seconds')
                    time.sleep(interval)
                    return True
                except requests.exceptions.ConnectionError as e:
                    logging.error(f'{func.__name__} timeout and the error message is {e}, '
                                  f'will retry after {interval} seconds')
                except Exception as e:
                    logging.error(
                        f'Exec {func.__name__} accur an Exception {e}, error type is {type(e)}, will sleep {interval} seconds')
                    if 'Read timed out' in e and 'await' not in func.__name__:
                        logging.error(f'{func.__name__} timeout and the error message is {e}, '
                                      f'do not need to retry, wait {interval} seconds')
                        time.sleep(interval)
                        return True
                time.sleep(interval)
            timeout_message = f'{func.__name__} is out of waiting_time = {waiting_time} minetes'
            logging.error(timeout_message)
            if raise_exp_when_timeout:
                raise Exception(timeout_message)

        return wrapper

    return wrapper_job


class LightningHttpClient(BasicHttpClient):  # pylint: disable=too-many-public-methods
    _base_url = 'http://{host}:{port}'

    # _security_url = 'https://{host}:{port}/kylin/api'

    def __init__(self, host, port):
        super().__init__(host, port)
        self._public_accept = 'application/vnd.apache.kylin-v4-public+json'
        self._headers = {'Accept': self._public_accept,
                         'Accept-Language': 'en',
                         'Content-Type': 'application/json;charset=utf-8'
                         }
        self._private_headers = self._headers.copy()
        self._private_headers['Accept'] = 'application/json, text/plain, application/vnd.apache.kylin-v4+json'
        # self._auth = ('ADMIN', 'KYLIN')
        self._base_url = self._base_url.format(host=self._host, port=self._port)

    def set_headers(self, key, value=None, private=False):
        if private:
            if value is not None:
                self._private_headers[key] = value
            else:
                if key in self._private_headers.keys():
                    self._private_headers.pop(key)
        else:
            if value is not None:
                self._headers[key] = value
            else:
                if key in self._headers.keys():
                    self._headers.pop(key)

    def set_base_url(self, url):
        self._base_url = url

    def login(self, username, password, user_session=False):
        """
        use username and password login
        :param username: string, target group name
        :param password: array, the users add to group
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users/me/login'
        self.auth(username, password)
        self.set_headers('Accept', '')
        resp = self._request('PUT', url, inner_session=user_session)
        self.set_headers('Accept', self._public_accept)
        return resp

    def check_login_state(self):
        return self._request('GET', '/api/user/authentication', inner_session=True)

    def get_session(self):
        return self._inner_session

    def logout(self, user_session=False):
        # self._inner_session = requests.Session()
        """
        logout
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users/me/logout'
        resp = self._request('GET', url, inner_session=user_session)
        return resp

    def create_project(self, workspace_name, project_name, maintain_model_type='AUTO_MAINTAIN', description=None):
        url = '/api/projects/{workspace_name}'.format(workspace_name=workspace_name)
        data = {'name': project_name,
                'description': description or '',
                'maintain_model_type': maintain_model_type
                }
        resp = self._request('POST', url, json=data)
        return resp

    def clone_model(self, workspace_name, project, model_name, new_model_name):
        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/clone'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        payload = {
            'new_model_name': new_model_name,
            'project': project
        }
        resp = self._request('POST', url, headers=self._private_headers, json=payload)
        return resp

    def update_job_status(self, workspace_name, project_name=None, jobs=None, action=None,
                          status=None):
        """
        :param status: string, DISCARDED, ERROR, FINISHED, NEW, PENDING, RUNNING, STOPPED
        :param action: string, update status, DISCARD, ERROR, FINISHED, NEW, PENDING, RUNNING, STOPPED
        :param project_name: project name
        :param jobs: array[string]
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/jobs/status'
        payload = {
            'job_ids': jobs,
            'project': project_name,
            'action': action,
            'status': status
        }
        resp = self._request('PUT', url, json=payload, to_json=False)
        return resp

    def delete_job(self, workspace_name, project, job_ids=None, user_session=False):
        url = '/workspaces/{workspace_name}/kylin/api/jobs'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name)
        params = {
            'job_ids': job_ids,
            'project': project
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def await_all_jobs(self, workspace_name, project, waiting_time=30):
        """
        await all jobs to be finished, default timeout is 30 minutes
        :param workspace_name: workspace name
        :param project: project name
        :param waiting_time: timeout, in minutes
        :return: boolean, timeout will return false
        """
        running_flag = ['PENDING', 'RUNNING']
        try_time = 0
        max_try_time = waiting_time * 2
        # finish_flags = ['ERROR', 'FINISHED', 'DISCARDED']
        while try_time < max_try_time:
            jobs = self.get_job_list(workspace_name, project=project, time_filter=0)
            if not jobs['value']:
                continue
            all_finished = True
            for job in jobs['value']:
                if job['job_status'] in running_flag:
                    all_finished = False
                if job['job_status'] == 'ERROR':
                    logging.debug(f"{job['target_subject']}'s job {job['id']} failed")
                    return False
            if all_finished:
                return True
            time.sleep(30)
            try_time += 1
        return False

    def await_workspace(self, workspace_name, cloud, waiting_time=30, interval=20, expected_status=None):
        """
        Await specific job to be given status, default timeout is 20 minutes.
        :param workspace_name: workspace name
        :param cloud: the type of cloud
        :param waiting_time: timeout, in minutes.
        :param interval:
        :param expected_status: excepted job status list, default contains 'ERROR', 'FINISHED'
        and 'DISCARDED'
        :return: boolean, if the job is in finish status, return true
        """
        return self.await_all_workspace([workspace_name], cloud, expected_status, waiting_time, interval)

    def await_workspace_running(self, workspace_name, cloud):
        """
        Await specific job to be finished, default timeout is 20 minutes.
        :param workspace_name: workspace name
        :param cloud: the type of cloud
        :return: boolean, if the job is in finish status, return true
        """
        return self.await_all_workspace([workspace_name], cloud, expected_status=['RUNNING'])

    def set_system_prop(self, key, value, server=None):
        """
        This api is not allowed to use directly.
        if you want to set system props, please follow the Usage.

        Usage:

            @pytest.hookimpl
            def pytest_create_system_prop(instance, request):
                return [{'key':'...','value':'...'}, ...]

            @pytest.mark.usefixtures('setup_system_prop')
            def start(instance, project):
                ...

        """
        url = '/api/admin/config'
        payload = {
            'key': key,
            'value': value,
            'server': server
        }
        self._request('PUT', url, json=payload)

    def get_all_system_prop(self, server=None):
        url = '/api/admin/config'
        if server is not None:
            url = '/api/admin/config?server={serverName}'.format(serverName=server)
        prop_resp = self._request('GET', url)
        property_values = {}
        if prop_resp is None:
            return property_values
        prop_lines = prop_resp.splitlines(False)
        for prop_line in prop_lines:
            splits = prop_line.split('=')
            property_values[splits[0]] = splits[1]
        return property_values

    def create_group(self, group_name, user_session=False):
        """
        create a group with group_name
        :param group_name:  string, target group name
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/{group_name}'.format(group_name=group_name)
        resp = self._request('POST', url, inner_session=user_session)
        return resp

    def get_user_list(self, username=None, is_case_sensitive=None, offset=None, size=None,
                      user_session=False):
        """
        get user list
        :param username: string, target user name
        :param is_case_sensitive: string, target password
        :param offset: int, page offset
        :param size: int, page size
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users'
        params = {}
        if username is not None:
            params['name'] = username
        if is_case_sensitive is not None:
            params['is_case_sensitive'] = is_case_sensitive
        if offset is not None:
            params['page_offset'] = offset
        if size is not None:
            params['page_size'] = size
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def create_user(self, username, password, authorities, user_session=False):
        """
        create a user
        :param username: string, target user name
        :param password: string, target password
        :param authorities: array, user's authorities
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users'
        payload = {
            'username': username,
            'password': password,
            'authorities': authorities,
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def modify_user_info(self, username, authorities, enabled, user_session=False):
        """
        modify user info
        :param username: string, target user name
        :param authorities: array, user's authorities
        :param enabled: boolean, true for enable user false for disable user
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users'
        payload = {
            'username': username,
            'authorities': authorities,
            'enabled': enabled,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def modify_user_pwd(self, username, password, user_session=False):
        """
        modify user password
        :param username: string, target user name
        :param password: string, target password
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users/password'
        payload = {
            'name': username,
            'password': password,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def delete_user(self, username, user_session=False):
        """
        delete user
        :param username: string, target user name
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users/{username}'.format(username=username)
        resp = self._request('DELETE', url, inner_session=user_session)
        return resp

    def get_usergroup_list(self, offset=None, size=None, user_session=False):
        """
        get group list
        :param offset: int, page offset
        :param size: int, page size
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/groups'
        params = {}
        if offset is not None:
            params['page_offset'] = offset
        if size is not None:
            params['page_size'] = size
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def get_users_in_group(self, group_name, offset=None, size=None, user_session=False):
        """
        get users in group
        :param group_name: string, target group name
        :param offset: int, page offset
        :param size: int, page size
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/group_members/{group_name}'.format(group_name=group_name)
        params = {}
        if offset is not None:
            params['page_offset'] = offset
        if size is not None:
            params['page_size'] = size
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def add_usergroup(self, group_name, user_session=False):
        """
        add a new group
        :param group_name: string, target group name
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/{group_name}'.format(group_name=group_name)
        resp = self._request('POST', url, inner_session=user_session)
        return resp

    def delete_group(self, group_name, user_session=False):
        """
        delete an usergroup
        :param group_name: string, target group name
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/{group_name}'.format(group_name=group_name)
        resp = self._request('DELETE', url, inner_session=user_session)
        return resp

    def update_user_in_group(self, group, names, user_session=False):
        """
        update user in group
        :param group: string, target group name
        :param names: array, the users add to group
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/user_group/users'
        payload = {
            'group': group,
            'names': names,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def _request(self, method, url, **kwargs):  # pylint: disable=arguments-differ
        url = url if 'http' in url else ''.join((self._base_url, url))
        return super()._request(method, url, **kwargs)

    def _get_orgid(self):
        url = '/api/users/me'
        resp = self._request('GET', url, headers=self._private_headers, json={})
        return resp['uuid']

    def get_rsa_public_key(self):
        url = '/api/utils/rsa_public_key'
        import_headers = self._headers.copy()
        import_headers['Accept'] = 'application/json, text/plain, application/vnd.apache.kylin-v4+json'
        resp = self._request('GET', url, headers=self._private_headers)
        return resp['datas'][0]

    def set_secret(self, cloud, display_name, username='azureuser', secret='', user_session=False):
        orgid = self._get_orgid()
        import_headers = self._headers.copy()
        import_headers['Accept'] = 'application/json, text/plain, application/vnd.apache.kylin-v4+json'
        url = '/api/secrets'
        payload = {
            "displayName": display_name,
            "username": username,
            "credentialType": "PASSWORD",
            "secret": self._rsa_encrypt(secret),
            "description": "",
            "publicKey": "",
            "privateKey": "",
            "fingerPrint": "",
            "environment": cloud
        }
        resp = self._request('POST', url, params={'orgid': orgid}, json=payload,
                             headers=self._private_headers, inner_session=user_session)
        return resp

    def stop_status_update_cluster(self, cluster_id, payload, user_session=False):
        """
        stop status update cluster
        :param cluster_id: cluster id
        :param payload: json, cluster info
        :return:
        """
        url = '/api/clusters/{cluster_id}'.format(cluster_id=cluster_id)
        resp = self._request('PUT', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def change_account_password(self, cluster_id, azure_account_key, user_session=False):
        data_source_account_key = self._rsa_encrypt(azure_account_key)
        url = '/api/clusters/{cluster_id}/change_account_password'.format(cluster_id=cluster_id)
        payload = {
            "dataSourceAccountKey": data_source_account_key
        }
        resp = self._request('PUT', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_cluster_info(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = list(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        return message[0]['cluster']

    def get_cluster_id(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = list(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        return message[0]['cluster']['id']

    def get_workspace_id(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = list(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        return message[0]['id']

    def get_workspace_status(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = list(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        if not message:
            return None
        return message[0]['cluster']['status']

    def start_workspace(self, workspace_name, user_session=False):
        url = f'/api/workspaces/{workspace_name}/start'
        resp = self._request('PUT', url, inner_session=user_session)
        return resp

    def stop_workspace(self, workspace_name, user_session=False):
        url = f'/api/workspaces/{workspace_name}/stop'
        resp = self._request('PUT', url, inner_session=user_session)
        return resp

    def delete_workspace(self, workspace_name, destroy_data=True, destroy_storage=True, user_session=False):
        url = f'/api/workspaces/{workspace_name}'
        params = {
            'destroy_data': destroy_data,
            'destroy_storage': destroy_storage,
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def grant_workspace_permission(self, workspace, type, names, permission, user_session=False,
                                   stream=False):
        """
        grant workspace permission
        :param workspace: string, the name of workspace
        :param type: string, the users or groups, optional value 'user'、'group'
        :param names: array[string], the users or groups list
        :param permission: string, permission, optional value VIEWER、ANALYST、OPERATION、 MANAGEMENT、ADMINISTRATION
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/access/workspaces/{workspace}'.format(workspace=workspace)
        payload = {
            'type': type,
            'names': names,
            'permission': permission
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session, stream=stream)
        return resp

    def get_workspace_permission(self, workspace, name=None, page_offset=0, page_size=1000,
                                 user_session=False):
        """
        get workspace permission
        :param workspace: string, the name of workspace
        :param name: string, the name of user or group
        :param page_offset: offset of returned result
        :param page_size: quantity of returned result per page
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/access/workspaces/{workspace}'.format(workspace=workspace)
        params = {
            'name': name,
            'page_offset': page_offset,
            'page_size': page_size,
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def update_ke_config(self, cluster_id, ke_config):
        """
        update ke config
        :param cluster_id: cluster id
        :param ke_config: ke config string
        :return:
        """
        ke_config_base64 = base64.b64encode(ke_config.encode('utf-8')).decode()
        update_ke_config_url = '/api/ke/config/update'
        body = {
            'clusterId': cluster_id,
            'encodedConfig': ke_config_base64
        }
        resp = self._request('POST', update_ke_config_url, json=body, headers=self._private_headers)
        return resp

    def restart_ke(self, cluster_id):
        """
        Restart KE
        :param cluster_id: cluster id
        :return:
        """
        restart_ke_url = '/api/ke/restart'
        params = {
            'id': cluster_id,
        }
        resp = self._request('GET', restart_ke_url, params=params, headers=self._private_headers)
        return resp

    def load_sample_data(self, project_name, cluster_id, user_session=False):
        url = '/api/sample/{cluster_id}/load_samples'.format(cluster_id=cluster_id)
        payload = {
            'project': project_name
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers, timeout=180,
                             inner_session=user_session)
        return resp

    def load_data(self, workspace_name, project_name, model_name, start=1, end=1627022429000, user_session=False):
        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        payload = {
            'project': project_name,
            'start': start,
            'end': end
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def delete_model(self, workspace_name, project, model_name, user_session=False):
        """
        delete model
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        params = {
            'project': project
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def build_index(self, workspace_name, project, model_name, user_session=False):
        """
        build index
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project_name
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/indexes'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        params = {
            'project': project
        }
        resp = self._request('POST', url, json=params, inner_session=user_session)
        return resp

    def get_job_list(self, workspace_name, project=None, time_filter=0, page_offset=0,
                     page_size=10000, sort_by='last_modified', reverse=True, key=None,
                     user_session=False):
        """
        get job list
        :param workspace_name: string, the name of workspace
        :param time_filter: int, the value in[0,1,2,3,4],corresponding description 0:last day，1：last week，2：last month，
        3：last year，4：all
        :param project: string, the name of project
        :param page_offset: offset of returned result
        :param page_size: quantity of returned result per page
        :param sort_by: string, sort field
        :param reverse: boolean, whether reverse order
        :param key: string, filter field, currently supports job id and job object name
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/jobs'.format(
            host=self._host, port=self._port, workspace_name=workspace_name)
        params = {
            'time_filter': time_filter,
            'project': project,
            'page_offset': page_offset,
            'page_size': page_size,
            'sort_by': sort_by,
            'reverse': reverse,
            'key': key
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def get_job(self, workspace_name, project_name, job_id):
        all_job = self.get_job_list(workspace_name, project_name)['value']
        for job in all_job:
            if job['id'] == job_id:
                return job
        return None

    def get_job_detail(self, workspace_name, project_name, job_id):
        """
        get job detail, for example, build index include 3-steps: 1. Detect Resource, 2.Load Data To Index, 3. Update Metadata
        :param workspace_name: string, the name of workspace
        :param project_name: string, name of project
        :param job_id: string, id of job, should get from #get_job_list
        :return: job detail
        """
        url = f'/workspaces/{workspace_name}/kylin/api/jobs/{job_id}/detail'
        params = {
            'project': project_name,
            'job_id': job_id
        }
        resp = self._request('GET', url, params=params)
        return resp

    def get_segment(self, workspace_name, project, model_name, page_offset=0, page_size=10000,
                    start=1, end=9223372036854775806, user_session=False):
        """
        get segment
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project_name
        :param model_name: string, the name of model
        :param page_offset: offset of returned result
        :param page_size: quantity of returned result per page
        :param start: string, Segments start time, default is 1, timestamp type, milliseconds
        :param end: string, Segments end time, default is 1, timestamp type, milliseconds
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        params = {
            'project': project,
            'page_offset': page_offset,
            'page_size': page_size,
            'start': start,
            'end': end
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def refresh_or_merge_segment(self, workspace_name, project, model_name, ids, type,
                                 user_session=False):
        """
        refresh or merge segment
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project_name
        :param model_name: string, the name of model
        :param ids: array[string], the segments id
        :param type: string, the value is REFRESH or MERGE。 refresh Segments or merge segment
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        params = {
            'project': project,
            'type': type,
            'ids': ids
        }
        resp = self._request('PUT', url, json=params, inner_session=user_session)
        return resp

    def delete_segment(self, workspace_name, project, model_name, purge, ids=None, force=False,
                       names=None, user_session=False):
        """
        delete segment
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project_name
        :param model_name: string, the name of model
        :param purge: boolean，whether clear Segments or not
        :param ids: array[string], Segments id
        :param force: boolean, Whether to force delete
        :param names: array[string], Segments name list
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name,
                   model_name=model_name)
        params = {
            'project': project,
            'purge': purge,
            'ids': ids or [],
            'force': force,
            'names': names or []
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def await_job(self, workspace_name, project_name, job_id, waiting_time=20, interval=30,
                  excepted_status=None, init_waiting_time=10):
        """
        Await specific job to be given status, default timeout is 20 minutes.
        :param workspace_name: the name of the workspace
        :param project_name: project name of the job
        :param job_id: id of the job
        :param waiting_time: timeout, in minutes.
        :param interval: check interval, default value is 1 second
        :param excepted_status: excepted job status list, default contains 'ERROR', 'FINISHED' and 'DISCARDED'
        :return: boolean, if the job is in finish status, return true
        """

        finish_flags = ['ERROR', 'FINISHED', 'DISCARDED']
        if excepted_status is None:
            excepted_status = finish_flags
        timeout = waiting_time * 60
        start = time.time()
        time.sleep(init_waiting_time)
        while time.time() - start < timeout:
            job_status = self.get_job(workspace_name, project_name, job_id)['job_status']
            logging.debug(f"{job_id} in {project_name}'s status is {job_status}")
            if job_status in excepted_status:
                return True
            if job_status in finish_flags:
                return False
            time.sleep(interval)
        return False

    def await_job_name_exist(self, workspace_name, project_name, job_names, waiting_time=60,
                             interval=1):
        """
        wait job exist in job list after submit job
        :param project_name: string, project name
        :param job_names: list, expected job names list
                         eg: ['INDEX_REFRESH', 'INDEX_BUILD', 'INDEX_BUILD', 'TABLE_SAMPLING', 'INC_BUILD']
        :param waiting_time: int, minutes to wait job name exist in job list
        :param interval: int, interval time to get list jobs
        :return:
        """
        timeout = waiting_time * 60
        start = time.time()
        while time.time() - start < timeout:
            jobs = self.get_job_list(workspace_name, project_name)['value']
            project_job_names = [job['job_name'] for job in jobs if job['project'] == project_name]
            logging.debug(f'jobs is {jobs}')
            if jobs and sorted(project_job_names) == sorted(job_names):
                return True
            time.sleep(interval)
        return False

    @await_with_retry()
    def waiting_job_exists(self, workspace_name, project_name, job_id):
        jobs = self.get_job_list(workspace_name, project_name)['value']
        if len(list(filter(lambda job: job['id'] == job_id, jobs))) == 1:
            return True

    def get_model(self, workspace_name, project, model_name=None, page_offset=0, page_size=10000,
                  status=None, exact=False, user_session=False):
        """
        get model list
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model
        :param page_offset: offset of returned result
        :param page_size: quantity of returned result per page
        :param status: string, model status
        :param exact: boolean, whether exactly match the model name
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/models'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name)
        params = {
            'project': project,
            'page_offset': page_offset,
            'page_size': page_size,
            'status': status,
            'model_name': model_name,
            'exact': exact
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def update_table_permission(self, workspace_name, type, name, project, database_name, tables,
                                user_session=False):
        """
        update table permission
        :param workspace_name: string the name of workspace
        :param type: string the user type, the value is user or group
        :param name: string the user or group name
        :param project: string the name of project
        :param database_name: string the name of database
        :param tables: list the info of tables
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/acl/{type}/{name}?project={project}'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name, type=type,
                   name=name, project=project)
        params = [{
            'database_name': database_name,
            'tables': tables
        }]
        resp = self._request('PUT', url, json=params, inner_session=user_session)
        return resp

    def get_table_permission(self, workspace_name, type, name, project, authorized_only=False,
                             user_session=False):
        """
        update table permission
        :param workspace_name: string the name of workspace
        :param type: string the user type, the value is user or group
        :param name: string the user or group name
        :param project: string the name of project
        :param authorized_only: whether to return only authorized table rows and columns
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/acl/{type}/{name}'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name, type=type,
                   name=name)
        params = {
            'authorized_only': authorized_only,
            'project': project
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def get_exportable_models(self, workspace_name, project, model_names=None, user_session=False):
        """
        get exportable models
        :param workspace_name: string the name of workspace
        :param project: string the name of project
        :param model_names: list the name of model_names
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/metastore/previews/models'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name)
        params = {
            'project': project,
            'model_names': model_names or []
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def export_model_metadata(self, workspace_name, project, names, export_recommendations=False,
                              export_over_props=False, export_multiple_partition_values=False, stream=True,
                              user_session=False):
        """
        export model metadata
        :param workspace_name: string the name of workspace
        :param project: string the name of project
        :param names: array[string] the name of project
        :param export_recommendations: bool whether to export the optimization suggestions of the model
        :param export_over_props: bool whether to export the rewrite configuration of the model
        :param export_multiple_partition_values: bool whether to export the multi-level partition value of the model
        :param stream: bool
        :return:
        """

        url = '/workspaces/{workspace_name}/kylin/api/metastore/backup/models?project={project}'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name, project=project)
        payload = {
            'names': names,
            'export_recommendations': export_recommendations,
            'export_over_props': export_over_props,
            'export_multiple_partition_values': export_multiple_partition_values

        }
        resp = self._request('POST', url, json=payload, stream=stream, inner_session=user_session)
        return resp

    def import_model_metadata(self, workspace_name, project, file_path, request_path):
        """
        import model metadata
        :param workspace_name: string the name of workspace
        :param project: string the name of project
        :param request_path: string the name of original model
        :param file_path: MultipartFile full path of zip file
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/metastore/import/models?project={project}'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name, project=project)
        import_headers = self._headers.copy()
        import_headers.pop('Content-Type')

        with open(file_path, 'rb') as f, open(request_path, 'rb') as r_f:
            files = [
                ('file', (os.path.basename(file_path), f, 'application/zip')),
                ('request', (os.path.basename(request_path), r_f, 'application/json'))
            ]
            resp = self._request('POST', url, headers=import_headers, files=files)

        return resp

    def upload_and_check_model_metadata(self, workspace_name, project, file_path):
        """
        check imported zip file is validate
        :param project: string, project name
        :param file_path: string, full path of zip file
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/metastore/validation/models?project={project}'. \
            format(host=self._host, port=self._port, workspace_name=workspace_name, project=project)
        import_headers = self._private_headers.copy()
        import_headers['Accept'] = 'application/vnd.apache.kylin-v4+json'
        import_headers.pop('Content-Type')
        with open(file_path, 'rb') as f:
            file = [('file', (os.path.basename(file_path), f))]
            resp = self._request('POST', url, headers=import_headers, files=file)

        return resp

    def update_license(self, license, user_session=False):
        url = '/api/config/license'.format(host=self._host, port=self._port)
        payload = {
            'license': license
        }
        resp = self._request('PUT', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def get_keypairs(self, platform_info='aws', user_session=False):
        url = f'/api/{platform_info}/keypairs'
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    @await_worksapce_and_retry(waiting_time=5, interval=60, retry_times=3)
    def create_aws_workspace(self, workspace, cloud, key_name, user_session=False,
                             **kwargs):

        orgid = self._get_orgid()
        url = '/api/workspaces?orgid={orgid}'.format(orgid=orgid)
        bucket_name = kwargs['s3bucket']
        payload = {
            "sourceType": "SPARKSQL",
            "kdu": 1,
            "projectRequest": {
                "name": workspace,
                "maintain_model_type": "MANUAL_MAINTAIN",
                "override_kylin_properties": {}
            },
            "sourceRequest": {
                "url": "",
                "username": "",
                "password": "",
                "sourceType": "SPARKSQL"
            },
            "environment": cloud,
            "cluster": {
                "name": workspace,
                "status": "NEW",
                "vendor": "AWS",
                "topology": "RW_SEPARATED",
                "environment": cloud,
                "managed": True,
                "installKI": False,
                "storageVersion": 1,
                "hadoopClusters": [{
                    "classType": "aws",
                    "hadoopRole": "SEPARATED_QUERY",
                    "upperLimit": 0,
                    "highAvailable": False,
                    "autoScale": True,
                    "lowerLimit": 0,
                    "s3bucket": bucket_name,
                    "managedStorage": kwargs['managed_storage'],
                    "masterNodeSize": kwargs['query_master_node_size'],
                    "masterNodeStorageType": "SSD",
                    "alluxioNodeSize": kwargs['alluxio_node_size'],
                    "alluxioNodeStorage": 100,
                    "alluxioNodeStorageType": "SSD",
                    "masterNodeStorage": 100,
                    "workNodeStorage": 400,
                    "workNodeSize": kwargs['query_work_node_size'],
                    "workNodeCount": kwargs['query_work_node_count'],
                    "workNodeStorageType": kwargs['query_work_node_storage_type'],
                    "edgeNodeSize": kwargs['edge_node_size'],
                    "edgeNodeCount": kwargs['edge_node_count'],
                    "edgeNodeStorageType": kwargs['edge_node_storage_type'],
                    "spot": False,
                    "spotWorkerNodeSize": "",
                    "spotWorkerNodeCount": 0,
                    "edgeNodeStorage": 100,
                    "sshCred": {
                        "displayName": key_name
                    },
                    "region": "",
                    "name": workspace
                }, {
                    "name": workspace,
                    "hadoopRole": "SEPARATED_COMPUTE",
                    "classType": "aws",
                    "autoScale": True,
                    "upperLimit": kwargs['build_upper_limit'],
                    "lowerLimit": kwargs['build_lower_limit'],
                    "masterNodeSize": kwargs['build_master_node_size'],
                    "masterNodeStorage": 100,
                    "masterNodeStorageType": "SSD",
                    "workNodeSize": kwargs['build_work_node_size'],
                    "workNodeStorage": 400,
                    "workNodeCount": kwargs['build_work_node_count'],
                    "workNodeStorageType": kwargs['build_work_node_storage_type']
                }],
                "tags": json.dumps(kwargs['Tags'])
            }
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def get_buckets(self, user_session=False):
        url = '/api/aws/s3/buckets'.format(host=self._host, port=self._port)
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_work_node_count(self, workspace_name, cloud='AzureChinaCloud', instance_type=InstanceTypeAttr.QUERY):
        """
        Get count of worker node
        :param workspace_name: string, name of workspace
        :param cloud: string, cloud name
        :param instance_type: string, instance type
        :return:
        """
        resp = self.get_workspace_list(cloud)
        message = next(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        if instance_type not in [InstanceTypeAttr.QUERY, InstanceTypeAttr.BUILD,
                                 InstanceTypeAttr.EDGE, InstanceTypeAttr.KI, InstanceTypeAttr.MDX]:
            logging.error("Unexpected work type, it should be %s, %s, %s, %s, %s,",
                          InstanceTypeAttr.QUERY,
                          InstanceTypeAttr.BUILD, InstanceTypeAttr.EDGE, InstanceTypeAttr.KI,
                          InstanceTypeAttr.MDX)
            raise ValueError
        return message['cluster']['hadoopClusters'][instance_type.value[1]][instance_type.value[2]]

    def get_ki_and_mdx_status(self, workspace_name, cloud='AzureChinaCloud', instance_type=InstanceTypeAttr.KI):
        """
        Get install status of ki & mdx
        :param workspace_name: string, name of workspace
        :param cloud: string, cloud name
        :param instance_type: string, instance type
        :return:
        """
        resp = self.get_workspace_list(cloud)
        message = next(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        if instance_type not in [InstanceTypeAttr.KI, InstanceTypeAttr.MDX]:
            logging.error("Unexpected Instance type, it should be %s or %s", InstanceTypeAttr.KI,
                          InstanceTypeAttr.MDX)
            raise ValueError
        return message['cluster'][instance_type.value[3]]

    def resize_worker(self, cluster_id, upper_limit=15, lower_limit=1, work_node_count=1,
                      user_session=False):
        url = '/api/clusters/{cluster_id}/resize'.format(cluster_id=cluster_id)
        import_headers = self._private_headers.copy()
        import_headers.pop('Content-Type')
        payload = {
            'workNodeCount': work_node_count,
            'upperLimit': upper_limit,
            'lowerLimit': lower_limit
        }
        resp = self._request('PUT', url, params=payload, headers=import_headers, inner_session=user_session)
        return resp

    def resize_engine(self, cluster_id, edge_node_count, user_session=False):
        url = '/api/clusters/{cluster_id}/scale?edgeNodeCount={edge_node_count}' \
            .format(cluster_id=cluster_id, edge_node_count=edge_node_count)
        import_headers = self._private_headers.copy()
        import_headers.pop('Content-Type')
        payload = {
            'edgeNodeCount': edge_node_count
        }
        resp = self._request('PUT', url, params=payload, headers=import_headers, inner_session=user_session)
        return resp

    def get_spark_url(self, workspace_name, cloud='AzureChinaCloud', instance_type=InstanceTypeAttr.QUERY):
        resp = self.get_workspace_list(cloud)
        message = next(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        if instance_type not in [InstanceTypeAttr.QUERY, InstanceTypeAttr.BUILD]:
            logging.error("Unexpected work type, it should be %s or %s", InstanceTypeAttr.QUERY,
                          InstanceTypeAttr.BUILD)
            raise ValueError
        name = ((instance_type is InstanceTypeAttr.BUILD and 'SPARK_MASTER_BUILD_ENDPOINT') or
                'SPARK_MASTER_QUERY_ENDPOINT')
        endpoints_message = next(
            filter(lambda msg: msg['name'] == name, message['cluster']['endpoints']))
        return endpoints_message['url']

    def get_spark_application_page(self, spark_application_url, inner_session=False):
        resp = self._request('GET', spark_application_url, headers=self._private_headers,
                             inner_session=inner_session, to_json=False)
        return resp

    def wizard_check_table_exist(self, workspace_id, database, table, user_session=False):
        """
        wizard check table exist in database
        :param workspace_id: int, workspace id
        :param database: string, database name
        :param table: string, table name
        :param user_session
        :return:
        """
        url = f'/api/spark_source/{database}/{table}'
        params = {
            'workspaceId': workspace_id,
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def wizard_infer_table(self, workspace_id, database, table, bucket, directory, data_type='csv', delimiter=',',
                           quote='\"', header=False, from_upload=False, num=3, user_session=False):
        """
        infer table before create table on wizard mode
        :param workspace_id: int, workspace id
        :param database: string, database name
        :param table: string, table name
        :param bucket: string, bucket name on cloud object storage
        :param directory: string, directory in bucket
        :param data_type: string, csv, orc, parquet
        :param delimiter: string, delimiter in data
        :param quote: string, quote in data
        :param header: boolean, is first line header in data
        :param from_upload: is uploaded data
        :param num:
        :param user_session:
        :return:
        """
        data_type = data_type if data_type in ('csv', 'parquet', 'orc') else 'csv'
        url = f'/api/spark_source/{data_type}/infer'
        payload = {
            'database': database,
            'table': table,
            'delimiter': delimiter,
            'quote': quote,
            'bucket': bucket,
            'directory': directory,
            'header': header,
            'num': num,
            'workspaceId': workspace_id,
            'fromUpload': from_upload,
        }
        resp = self._request('POST', url, headers=self._private_headers, json=payload, inner_session=user_session)
        return resp

    def wizard_samples(self, workspace_id, bucket, directory, data_type='csv', from_upload=False, user_session=False):
        """
        sample data when create table on wizard mode
        :param workspace_id: int, workspace id
        :param bucket: string, bucket name on cloud object storage
        :param directory: string, directory in bucket
        :param data_type: string, csv, orc, parquet
        :param from_upload: is uploaded data
        :param user_session:
        :return:
        """
        data_type = data_type if data_type in ('csv', 'parquet', 'orc') else 'csv'
        url = f'/api/spark_source/{data_type}/samples'
        payload = {
            'bucket': bucket,
            'directory': directory,
            'workspaceId': workspace_id,
            'fromUpload': from_upload,
        }
        resp = self._request('POST', url, headers=self._private_headers, json=payload, inner_session=user_session)
        return resp

    def wizard_create_table(self, table_data, table_name, workspace_id, data_type='csv', user_session=False):
        """
        wizard create table
        :param table_data: string, the name of database
        :param table_name: string, table name
        :param data_type: string, csv, orc, parquet
        :param workspace_id: int, workspace Id
        :param user_session:
        :return:
        """
        data_type = data_type if data_type in ('csv', 'parquet', 'orc') else 'csv'
        url = f'/api/spark_source/{data_type}/create_table'
        table_data['table'] = table_name
        table_data['workspaceId'] = workspace_id
        payload = table_data
        resp = self._request('POST', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_worker_scope(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = next(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        return message['cluster']['hadoopClusters'][1]['upperLimit'], \
               message['cluster']['hadoopClusters'][1]['lowerLimit']

    def delete_project(self, workspace_name, project_name, user_session=False):
        url = f'/workspaces/{workspace_name}/kylin/api/projects/{project_name}'
        resp = self._request('DELETE', url, inner_session=user_session)
        return resp

    def ddl_create_table(self, workspace_name, database, sql, user_session=False):
        """
        DDL create table
        :param workspace_name: string, the name of workspace
        :param database: string, the name of database
        :param sql: string, statement to be executed
        :return:
        """
        url = '/api/spark_source/workspaces/{workspace_name}/execute'.format(
            workspace_name=workspace_name)
        payload = {
            'database': database,
            'sql': sql,
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def load_table(self, workspace_name, project, datasource_type, need_sampling=False,
                   sampling_rows=20000000,
                   databases=None, tables=None, user_session=False):
        """
        load tables
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param datasource_type: int, data_source type, fill in 8 for jdbc data source and 9 for others
        :param need_sampling: boolean, whether to enable table sampling
        :param sampling_rows: int, the maximum limit of the number of sampling rows, the value range is [10000-20000000]
        :param databases: [string], load all tables in the database
        :param tables: [string], specify the table you want to load, in the format: DB.TABLE
        :return:
        """
        url = '/api/tables/workspaces/{workspace_name}/load'.format(workspace_name=workspace_name)
        payload = {
            'datasourceType': datasource_type,
            'project': project,
            'need_sampling': need_sampling,
            'sampling_rows': sampling_rows,
            'databases': databases or [],
            'tables': tables or []
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def reload_table(self, workspace_name, project, table, need_sampling=False,
                     sampling_rows=20000000,
                     need_build=False, user_session=False):
        """
        reload tables,
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param need_sampling: boolean, whether to enable table sampling
        :param sampling_rows: int, the maximum limit of the number of sampling rows, the value range is [10000-20000000]
        :param table: [string], specify the table you want to load, in the format: DB.TABLE
        :param need_build: boolean, whether to update the model
        :return:
        """
        url = '/api/tables/workspaces/{workspace_name}/reload'.format(workspace_name=workspace_name)
        payload = {
            'project': project,
            'need_sampling': need_sampling,
            'sampling_rows': sampling_rows,
            'table': table,
            'need_build': need_build
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def submit_sampling(self, workspace_name, project, qualified_table_name, rows=20000000,
                        user_session=False):
        """
        reload tables,
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param qualified_table_name: [string], specify the table you want to load, in the format: DB.TABLE
        :param rows: integer, the maximum limit of the number of sampling rows, the value range is [10000-20000000]
        :return:
        """
        url = '/api/tables/workspaces/{workspace_name}/sampling'.format(workspace_name=workspace_name)
        payload = {
            'project': project,
            'qualified_table_name': qualified_table_name,
            'rows': rows,
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def execute_query(self, workspace_name, project, sql, offset=0, limit=500, forced_to_push_down=None,
                      partialMatchIndex=False, user_session=False, timeout=360):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param sql: query sql
        :param offset: offset of returned result
        :param limit: limit of returned result
        :param forced_to_push_down: query whether to force down
        :param timeout: session timeout time
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/query' \
            .format(host=self._host, port=self._port, workspace_name=workspace_name)
        payload = {
            'forcedToPushDown': forced_to_push_down,
            'limit': limit,
            'offset': offset,
            'project': project,
            'sql': sql,
            'partialMatchIndex': partialMatchIndex
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session, timeout=timeout)
        return resp

    def create_model(self, workspace_name, model_desc_data, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param model_desc_data: json, path src/data/{module_name}
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/models' \
            .format(host=self._host, port=self._port, workspace_name=workspace_name)
        payload = model_desc_data
        resp = self._request('POST', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def sampling_jobs(self, cluster_id, project, table_name, rows=20000000, user_session=False):
        """
        exit table sampling
        :param cluster_id: id of workspaces
        """
        url = '/api/tables/{cluster_id}/sampling_jobs'.format(cluster_id=cluster_id)
        payload = {
            "project": project,
            "qualified_table_name": table_name,
            "rows": rows
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def add_aggregate_indices(self, workspace_name, project, model_id, agg_groups, load_data=False,
                              global_dim_cap=None, user_session=False):
        """
        Add aggregate index
        :param workspace_name: workspace name
        :param project: project name
        :param model_id: model id
        :param agg_groups: aggregate groups
        :param load_data: boolean, load data or not, if set to True, will trigger a build job
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/index_plans/rule' \
            .format(host=self._host, port=self._port, workspace_name=workspace_name)
        payload = {
            'project': project,
            'model_id': model_id,
            'aggregation_groups': agg_groups,
            'load_data': load_data,
            'global_dim_cap': global_dim_cap
        }
        resp = self._request('PUT', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def add_table_indices(self, workspace_name, project, model_id, col_order, indices_id=None,
                          # pylint: disable=R0913
                          sort_by_cols=None, shard_by_cols=None, load_data=True,
                          user_session=False):
        """
        Add table index
        :param name: string
        :param indices_id:
        :param layout_override_indexes:
        :param storage_type:
        :param project_name: project name
        :param model_id: model id
        :param col_order: list of col order
        :param sort_by_cols: sort by columns
        :param shard_by_cols: shard_by_columns
        :param load_data: boolean, load data or not, if set to True, will trigger a build job
        :return:
        """
        url = '/workspaces/{workspace_name}/kylin/api/index_plans/table_index' \
            .format(host=self._host, port=self._port, workspace_name=workspace_name)
        payload = {
            'col_order': col_order,
            'project': project,
            'id': indices_id or '',
            'model_id': model_id,
            'sort_by_columns': sort_by_cols or [],
            'shard_by_columns': shard_by_cols or [],
            'load_data': load_data,
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def get_created_tables(self, workspace_id, project, database_name):
        """
        get loaded tables
        :param workspace_name: string, workspace name
        :param workspace_id: string, workspace id
        :param project: string, project !!!IMPORTANT!!! - project should exist is workspace,
        other-wise, throw http-500 error
        :param database_name: string, database name
        :return : loaded tables , example  {"data":[{"tableName":"CUSTOMER","loaded":true},
        {"tableName":"LINEITEM","loaded":true}],"msg":null,"code":"000","totalRecords":2}
        """
        url = f'/api/spark_source/{database_name}/tables'
        params = {
            'workspaceId': workspace_id,
            'project': project,
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers)
        return resp

    def get_project_tables(self, workspace_id, project_name):
        """"
        :param workspace_id: workspace id
        :param project_name project name
        """
        url = f'/api/tables/{workspace_id}/project_tables'
        params = {
            'project': project_name
        }

        resp = self._request('GET', url, params=params, headers=self._private_headers)
        return resp

    def add_partition(self, workspace_name, database, table, partition_name, value):
        """
        :param database: string,  database name
        :param table: string, table within database
        :param partition_name: string, the partition name in create table sql
        :param value: string, partition value, example: partition name is: country, value can be china/usa
        """
        url = f'/api/source_file/{database}/{table}/partitions'
        data = {
            'workspace_name': workspace_name,
            'path_to_add': f'{partition_name}={value}'
        }
        resp = self._request('POST', url, json=data)
        return resp

    def update_partition(self, workspace_name, database, table):
        """
        :param workspace_name: string, workspace to use
        :param database: string,  database name
        :param table: string, table within database
        """
        url = f'/api/source_file/{database}/{table}/msck'
        data = {
            'workspace_name': workspace_name,
        }
        resp = self._request('PUT', url, params=data)
        return resp

    def general_settings(self, workspace_name, project, desc=None, semi_automatic_mode=False):
        """
        :param workspace_name: string, workspace to use
        :param project: string
        :param desc: string, description for general settings
        :param semi_automatic_mode: bool
        """
        url = f'/workspaces/{workspace_name}/' \
              f'kylin/api/projects/{project}/project_general_info'
        data = {
            'description': desc,
            'semi_automatic_mode': semi_automatic_mode
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def storage_quota(self, workspace_name, project_name, storage_quota_size=0):
        """
        :param workspace_name, string,
        :param project_name: string,
        :param storage_quota_size: unsigned int
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/storage_quota'
        data = {
            'storage_quota_size': storage_quota_size
        }

        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def garbage_cleanup_config(self, workspace_name, project_name, frequency_time_window, low_frequency_threshold):
        """
        :param workspace_name: string
        :param project_name: string
        :param frequency_time_window: string, value must be in ['MONTH', 'WEEK', 'DAY']
        :param low_frequency_threshold: unsigned int
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/garbage_cleanup_config'
        data = {
            'frequency_time_window': frequency_time_window,
            'low_frequency_threshold': low_frequency_threshold
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def push_down_config(self, workspace_name, project_name, push_down_enabled=True):
        """
        :param workspace_name: string
        :param project_name: string
        :param push_down_enabled: bool
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/push_down_config'
        data = {
            'push_down_enabled': push_down_enabled
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def push_down_project_config(self, workspace_name, project_name, runner_class_name, converter_class_names):
        """
        :param workspace_name: string
        :param project_name: string
        :param runner_class_name, string, value for 'kylin.query.pushdown.runner-class-name', define query engine
        :param converter_class_names, string, value for 'kylin.query.pushdown.converter-class-names'
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/push_down_project_config'

        data = {
            'runner_class_name': runner_class_name,
            'converter_class_names': converter_class_names
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def segment_config(self, workspace_name, project_name, auto_merge_enabled, auto_merge_time_ranges,
                       volatile_range_number=None, volatile_range_type=None, retention_range_number=None,
                       retention_range_enabled=None):
        """
        :param workspace_name: string
        :param project_name: string
        :param auto_merge_enabled: bool
        :param auto_merge_time_ranges: list, one or all of ["WEEK", "MONTH", "QUARTER", "DAY", "YEAR"],
        :param volatile_range_number: unsigned int, 0 or > 0
        :param volatile_range_type: string, can be one of ['MONTH', 'WEEK', 'DAY']
        :param retention_range_number: int, 0 or 1
        :param retention_range_enabled: bool
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/segment_config'
        data = {
            "auto_merge_time_ranges": auto_merge_time_ranges,
            "auto_merge_enabled": auto_merge_enabled,
            "volatile_range": {
                "volatile_range_number": volatile_range_number,
                "volatile_range_type": volatile_range_type
            },
            "retention_range": {
                "retention_range_number": retention_range_number,
                "retention_range_enabled": retention_range_enabled
            }
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def default_database(self, workspace_name, project_name, database_name):
        """
        :param workspace_name: string
        :param project_name: string
        :param database_name: string, one of database in project
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/default_database'
        data = {
            'default_database': database_name
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def job_notification_config(self, workspace_name, project_name, data_load_empty_notification_enabled,
                                job_error_notification_enabled, job_notification_emails):
        """
        :param workspace_name, string
        :param project_name, string
        :param data_load_empty_notification_enabled: bool
        :param job_error_notification_enabled: bool
        :param job_notification_emails: list
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/projects/{project_name}/job_notification_config'
        data = {
            "data_load_empty_notification_enabled": data_load_empty_notification_enabled,
            "job_error_notification_enabled": job_error_notification_enabled,
            "job_notification_emails": job_notification_emails
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def epoch(self, workspace_name, projects, force):
        """
        this method is to update the bind relationships between projects and task nodes
        :param workspace_name: string
        :param projects: list
        :param force: bool,
        """
        url = f'/workspaces/{workspace_name}/kylin/api/epoch'
        data = {
            "projects": projects,
            "force": force
        }
        resp = self._request('POST', url, json=data, to_json=False)
        return resp

    def reset_project_settings(self, workspace_name, project_name, reset_item):
        """
         Only one of low efficient storage, segment configuration and task notification can be set to default value
         in a Put operation
        :param workspace_name: string
        :param project_name: string
        :param reset_item: string, choice in ['job_notification_config'，'query_accelerate_threshold'，
                                              'garbage_cleanup_config'，'segment_config', 'storage_quota_config']
        """

        url = f'/workspaces/{workspace_name}/kylin/api/projects/{project_name}/project_config'

        data = {
            'reset_item': reset_item
        }
        resp = self._request('PUT', url, json=data)
        return resp

    def get_model_desc(self, workspace_name, project_name, model_name):
        """
        this method is to get model description
        :param workspace_name: string
        :param project_name: string
        :param model_name： string
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/models/{project_name}/{model_name}/model_desc'

        resp = self._request('GET', url)
        return resp

    def partition_desc(self, workspace_name, project_name, model_name,
                       partition_desc=None, start_date=None, end_date=None):
        """
        :param workspace_name: string
        :param project_name: string
        :param model_name: string
        :param partition_desc: json string, define partition column and row's data type
        :param start_date: string, segment time, timestamp type, unit ms
        :param end_date: string, timestamp, unit ms
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/models/{project_name}/{model_name}/partition_desc'

        data = {
            'partition_desc': partition_desc,
            'start': start_date,
            'end': end_date
        }
        resp = self._request('PUT', url, json=data, to_json=False)
        return resp

    def model_validation(self, workspace_name, project_name, sqls):
        """
        :param workspace_name: string
        :param project_name: string
        :param sqls: list
        """
        url = f'/workspaces/{workspace_name}/kylin/api/models/model_validation'
        data = {
            'project': project_name,
            'sqls': sqls
        }
        resp = self._request('POST', url, json=data)
        return resp

    def model_suggestion(self, workspace_name, project_name, sqls):
        """
        :param workspace_name: string
        :param project_name: string
        :param sqls: array/list
        """
        url = f'/workspaces/{workspace_name}/kylin/api/models/model_suggestion'
        data = {
            'project': project_name,
            'sqls': sqls
        }
        resp = self._request('POST', url, json=data)
        return resp

    def model_optimization(self, workspace_name, project_name, sqls):
        """
        :param workspace_name: string
        :param project_name: string
        :param sqls: array/list
        """
        url = f'/workspaces/{workspace_name}/kylin/api/models/model_optimization'
        data = {
            'project': project_name,
            'sqls': sqls
        }
        resp = self._request('POST', url, json=data)
        return resp

    def get_model_recommendations(self, workspace_name, project_name, model_name):
        """
        :param workspace_name: string
        :param project_name: string
        :param model_name: string,
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/models/{model_name}/recommendations'
        data = {
            'project': project_name
        }
        resp = self._request('GET', url, params=data)
        return resp

    def batch_get_model_recommendations(self, workspace_name, project_name, filter_by_models=True, model_names=None):
        """
        :param workspace_name: string
        :param project_name: string
        :param filter_by_models: bool, default is true, get recommendations by model names; if false, query all models
                                 under this workspace
        :param model_names: array/list, model names list
        """
        url = f'/workspaces/{workspace_name}/kylin/api/models/recommendations/batch'
        data = {
            'project': project_name,
            'filter_by_models': filter_by_models,
            'model_names': model_names
        }
        resp = self._request('PUT', url, params=data)
        return resp

    def segment_check(self, workspace_name, project_name, model_name, start_time, end_time):
        """
        :param workspace_name: string
        :param project_name: string
        :param model_name： string,
        :param start_time: int, millisecond
        :param end_time: int, millisecond
        """
        url = f'/workspaces/{workspace_name}/kylin/' \
              f'api/models/{model_name}/segments/check'
        data = {
            'project': project_name,
            'start': start_time,
            'end': end_time
        }
        resp = self._request('POST', url, json=data)
        return resp

    def refresh_catalog_data(self, workspace_name, tables):
        """
        :param workspace_name, string
        :param tables: list, eg: ['database.table_a', 'database.table_b']
        """
        url = f'/workspaces/{workspace_name}/kylin/api/tables/catalog_cache'
        data = {
            'tables': tables
        }
        resp = self._request('PUT', url, json=data)
        return resp

    def list_quota(self, search='', orderBy='kcuUsage', direction='desc'):
        """
        list quota
        :return: [{"quotaRecord":{"id":1,"workspaceId":1,"kduMalloced":1,"kduUsed":0.0,"kcuMalloced":1.0,
        "kcuUsed":1.0,"kduSynced":false,"createTime":1602754326000,"updateTime":1603103879000},
        "workspaceName":"newworkspace","kcuUsage":100.0,"kduUsage":0.0},{"quotaRecord":{"id":2,"workspaceId":2,
        "kduMalloced":10,"kduUsed":0.0,"kcuMalloced":30.0,"kcuUsed":3.0,"kduSynced":true,"createTime":1603158299000,
        "updateTime":1603159952000},"workspaceName":"test_auto_scalling_4147_4148","kcuUsage":10.0,"kduUsage":0.0}]
        """
        url = '/api/quota'
        params = {
            'search': search,
            'orderBy': orderBy,
            'direction': direction
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers)
        return resp['datas']

    def get_quota_info(self):
        """
        get quota info
        """
        url = '/api/quota/info'
        resp = self._request('GET', url, headers=self._private_headers)
        return resp

    def update_quota(self, kcuMalloced, kduMalloced, workspace_name):
        """
        update quota
        :param kcuMalloced: kcu number
        :param kduMalloced: kdu number
        :param workspace_name: workspace name
        :return: {"datas":null,"msg":null,"code":"000","totalRecords":null}
        """
        quotas = self.list_quota()
        quotaRecordId = next(filter(lambda msg: msg['workspaceName'] == workspace_name, quotas))['quotaRecord']['id']
        url = '/api/quota/batch/update'
        data = [{'kcuMalloced': kcuMalloced,
                 'kduMalloced': kduMalloced,
                 'quotaRecordId': quotaRecordId,
                 }]
        resp = self._request('POST', url, json=data, headers=self._private_headers)
        return resp

    def rewrite_model_configuration(self, workspace_name, project, model_id, alias, override_props,
                                    auto_merge_enabled=None, auto_merge_time_ranges=None, volatile_range=None,
                                    retention_range=None, config_last_modifier=None, config_last_modified=0,
                                    user_session=False):

        url = '/workspaces/{workspace_name}/kylin/api/models/{model_id}/config' \
            .format(host=self._host, port=self._port, workspace_name=workspace_name, model_id=model_id)
        payload = {
            'project': project,
            'model': model_id,
            'alias': alias,
            'auto_merge_enabled': auto_merge_enabled,
            'auto_merge_time_ranges': auto_merge_time_ranges,
            'volatile_range': volatile_range,
            'retention_range': retention_range,
            'config_last_modifier': config_last_modifier,
            'config_last_modified': config_last_modified,
            'override_props': override_props
        }
        resp = self._request('PUT', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_project_config(self, workspace_name, project_name):
        url = f'/kylin/api/projects/{project_name}/project_config'
        ref_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project_name}'
        self._private_headers['Referer'] = ref_url
        resp = self._request('GET', url, headers=self._private_headers)
        return resp

    def delete_database(self, workspace_id, database_name):
        """
        Delete database in kc
        :param workspace_id:
        :param database_name:
        :return:
        """
        url = f'/api/spark_source/databases/{database_name}?workspaceId={workspace_id}'
        resp = self._request('DELETE', url, headers=self._private_headers, to_json=False)
        return resp

    def delete_table(self, workspace_name, databases=None, tables=None, retain_databases=True):
        """
        :param workspace_name: string
        :param databases: string
        :param tables: table
        :param retain_databases: whether or not to retain databases
        """
        url = f'/api/source_file/workspaces/{workspace_name}/drop_tables'
        params = {
            'databases': databases or [],
            'tables': tables or [],
            'retain_databases': retain_databases,
        }
        resp = self._request('DELETE', url, json=params)
        return resp

    def pre_reload_table(self, workspace_name, project_name, table_name):
        """
        :param workspace_name: string
        :param project_name: string
        :param table_name: string, DB.TABLE
        """
        url = f'/api/tables/workspaces/{workspace_name}/pre_reload'
        params = {
            'project': project_name,
            'table': table_name
        }
        resp = self._request('GET', url, params=params)
        return resp

    def get_database_column(self, workspace_id, database, table):
        """
        :param workspace_id: int
        :param database: string, name of database
        :param table: string
        """
        url = f'/api/spark_source/{database}/{table}/columns?workspaceId={workspace_id}'
        resp = self._request('GET', url, headers=self._private_headers)
        return resp

    def get_model_desc_by_ke(self, workspace_name, project_name, model_id):
        """
        :param workspace_name: string
        :param project_name: string
        :param model_id: int
        """
        url = f'/kylin/api/models/{model_id}/json'
        referer_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/secret_ke_index.html'
        self._private_headers['Referer'] = referer_url
        data = {
            'model': model_id,
            'project': project_name
        }
        resp = self._request('GET', url, params=data, headers=self._private_headers)
        return resp

    def pack_diagnosis(self, cluster_id, modules, start_time, end_time, user_session=False):
        """
        pack diag
        :param cluster_id: kcu number
        :param modules: ['CLOUD'] or ['CLOUD', 'ENGIN']
        :param start_time: start time
        :param end_time: end time
        :return:
        """
        url = '/api/diag'
        payload = {
            'clusterId': cluster_id,
            'modules': modules,
            'startTime': start_time,
            'endTime': end_time
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp['datas'][0]

    def download_diagnosis(self, export_path, file):
        url = f'/api/diag/download?export_path={export_path}'
        import_headers = self._private_headers.copy()
        import_headers['Accept'] = '*/*'
        resp = self._request("GET", url, raw_response=True, headers=import_headers)
        logging.info(f"download diag {export_path} to temp file {file.name}")
        for chunk in resp.iter_content(chunk_size=1000000):
            file.write(chunk)
        resp.close()

    def get_diagnosis_status(self, uuid, user_session=False):
        """
        get diagnosis status
        :param uuid: uuid
        :return:
        """
        url = '/api/diag'
        params = {
            'uuid': uuid
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def list_diagnosis(self, cluster_id, page=0, size=10, user_session=False):
        url = '/api/diag/list'
        params = {
            'cluster_id': cluster_id,
            'page': page,
            'size': size
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp["content"]

    def edit_model(self, workspace_name, project_name, model_desc):
        """
        this method is to update a model
        :param workspace_name: string
        :param project_name: string
        :param model_desc: json type
        """
        url = f'/kylin/api/models/semantic'
        referer = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project_name}'
        import_headers = self._private_headers.copy()
        import_headers['Referer'] = referer

        resp = self._request('PUT', url, json=model_desc, headers=import_headers)
        return resp

    def list_databases(self, workspace_id):
        """
        Get database in kc
        :param workspace_id:
        :return:
        """
        url = f'/api/spark_source/databases'
        data = {
            'workspaceId': workspace_id,
        }
        resp = self._request('GET', url, params=data, headers=self._private_headers)
        return resp

    def list_tables(self, workspace_id, project_name, database_name):
        """
        this method is to list tables under a project_name->database_name
        :param workspace_id: int, the number of a workspace_name
        :param project_name: string
        :param database_name: string
        """
        url = f'/api/spark_source/{database_name}/tables'
        data = {
            'workspaceId': workspace_id,
            'project': project_name
        }
        resp = self._request('GET', url, params=data, headers=self._private_headers)
        return resp

    @retry(stop_max_attempt_number=3)
    def get_workspace_list(self, cloud='AzureChinaCloud', user_session=False):
        url = f'/api/workspaces/{cloud}/list'
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    @check_error_and_retry(interval=10, expect_error=json.decoder.JSONDecodeError)
    def get_ke_license(self, ke_url, user_session=False):
        url = f'http://{ke_url}/api/system/license'
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_kc_license(self, user_session=False):
        url = '/api/config/license'.format(host=self._host, port=self._port)
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    @check_error_and_retry(interval=10, expect_error=json.decoder.JSONDecodeError)
    def login_ke(self, ke_url, user_session=False):
        """
        use username and password login
        :param ke_url: string, ke url
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = f'http://{ke_url}/api/user/authentication'
        import_headers = self._private_headers.copy()
        import_headers['Authorization'] = self.token(':'.join(self._auth))
        resp = self._request('POST', url, headers=import_headers, inner_session=user_session)
        return resp

    def get_project_table(self, cluster_id, project_name, table=None, page_offset=0, page_size=10000,
                          user_session=False):
        url = f'/api/tables/{cluster_id}/project_tables'
        params = {
            'project': project_name,
            'page_offset': page_offset,
            'page_size': page_size,
            'table': table
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def update_model_status(self, workspace_name, project_name, model_uuid, status):
        """
        :param status: string, OFFLINE, ONLINE, WARNING
        :param workspace_name: workspace name
        :param project_name: project name
        :param model_uuid: model uuid
        :return:
        """
        url = f'/kylin/api/models/{model_uuid}/status'
        ref_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project_name}'
        payload = {
            'model': model_uuid,
            'project': project_name,
            'status': status
        }
        import_headers = self._private_headers.copy()
        import_headers['Referer'] = ref_url
        resp = self._request('PUT', url, json=payload, headers=import_headers)
        return resp

    @await_worksapce_and_retry(waiting_time=20)
    def await_delete_workspace(self, workspace_names, cloud):
        """
        await all workspace to be delete, default timeout is 20 minutes
        :param workspace_names: workspace name list
        :param cloud: cloud
        :return: boolean, timeout will return false
        """
        resp = self.get_workspace_list(cloud)
        message = list(filter(lambda msg: msg['project'] in workspace_names, resp['content']))
        return not message

    def await_all_workspace(self, workspace_names, cloud, expected_status=['RUNNING'], waiting_time=30, intelval=20):
        """
        await all workspace to be running, default timeout is 20 minutes
        :param workspace_names: workspace name list
        :param cloud: cloud
        :param expected_status: expected status
        :param waiting_time:
        :param intelval:
        :return: boolean, timeout will return false
        """

        @await_worksapce_and_retry(waiting_time=waiting_time, interval=intelval)
        def _await_result(client, ws_names, platform, ex_status):
            resp = client.get_workspace_list(platform)
            message = list(filter(lambda msg: msg['project'] in ws_names and
                                              msg['cluster']['status'] in ex_status, resp['content']))
            return len(message) == len(ws_names)

        return _await_result(self, workspace_names, cloud, expected_status)

    def get_project_list(self, workspace_id, project=None, page_offset=0, page_size=999, need_permission=True,
                         user_session=False):
        """
        get project list
        :param workspace_id: workspace id
        :param project: project
        :param page_offset: page offset
        :param page_size: page size
        :param need_permission: permission
        :return:
        """
        url = f'/api/projects/{workspace_id}'
        params = {
            'pageOffset': page_offset,
            'pageSize': page_size,
            'project': project,
            'need_permission': need_permission
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_logs(self, env, username, key=None, page=0, size=999, operation=None, status=None,
                 date_star=None, date_end=None, user_session=False):
        """
        get logs
        :param username: current user name
        :param env: cloud env
        :param key: search keywords
        :param page: page
        :param size: sizes
        :param operation: operation
        :param status: status，SUCCESS,ERROR,TIMEOUT,RUNNING
        :param date_star: date_star
        :param date_end: date_end
        :return:
        """
        url = '/api/operations'
        params = {
            'username': username,
            'env': env,
            'key': key,
            'page': page,
            'size': size,
            'operation': operation,
            'status': status,
            'dateStar': date_star,
            'dateEnd': date_end
        }
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_index_graph(self, workspace_name, project, model_id, user_session=False):
        """
        get index graph
        :param project: project name
        :param model_id: model id
        :return:
        """
        url = f'/kylin/api/index_plans/index_graph'
        params = {
            'project': project,
            'model': model_id,
        }
        ref_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project}'
        import_headers = self._private_headers.copy()
        import_headers['Referer'] = ref_url
        resp = self._request('GET', url, params=params, headers=import_headers, inner_session=user_session)
        return resp

    def model_segments(self, workspace_name, project, model_id, start_time, end_time, build_all_indexes, partition_desc,
                       build_all_sub_partitions=False, multi_partition_desc=None, sub_partition_values=None,
                       segment_holes=None):
        """
        param workspace_name:
        param project:
        param model_id: model id, string
        param start_time: build segment start time, int
        param end_time: build segment end time, int
        param build_all_indexes: bool
        param partition_desc: dict
        param build_all_sub_partitions: bool
        param multi_partition_desc: dict
        param sub_partition_values: []
        param segment_holes
        """
        url = f'/kylin/api/models/{model_id}/model_segments'
        ref_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project}'
        import_headers = self._private_headers.copy()
        import_headers['Referer'] = ref_url
        data = {
            "start": start_time,
            "end": end_time,
            "build_all_indexes": build_all_indexes,
            "partition_desc": partition_desc,
            "segment_holes": segment_holes,
            "project": project,
            "build_all_sub_partitions": build_all_sub_partitions,
            "multi_partition_desc": multi_partition_desc,
            "sub_partition_values": sub_partition_values
        }
        resp = self._request('PUT', url, json=data, headers=import_headers)
        return resp

    def _rsa_encrypt(self, value):
        """
        encrypt str by rsa
        :param value:
        :return:
        """
        public_key = self.get_rsa_public_key()
        pubkey = f'-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----\n'
        pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey.encode("utf-8"))
        rsa_value = rsa.encrypt(str(value).encode('utf-8'), pubkey)
        return base64.b64encode(rsa_value).decode()

    def import_aad_user(self, csv_file, user_session=False):
        """
        Import user from csv to KC
        :return:
        """
        url = '/api/upload/uploadCsv'
        payload = {}
        files = [
            ('file', ('user.csv', open(csv_file, 'rb'), 'text/csv'))
        ]
        headers = self._private_headers.copy()
        del headers['Content-Type']
        resp = self._request('POST', url, headers=headers, files=files, data=payload, inner_session=user_session)
        return resp

    def config_add(self, region, tenant_id, client_id, client_secret, admin_group, redirect_url,
                   auth_type='oauth2', user_filter=None, group_filter=None, page_size=200, user_session=False):
        """
        Configration aad
        :return:
        """
        url = '/api/config/third_party_user/aad'
        payload = {
            'activeRegion': region,
            'authType': auth_type,
            'userFilter': user_filter or '',
            'groupFilter': group_filter or '',
            'pageSize': page_size,
            'tenantId': tenant_id,
            'clientId': client_id,
            'clientSecret': self._rsa_encrypt(client_secret),
            'adminGroup': admin_group,
            'redirectUrl': redirect_url,
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def check_ldap(self, ldap_host, ldap_port,
                   ldap_user='cn=admin,dc=example,dc=org',
                   ldap_pwd='admin',
                   user_search_base='dc=example,dc=org',
                   user_search_pattern='(&(CN={0}))',
                   usergroup_search_base='ou=Groups,dc=example,dc=org',
                   usergroup_search_filter='(|(member={0})(memberUid={1}))',
                   group_member_search_filter='(&(cn={0})(objectClass=groupOfNames))',
                   user_search_filter='(objectClass=person)',
                   group_search_filter='(|(objectClass=groupOfNames)(objectClass=group))',
                   admin_role='admin_group',
                   ldap_ssl=False,
                   user_session=False, ):

        """
        Check ldap connection
        param ldap_host:
        param ldap_port:
        param ldap_user: string
        param ldap_pwd: string
        param user_search_base: string
        param user_search_pattern: string
        param usergroup_search_base: string
        param usergroup_search_filter: string
        param group_member_search_filter: string
        param user_search_filter: string
        param group_search_filter: string
        param admin_role: string
        param user_session: string
        :return:
        """
        url = '/api/config/third_party_user/ldap/check'
        if ldap_ssl:
            connection_server = f'ldaps://{ldap_host}:{ldap_port}'
        else:
            connection_server = f'ldap://{ldap_host}:{ldap_port}'

        payload = {
            'connectionServer': connection_server,
            'connectionUsername': ldap_user,
            'connectionPassword': self._rsa_encrypt(ldap_pwd),
            'userSearchBase': user_search_base,
            'userSearchPattern': user_search_pattern,
            'userGroupSearchBase': usergroup_search_base,
            'userGroupSearchFilter': usergroup_search_filter,
            'groupMemberSearchFilter': group_member_search_filter,
            'userSearchFilter': user_search_filter,
            'groupSearchFilter': group_search_filter,
            'adminRole': admin_role,
        }

        resp = self._request('POST', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def config_ldap(self, ldap_host, ldap_port,
                    ldap_user='cn=admin,dc=example,dc=org',
                    ldap_pwd='admin',
                    user_search_base='dc=example,dc=org',
                    user_search_pattern='(&(CN={0}))',
                    usergroup_search_base='ou=Groups,dc=example,dc=org',
                    usergroup_search_filter='(|(member={0})(memberUid={1}))',
                    group_member_search_filter='(&(cn={0})(objectClass=groupOfNames))',
                    user_search_filter='(objectClass=person)',
                    group_search_filter='(|(objectClass=groupOfNames)(objectClass=group))',
                    admin_role='admin_group',
                    ldap_ssl=False,
                    user_session=False, ):
        """
        Configration ldap
        :return:
        """
        url = '/api/config/third_party_user/ldap'
        if ldap_ssl:
            connection_server = f'ldaps://{ldap_host}:{ldap_port}'
        else:
            connection_server = f'ldap://{ldap_host}:{ldap_port}'

        payload = {
            'connectionServer': connection_server,
            'connectionUsername': ldap_user,
            'connectionPassword': self._rsa_encrypt(ldap_pwd),
            'userSearchBase': user_search_base,
            'userSearchPattern': user_search_pattern,
            'userGroupSearchBase': usergroup_search_base,
            'userGroupSearchFilter': usergroup_search_filter,
            'groupMemberSearchFilter': group_member_search_filter,
            'userSearchFilter': user_search_filter,
            'groupSearchFilter': group_search_filter,
            'adminRole': admin_role,
        }
        resp = self._request('POST', url, json=payload, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_ldap_user_list(self, username=None, is_case_sensitive=None, offset=None, size=None,
                           user_session=False):
        """
        get user list
        :param username: string, target user name
        :param is_case_sensitive: string, target password
        :param offset: int, page offset
        :param size: int, page size
        :param user_session: boolean, true for using login session to execute
        :return:
        """
        url = '/api/users'
        params = {}
        if username is not None:
            params['name'] = username
        if is_case_sensitive is not None:
            params['is_case_sensitive'] = is_case_sensitive
        if offset is not None:
            params['page_offset'] = offset
        if size is not None:
            params['page_size'] = size
        resp = self._request('GET', url, params=params, headers=self._private_headers, inner_session=user_session)
        return resp

    def await_kc_running(self, check_action=None, timeout=600, check_times=30, **kwargs):
        start_time = time.time()
        already_check_times = 0
        check_action = self.get_usergroup_list if check_action is None else check_action
        while time.time() - start_time < timeout:
            try:
                while already_check_times < check_times:
                    res = check_action(**kwargs)
                    assert res
                    already_check_times = already_check_times + 1
                    logging.debug(f'Already check {already_check_times} times')
                    time.sleep(1)
                return True
            except Exception as e:
                logging.debug('KC can not access now {}, wait 10s'.format(e))
                already_check_times = 0
                time.sleep(10)
        logging.debug('KC can not access after {}s'.format(timeout))
        return False

    def get_aad_token(self, user_session=False):
        """
        Get aad token when KC use aad
        :return:
        """
        url = '/api/users/me/id_token'
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    def get_system_profile(self, user_session=False):
        """
        Get KC security profile
        :return:
        """
        url = '/api/config/system_profile'
        resp = self._request('GET', url, headers=self._private_headers, inner_session=user_session)
        return resp

    def delete_loaded_table(self, cluster_id, project, database_name, table):
        """
        :param cluster_id: string
        :param project: string
        :param database_name: string
        :param table: string
        """
        url = f'/api/tables/{cluster_id}/{project}/{database_name}/{table}'
        resp = self._request('DELETE', url, headers=self._private_headers, to_json=False)
        return resp

    def export_table_structure(self, workspace_name, database, tables, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param database: string, the name of database
        :param tables: array string tables
        :return:
        """
        url = f'/api/tables/workspaces/{workspace_name}/export_table_structure'
        payload = {
            'database': database,
            'tables': tables
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def get_index_list(self, workspace_name, project, model_name, status=None, page_offset=0, page_size=10,
                       sources=None, sort_by='last_modified', reverse=True, user_session=False):
        """
        get index list
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project_name
        :param model_name: string, the name of model
        :param status: string, index status (NO_BUILD, BUILDING, LOCKED, ONLINE) default null
        :param page_offset: string, paging pages, default is 0
        :param page_size: string, paging size, default is 10
        :param sources: string, RECOMMENDED_AGG_INDEX, RECOMMENDED_TABLE_INDEX, CUSTOM_AGG_INDEX, CUSTOM_TABLE_INDEX
        :param sort_by: string, sort field, last_modified, usage, data_size. Default is last_modified
        :param reverse: string, whether to sort in reverse order. Default is true
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/indexes'
        params = {
            'project': project,
            'status': status,
            'page_offset': page_offset,
            'page_size': page_size,
            'sources': sources,
            'sort_by': sort_by,
            'reverse': reverse
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def completion_segments(self, workspace_name, project, model_name, parallel=False, ids=None, names=None,
                            user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, model_name
        :param parallel: bool, whether or not the segment completes supports parallelism. Default is false
        :param ids: array string, segment ids
        :param names: array string, segment names
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments/' \
              f'completion'
        payload = {
            'project': project,
            'parallel': parallel,
            'ids': ids,
            'names': names or []
        }
        resp = self._request('POST', url, params=payload, inner_session=user_session)
        return resp

    def execute_async_query(self, workspace_name, project, sql, separator=',', offset=0, limit=500, format='csv',
                            encode='utf-8', file_name='result', user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param sql: query sql
        :param offset: offset of returned result
        :param limit: limit of returned result
        :param separator: the delimiter for the exported results, default to ","
        :param format: file format, default is "CSV ", other optional values are "json"," XLSX"
        :param encode: file encoding, default is "UTF-8 ", other optional values are" GBK"
        :param file_name: file name (not yet supported in Chinese), default is "result"
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query'
        payload = {
            'project': project,
            'sql': sql,
            'separator': separator,
            'offset': offset,
            'limit': limit,
            'format': format,
            'encode': encode,
            'file_name': file_name
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    @await_with_retry()
    def get_async_query_status(self, workspace_name, project, query_id, exepct_stats='SUCCESSFUL', user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :param exepct_stats:
        :param user_session:
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}/status'
        payload = {
            'project': project,
        }
        resp = self._request('GET', url, json=payload, inner_session=user_session)
        return resp['status'] == exepct_stats

    def get_async_query_metadata(self, workspace_name, project, query_id, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}/metadata'
        payload = {
            'project': project,
        }
        resp = self._request('GET', url, json=payload, inner_session=user_session)
        return resp

    def get_async_query_size(self, workspace_name, project, query_id, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}/' \
              f'file_status'
        payload = {
            'project': project,
        }
        resp = self._request('GET', url, json=payload, inner_session=user_session)
        return resp

    def download_query_results(self, workspace_name, project, query_id, include_header=False, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :param query_id: whether or not the download result contains a table header, default false
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}/result_download?' \
              'include_header={include_header}'
        payload = {
            'project': project,
        }
        resp = self._request('GET', url, json=payload, content=True, inner_session=user_session)
        return resp

    def get_query_hdfs_path(self, workspace_name, project, query_id, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}/' \
              f'result_path'
        payload = {
            'project': project,
        }
        resp = self._request('GET', url, json=payload, inner_session=user_session)
        return resp

    def delete_all_query_results(self, workspace_name, user_session=False):
        """
        :param workspace_name: string, the name of workspace

        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query'
        resp = self._request('DELETE', url, inner_session=user_session)
        return resp

    def delete_query_results_based_time(self, workspace_name, project, older_than, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param older_than: string, older_than, The earliest retained time, last_modify async query result file earlier
         than this time will be deleted, the time format yyyy-mm-dd HH: MM :ss
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query'
        params = {
            'project': project,
            'older_than': older_than
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def delete_query_results_based_query_id(self, workspace_name, project, query_id, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param query_id: string, query id
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/async_query/{query_id}'
        payload = {
            'project': project,
        }
        resp = self._request('DELETE', url, json=payload, inner_session=user_session)
        return resp

    def get_workspace_full_name(self, workspace_name, cloud='AzureChinaCloud'):
        resp = self.get_workspace_list(cloud)
        message = next(filter(lambda msg: msg['project'] == workspace_name, resp['content']))
        return message['cluster']['name']

    def get_query_history(self, workspace_name, project, page_offset=0, page_size=10, start_time_from=None,
                          start_time_to=None, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param page_offset: paging pages, default to 0
        :param page_size: paging size, default is 10
        :param start_time_from: query history start timestamp, the unit ms, start_time_to cannot be used separately
        :param start_time_to: query history end timestamp, the unit ms, start_time_from cannot be used separately
        :param user_session:
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/query/query_histories'
        payload = {
            'project': project,
            'page_offset': page_offset,
            'page_size': page_size,
            'start_time_from': start_time_from or '',
            'start_time_to': start_time_to or '',
        }
        resp = self._request('GET', url, params=payload, inner_session=user_session)
        return resp

    def snapshot_management_switch(self, workspace_name, project, snapshot_manual_management_enabled=True,
                                   user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param snapshot_manual_management_enabled: string, enable snapshot manual management mode default false
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/projects/{project}/' \
              f'snapshot_config'
        payload = {
            'snapshot_manual_management_enabled': snapshot_manual_management_enabled,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def configure_snapshots_partition_columns(self, workspace_name, project, table_partition_col=None,
                                              user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param table_partition_col: Map [String: String] TABLE (e.g. DB.TABLE) to partition columns
        :return:
        """
        url = f'/workspaces/{workspace_name}/kylin/api/snapshots/config'
        payload = {
            'project': project,
            'table_partition_col': table_partition_col
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def new_snapshot(self, workspace_name, project, tables=None, databases=None, priority=3, options=None,
                     user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param tables: array string, specify the table you want to load in a format such as DB.TABLE
        :param databases: array string, load all tables under the database
        :param priority: int, set the priority of the task in the range of 0-4, with priority descending from high to
         low. default is 3
        :param options:Map [string:args], the name of the TABLE (e.g., db.table) to the set of parameters,
        args as follows:partition_col - Select the partition column of the corresponding table. default is NULL
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/snapshots'
        payload = {
            'project': project,
            'tables': tables or [],
            'databases': databases or [],
            'priority': priority,
            'options': options
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def refresh_snapshot(self, workspace_name, project, tables=None, databases=None, priority=3, options=None,
                         user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param tables: array string, specify the table you want to load in a format such as DB.TABLE
        :param databases: array string, load all tables under the database
        :param priority: int, set the priority of the task in the range of 0-4, with priority descending from high to
         low. default is 3
        :param options:Map [string:args], the name of the TABLE (e.g., db.table) to the set of parameters,
        args as follows:partition_col - Select the partition column of the corresponding table. default is NULL
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/snapshots'
        payload = {
            'project': project,
            'tables': tables or [],
            'databases': databases or [],
            'priority': priority,
            'options': options
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def delete_snapshot(self, workspace_name, project, tables, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param tables: array string, specify the table you want to load in a format such as DB.TABLE
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/snapshots'
        params = {
            'project': project,
            'tables': tables,
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def get_snapshot_list(self, workspace_name, project, table=None, page_offset=0, page_size=10, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param table: string, table of search keywords, empty by default, showing all snapshots under the project.
        :param page_offset: paging pages, default to 0
        :param page_size: paging size, default is 10
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/snapshots'
        params = {
            'project': project,
            'table': table,
            'page_offset': page_offset,
            'page_size': page_size
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def get_log_node(self, cluster_name=None, service='kc'):
        """

        :param cluster_name:
        :param service:
        :return:
        """
        cluster_name = '' if cluster_name is None else cluster_name
        url = f'/api/log/node'
        params = {
            'clusterName': cluster_name,
            'service': service
        }
        resp = self._request('GET', url, headers=self._private_headers, params=params)
        return resp

    def list_config(self, search_info='', data_id='KYLIGENCE_CLOUD',
                    group='KYLIGENCE_CLOUD_GROUP', page=1, size=1000, use=True):
        """

        :param search_info:
        :param data_id:
        :param group:
        :param page:
        :param size:
        :param use:
        :return:
        """
        url = '/api/kycc/v1/cs/configs/listConfig'
        params = {
            'sorts': 'itemKey,desc',
            'likes': f'itemKey,*{search_info}*',
            'dataId': data_id,
            'group': group,
            'pageNo': page,
            'pageSize': size,
            'use': use
        }
        resp = self._request('GET', url, headers=self._private_headers, params=params)
        return resp

    def get_ke_config(self, cluster_id):
        """
        :param cluster_id:
        :return:
        """
        url = '/api/ke/config/get'
        params = {
            'id': cluster_id
        }
        resp = self._request('GET', url, headers=self._private_headers, params=params)
        return resp

    def config_multi_partition(self, workspace_name, project, multi_partition_enabled=True):

        """
        :param project: the name of project
        :param multi_partition_enabled: multi partition enabled
        :return:
        """
        url = f'/kylin/api/projects/{project}/multi_partition_config'
        import_headers = self._private_headers.copy()
        ref_url = f'{self._base_url}/workspaces/{workspace_name}/kylin/' \
                  f'secret_ke_index.html?project={project}'
        import_headers['Referer'] = ref_url
        payload = {
            'project': project,
            'multi_partition_enabled': multi_partition_enabled
        }
        resp = self._request('PUT', url, json=payload, headers=import_headers)
        return resp

    def add_multi_partition_values(self, workspace_name, project, model_name, sub_partition_values, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param sub_partition_values: array, sub partition values
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/segments/multi_partition/sub_partition_values'
        payload = {
            'project': project,
            'sub_partition_values': sub_partition_values,
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def build_multi_partition_values(self, workspace_name, project, model_name, segment_id, sub_partition_values,
                                     parallel_build_by_segment=False, build_all_sub_partitions=False,
                                     user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param sub_partition_values: array, sub partition values
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/' \
              f'segments/multi_partition'
        payload = {
            'project': project,
            'sub_partition_values': sub_partition_values,
            'segment_id': segment_id,
            'parallel_build_by_segment': parallel_build_by_segment,
            'build_all_sub_partitions': build_all_sub_partitions
        }
        resp = self._request('POST', url, json=payload, inner_session=user_session)
        return resp

    def refresh_multi_partition_values(self, workspace_name, project, model_name, segment_id, sub_partition_values,
                                       user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param sub_partition_values: array, sub partition values
        :param segment_id: string, segment id
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/' \
              f'segments/multi_partition'
        payload = {
            'project': project,
            'sub_partition_values': sub_partition_values,
            'segment_id': segment_id
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def get_multi_partition(self, workspace_name, project, model_name, segment_id, page_offset=0, page_size=10,
                            user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param page_offset: int, page_offset
        :param segment_id: string, segment id
        :param page_size: int, page_size
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/' \
              f'segments/multi_partition'
        params = {
            'project': project,
            'page_offset': page_offset,
            'segment_id': segment_id,
            'page_size': page_size
        }
        resp = self._request('GET', url, params=params, inner_session=user_session)
        return resp

    def delete_multi_partition_build_data(self, workspace_name, project, model_name, segment_id, sub_partition_values,
                                          user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param segment_id: string, segment id
        :param sub_partition_values: string, sub_partition_values
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/segments/multi_partition'
        params = {
            'project': project,
            'model': model_name,
            'segment_id': segment_id,
            'sub_partition_values': sub_partition_values
        }
        resp = self._request('DELETE', url, params=params, inner_session=user_session)
        return resp

    def query_mapping_settings(self, workspace_name, project, model_name, alias_columns, multi_partition_columns,
                               value_mapping, user_session=False):
        """
        :param workspace_name: string, the name of workspace
        :param project: string, the name of project
        :param model_name: string, the name of model_name
        :param alias_columns: array<string>, alias columns
        :param multi_partition_columns: array<string>, the name of multi partition columns
        :param value_mapping: array<string>, value_mapping
        :return:
        """

        url = f'/workspaces/{workspace_name}/kylin/api/models/{model_name}/multi_partition/mapping'
        payload = {
            'project': project,
            'alias_columns': alias_columns,
            'multi_partition_columns': multi_partition_columns,
            'value_mapping': value_mapping
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def configs_import_check(self, file_path, dataId=' KYLIGENCE_CLOUD', group='KYLIGENCE_CLOUD_GROUP'):
        """
        configs import check
        :param dataId: string the name of workspace
        :param group: string the name of project
        :param file_path: MultipartFile full path of zip file
        :return:
        """

        url = '/api/kycc/v1/cs/configs/importCheck'
        import_headers = self._headers.copy()
        import_headers['Accept'] = 'application/json, text/plain, application/vnd.apache.kylin-v4+json'
        import_headers.pop('Content-Type')
        params = {
            'dataId': dataId,
            'group': group
        }
        with open(file_path, 'rb') as f:
            files = [('file', (os.path.basename(file_path), f, 'application/zip'))]
            resp = self._request('POST', url, headers=import_headers, params=params, files=files)

        return resp

    def add_configuration(self, config_requests, user_session=False):
        """
        :param config_requests: json config requests

        :return:
        """

        url = '/api/kycc/v1/cs/configs/addConfig'
        resp = self._request('POST', url, json=config_requests, headers=self._private_headers,
                             inner_session=user_session)
        return resp

    def delete_configuration(self, ids='', commit_id='', notify=False, dataId='KYLIGENCE_CLOUD',
                             group='KYLIGENCE_CLOUD_GROUP', desc='1.0'):
        """
        delete configuration
        :param dataId: string the name of workspace
        :param group: string the name of project
        :param ids: str id of config
        :param commit_id: str
        :param notify: bool
        :param desc: str
        :return:
        """

        url = '/api/kycc/v1/cs/configs/deleteConfig'
        params = {
            'dataId': dataId,
            'group': group,
            'ids': ids,
            'commitId': commit_id,
            'notify': notify,
            'desc': desc
        }
        import_headers = self._private_headers.copy()
        import_headers.pop('Content-Type')
        resp = self._request('DELETE', url, headers=import_headers, params=params)
        return resp

    def get_log_query(self, query, start, end, limit=5000):
        """

        :param query:
        :param start:
        :param end:
        :param limit:
        :return:
        """
        url = f'/api/log/query'
        params = {
            'query': query,
            'start': start,
            'end': end,
            'limit': limit
        }
        resp = self._request('GET', url, headers=self._private_headers, params=params)
        return resp

    def forbidden_users_ui(self, name, forbidden_ui=True, user_session=False):
        """
        forbidden users ui
        :param name:  string, the name ot user
        :param forbidden_ui: boolean
        :return:
        """
        url = '/api/users/ui/forbidden'
        payload = {
            'name': name,
            'forbiddenUI': forbidden_ui,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def forbidden_user_group_ui(self, name, forbidden_ui=True, user_session=False):
        """
        forbidden users ui
        :param name:  string, the name ot user group
        :param forbidden_ui: boolean
        :return:
        """
        url = '/api/user_group/ui/forbidden'
        payload = {
            'name': name,
            'forbiddenUI': forbidden_ui,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def batch_forbidden_users_ui(self, names, forbidden_ui=True, user_session=False):
        """
        forbidden users ui
        :param names:  array[string], the name ot user
        :param forbidden_ui: boolean
        :return:
        """
        url = '/api/users/ui/forbidden/batch'
        payload = {
            'names': names,
            'forbiddenUI': forbidden_ui,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp

    def batch_forbidden_user_group_ui(self, names, forbidden_ui=True, user_session=False):
        """
        forbidden users ui
        :param names:  array[string], the name ot user group
        :param forbidden_ui: boolean
        :return:
        """
        url = '/api/user_group/ui/forbidden/batch'
        payload = {
            'names': names,
            'forbiddenUI': forbidden_ui,
        }
        resp = self._request('PUT', url, json=payload, inner_session=user_session)
        return resp


def connect(**conf):
    _host = conf.get('host')
    _port = conf.get('port')

    return LightningHttpClient(_host, _port)
