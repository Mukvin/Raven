import base64
import json
import logging
import time
from enum import Enum

import boto3
from botocore.exceptions import ClientError

import gl

# EDGE == KE NODE
from . import utils
from .common import InstanceTag


class AWSInstance:

    def __init__(self, kc_config):
        self.region = kc_config['AWS_REGION']
        self.kc_config = kc_config
        self.client = boto3.client('s3',
                                   region_name=self.region)
        self.client_ec2 = boto3.client('ec2',
                                       region_name=self.region)
        self.resource_ec2 = boto3.resource('ec2',
                                           region_name=self.region)
        self.client_ssm = boto3.client('ssm',
                                       region_name=self.region)

        self.client_cf = boto3.client('cloudformation',
                                      region_name=self.region)

        self.client_elb = boto3.client('elbv2',
                                       region_name=self.region)

    def list_buckets(self):
        response = self.client.list_buckets()
        return response['Buckets']

    def create_bucket(self, bucket_name):
        """Create an S3 bucket in a specified region
        :param bucket_name: Bucket to create
        :return: True if bucket created, else False
        """

        try:
            self.client.create_bucket(Bucket=bucket_name,
                                      CreateBucketConfiguration={'LocationConstraint': self.region})
        except ClientError as e:
            logging.exception(e)
            return False
        return True

    def delete_bucket(self, bucket_name):
        """Delete an S3 bucket in a specified region
        :param bucket_name: Bucket to create
        :return: True if bucket delete, else False
        """

        try:
            self.client.delete_bucket(Bucket=bucket_name)
        except ClientError as e:
            logging.exception(e)
            return False
        return True

    def upload_file(self, bucket_name, file_name, object_name=None, acl='public-read'):
        """upload local file to s3
        :param bucket_name: Bucket to upload to
        :param file_name: File to upload
        :param object_name: S3 object name. If not specified then file_name is used
        :param acl: bucket acl, ACL:'private'|'public-read'|'public-read-write'|'authenticated-read'|'aws-exec-read'|
        'bucket-owner-read'|'bucket-owner-full-control'
        :return: boolean
        """
        if object_name is None:
            object_name = file_name
        try:
            self.client.upload_file(file_name, bucket_name, object_name,
                                    ExtraArgs={'ACL': acl})
        except ClientError as e:
            logging.exception(e)
            return False
        return True

    def delete_object(self, bucket_name, object_name):
        """delete s3 object
        :param bucket_name: Bucket name
        :param object_name: S3 object name to delete
        :return: boolean
        """
        try:
            self.client.delete_object(Bucket=bucket_name, Key=object_name)
        except ClientError as e:
            logging.exception(e)
            return False
        return True

    def download_fileobj(self, bucket_name, object_name, fileobj):
        """download s3 object
        :param bucket_name: Bucket name
        :param object_name: S3 object name to download
        :param fileobj: file object
        :return:
        """
        try:
            with open(fileobj, 'wb') as data:
                self.client.download_fileobj(bucket_name, object_name, data)
        except ClientError as e:
            logging.exception(e)
            return False
        return True

    def list_object_on_cloud(self, bucket_name, delimiter, prefix):
        """fuzzy search s3 object name
        :param bucket_name: Bucket name
        :param delimiter: A delimiter is a character you use to group keys
        :param Prefix: Limits the response to keys that begin with the specified prefix
        :return: current object name
        """
        try:
            objects = self.client.list_objects_v2(Bucket=bucket_name, Delimiter=delimiter, Prefix=prefix)
        except ClientError as e:
            logging.exception(e)
            return False
        return objects

    def list_object(self, bucket_name, delimiter, prefix, is_match_file=False):
        objects = self.list_object_on_cloud(bucket_name, delimiter, prefix)
        current_object_name = []
        if objects.get('CommonPrefixes', None):
            current_object_name.append(objects['CommonPrefixes'][0]['Prefix'].split('/')[-1])
        elif objects.get('Contents', None):
            for item in objects['Contents']:
                if item['Key'].endswith('/') and not is_match_file:
                    current_object_name.append(item['Key'].split('/')[-2])
                elif not item['Key'].endswith('/') and is_match_file:
                    current_object_name.append(item['Key'].split('/')[-1])
        return current_object_name

    def list_file(self, **kwargs):
        bucket_name = kwargs['bucket_name']
        delimiter = kwargs['delimiter']
        prefix = kwargs['prefix']
        objects = self.list_object_on_cloud(bucket_name, delimiter, prefix)
        current_object_name = []
        if objects.get('CommonPrefixes', None):
            current_object_name.append(objects['CommonPrefixes'][0]['Prefix'])
        elif objects.get('Contents', None):
            for item in objects['Contents']:
                current_object_name.append(item['Key'])
        return current_object_name

    def describe_stacks(self, stack_name):
        response = self.client_cf.describe_stacks(
            StackName=stack_name
        )
        return response

    def list_stack_resource(self, stack_name):
        response = self.client_cf.list_stack_resources(
            StackName=stack_name
        )
        return response

    def describe_load_balancers(self, lb_name):
        response = self.client_elb.describe_load_balancers(
            Names=[lb_name]
        )
        return response

    def create_stack(self, stack_name, url, aws_parameters, tags, capabilities=['CAPABILITY_IAM']):
        response = self.client_cf.create_stack(StackName=stack_name, TemplateURL=url, Parameters=aws_parameters,
                                               # Tags=tags,
                                               Capabilities=capabilities)
        return response

    def send_command(self, **kwargs):
        instance_ids = kwargs['vm_name']
        script = kwargs['script']
        document_name = "AWS-RunShellScript"
        parameters = {'commands': [script]}
        response = self.client_ssm.send_command(InstanceIds=instance_ids, DocumentName=document_name,
                                                Parameters=parameters)
        return response

    def get_command_invocation(self, command_id, instance_id):
        response = self.client_ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        return response

    def stop_cloud_instance(self, **kwargs):
        vm_id = kwargs['vm_name']
        instance_need_to_stop = self.resource_ec2.Instance(vm_id)
        instance_need_to_stop.stop(Force=True)

    def start_cloud_instance(self, **kwargs):
        vm_id = kwargs['vm_name']
        response = self.client_ec2.start_instances(
            InstanceIds=[vm_id])
        return response

    def describe_instances(self, **kwargs):
        identifier = self.kc_config['StackName']
        vm_type = kwargs.get('vm_type')
        filters = [
            {
                'Name': 'tag:Owner',
                'Values': [self.kc_config['Tags']['Owner']]
            },
            {
                'Name': 'tag:kyligence:cloud:vm-type',
                'Values': [vm_type]
            },
            {
                'Name': 'instance-state-name',
                'Values': ['running', 'stopped']
            }
        ]
        custom_filter = kwargs.get('custom_filter')
        if custom_filter is not None:
            filters = custom_filter

        resp = self.client_ec2.describe_instances(Filters=filters, DryRun=False, MaxResults=1000)
        reservations = resp.get('Reservations')
        while resp.get('NextToken'):
            resp = self.client_ec2.describe_instances(
                Filters=filters,
                NextToken=resp.get('NextToken')
            )
            reservations = reservations + resp.get('Reservations')

        resp = []
        for obj in reservations:
            if identifier in str(obj):
                resp.append(obj)
        return resp

    def get_instance_info(self, **kwargs):
        identifier = self.kc_config['StackName']
        vm_type = kwargs.get('vm_type')
        if isinstance(vm_type, str):
            vm_type = [vm_type]
        workspace_name = kwargs.get('workspace_name')
        instances_info = {}
        all_vm_types = []
        for tag in InstanceTag:
            all_vm_types.append(tag.value)
        vm_types = all_vm_types if vm_type is None else vm_type
        kc_net_prefix = f"kyligence-{identifier}"
        for vm_type in vm_types:
            items = self.describe_instances(vm_type=vm_type)
            for item in items:
                for tag in item['Instances'][0]['Tags']:
                    if (tag.get('Value', '').startswith(workspace_name or 'False') and tag.get('Key', '').
                            startswith('kyligence:cloud:workspace')) or tag.get('Value', '').startswith(kc_net_prefix):
                        vm_name = next(filter(lambda x: x['Key'] == 'Name', item['Instances'][0]['Tags']))['Value']
                        if vm_type not in instances_info:
                            instances_info[vm_type] = []
                            instances_info[vm_type].append([item['Instances'][0]['PrivateIpAddress'],
                                                            item['Instances'][0]['InstanceId'],
                                                            item['Instances'][0]['State']['Name'],
                                                            vm_name])
                        else:
                            instances_info[vm_type].append([item['Instances'][0]['PrivateIpAddress'],
                                                            item['Instances'][0]['InstanceId'],
                                                            item['Instances'][0]['State']['Name'],
                                                            vm_name])
        return instances_info

    def exec_script_instance_and_return(self, vm_name, script, timeout=20, **kwargs):
        """
        exec script aws cloud and return
        :param instance:
        :param instance_id instance ID
        :param script: script content
        :return:
        """
        if isinstance(vm_name, str):
            vm_name = [vm_name]
        response = self.send_command(vm_name=vm_name, script=script)
        command_id = response['Command']['CommandId']
        time.sleep(5)
        start = time.time()
        while time.time() - start < timeout * 60:
            output = self.get_command_invocation(
                command_id=command_id,
                instance_id=vm_name[0],
            )
            if output['Status'] in ['Delayed', 'Success', 'Cancelled', 'TimedOut', 'Failed']:
                break
            time.sleep(10)
        assert output['Status'] == 'Success', f"execute script failed, failed info: {output['StandardErrorContent']}"
        return output['StandardOutputContent']


class AWS:
    @staticmethod
    def aws_cloud(kc_config):
        version = kc_config['deploy_version']
        url = f'https://s3.amazonaws.com/public.kyligence.io/kycloud/version/{version}' + \
              '/dev/template/kyligence_cloud_aws_3_0.json'

        stack_name = 'RavenKCStack' + time.strftime('%d%H%M%S')
        kc_config['StackName'] = stack_name
        # tag_str = base64.b64encode(json.dumps(tags).encode("utf-8"))
        # kc_config['Tags'] = str(tag_str, encoding="utf-8")
        bucket_object = f's3://public.kyligence.io/kycloud/version/{version}/dev'
        kc_config['BucketObject'] = bucket_object

        parameter_keys = ['BucketObject', 'KeyName', 'InstanceType', 'RDSType', 'DBEngineType', 'InstanceCount',
                          'LoadBalancerSchema',
                          'LokiOption', 'Monitor', 'RDSPassword', 'TrustCidrs', 'ZkInstancetype', 'Tags']
        aws_parameters = [{'ParameterKey': str(k), 'ParameterValue': str(v)} for k, v in kc_config.items() if
                          parameter_keys.__contains__(k)]
        # aws_tags = [{'Key': k, 'Value': v} for k, v in tags.items()]
        cloud_instance = AWSInstance(kc_config)
        cloud_instance.create_stack(stack_name=stack_name, url=url, aws_parameters=aws_parameters, tags=[])

        # Check stack ready or not
        stack_create_failed = ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_FAILED',
                               'ROLLBACK_COMPLETE', 'ROLLBACK_COMPLETE']
        start = time.time()
        while time.time() - start < 3600:
            stack = cloud_instance.describe_stacks(stack_name)
            stack_status = stack['Stacks'][0]['StackStatus']
            assert stack_status not in stack_create_failed, f'execute failed,output: {stack_status}'
            if stack_status == 'CREATE_COMPLETE':
                break
            time.sleep(10)

        # Get resources from stack and get lb_dns
        resources = cloud_instance.list_stack_resource(stack_name)
        lb_resource = list(
            filter(lambda res: res['LogicalResourceId'] == 'KcLoadBalancer', resources['StackResourceSummaries']))
        lb_id = lb_resource[0]['PhysicalResourceId'].split('/')
        lb_name = lb_id[len(lb_id) - 2]
        load_balancers = cloud_instance.describe_load_balancers(lb_name)
        lb_ip = load_balancers['LoadBalancers'][0]['DNSName']
        logging.info(f"Load balancer ip: {lb_ip}, stack name: {stack_name}")
        return lb_ip, stack_name

    @staticmethod
    def aws_workspace(kylin_instance, user_session=False, **kwargs):
        workspace_name = 'newworkspace'
        resp = kylin_instance.client.get_keypairs()
        platform = kylin_instance.platform
        key_name = resp['datas'][0]['keyName']
        assert key_name, 'the keyName does not exist'
        kylin_instance.client.create_aws_workspace(workspace_name, platform, key_name, user_session, **kwargs)

        logging.debug('start workspace')
        cluster_id = kylin_instance.client.get_cluster_id(workspace_name, cloud=platform)

        kylin_instance.client.start_workspace(workspace_name)
        assert kylin_instance.client.await_workspace_running(workspace_name, cloud=platform), 'workspace start failure'

        return cluster_id
