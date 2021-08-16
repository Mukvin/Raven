import yaml

print('gl.py initializing ...')

with open("global_config.yaml", encoding="UTF-8") as global_conf_file:
    global_conf = yaml.load(global_conf_file, Loader=yaml.FullLoader)

aws_format_tags = [{'Key': key, 'Value': global_conf['TAGS'].get(key)} for key in global_conf['TAGS']]

# how long does each query take
AM_times = []
PM_times = []
