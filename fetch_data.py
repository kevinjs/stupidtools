#!/usr/bin/env python

# transform data from mongodb to mysql
# install sqlalchemy first, using python-mysqldb as connector
# create by dysj4099_AT_gmail.com

import pymongo
import time
import getopt
import datetime
from functools import wraps

#from models import SrvStat

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Integer, String, Float, Column
from sqlalchemy.ext.declarative import declarative_base

engine = create_engine('mysql+mysqldb://root:root@127.0.0.1:3306/db_srv_monitor')
DBSession = sessionmaker(bind=engine)

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

item_list = [
        {'counter_name':'server.cpu.usage', 'data':['counter_volume'], 'key':['cpu_u']},
        {'counter_name':'server.mem.usage', 'data':['counter_volume', 'resource_metadata*mem_total'], 'key':['mem_u', 'mem_t']},
        {'counter_name':'server.disk.util', 'data':['counter_volume', 'resource_metadata*capacity'], 'key':['disk_u', 'disk_t']},
        {'counter_name':'server.net.bytes.in', 'data':['counter_volume'], 'key':['net_b_in']},
        {'counter_name':'server.net.bytes.out', 'data':['counter_volume'], 'key':['net_b_out']}
]

Base = declarative_base()

class SrvStat(Base):
    __tablename__ = 't_srvstat'

    id = Column(Integer, primary_key=True)
    host_name = Column(String(40))
    host_ip = Column(String(15))
    status = Column(String(10))
    cpu_u = Column(Float(precision=2))
    mem_u = Column(Float(precision=2))
    mem_t = Column(Float(precision=2))
    disk_u = Column(Float(precision=2))
    disk_t = Column(Float(precision=2))
    net_b_in = Column(Float(precision=2))
    net_b_out = Column(Float(precision=2))
    rec_time = Column(Integer)

def timeit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print 'Run %s at %s cost:%s sec' %(func.__name__, datetime.datetime.utcnow(),round(end-start, 4))
        return result
    return wrapper

@timeit
def insert_mysql(data):
    def inner_recs_insert(rec_list):        
        session = DBSession()
        for it in rec_list:
            session.add(it)
            session.commit()
        session.close()

    def inner_rec_insert(rec_new):
        try:
            session = DBSession()
            session.add(rec_new)
            session.commit()
            session.close()
        except:
            pass

    inner_recs_insert(data)

def subqry_mongo(col, host, item):
    def inner_recur_access(tar_dict, key_str, sp='*'):
        flag = key_str.find(sp)
        if flag == -1:
            if key_str in tar_dict:
                return tar_dict[key_str]
            else:
                return None
        else:
            if (key_str[:flag] in tar_dict) and (type(tar_dict[key_str[:flag]]) == type({})):
                return inner_recur_access(tar_dict[key_str[:flag]], key_str[flag+1:], sp)
            else:
                return None

    qry_item = {'counter_name':item['counter_name'], 'server_ip':host['host_ip']}
    cur = col.find(qry_item).sort('timestamp', pymongo.DESCENDING).limit(1)
    latest_rec = None
    for it in cur:
        if it:
            latest_rec = it
            break

    # get each value in data dict
    value = []
    for it in item['data']:
        value.append(inner_recur_access(latest_rec, it))

    return dict(zip(item['key'], value)), time.mktime(latest_rec['timestamp'].timetuple())
    
@timeit
def fetch_mongo():
    conn = pymongo.Connection('127.0.0.1', 27017)
    db = conn['ceilometer']
    col = db['server']

    # get distinct server-name in last 30 min
    et = datetime.datetime.utcnow()
    st = et - datetime.timedelta(seconds = 30)

    host_list = []
    qry_host = {'counter_name':'server.cpu.usage', 'timestamp':{'$gte':st, '$lte':et}}

    cursor = col.find(qry_host).sort('timestamp', pymongo.DESCENDING)

    for item in cursor:
        item_info = {'host_name':item['server_name'], 'host_ip':item['server_ip']}
        if item_info not in host_list:
            host_list.append(item_info)

    # find the latest record of each host
    monitor_data = []
    for host in host_list:
        comb_unit = SrvStat(host_name=host['host_name'],
                           host_ip=host['host_ip'],
                           rec_time=-1)
        data_tmp = {}
        for item in item_list:
            features_tmp, timestamp_tmp = subqry_mongo(col, host, item)
            data_tmp = dict(data_tmp, **features_tmp)
            if timestamp_tmp > comb_unit.rec_time:
                comb_unit.rec_time = timestamp_tmp
        for k_data_tmp, v_data_tmp in data_tmp.items():
            setattr(comb_unit, k_data_tmp, v_data_tmp)
        if data_tmp:
            comb_unit.status = 'running'
        else:
            comb_unit.status = 'shutdown'
        monitor_data.append(comb_unit)
    return monitor_data

if __name__=='__main__':
    insert_mysql(fetch_mongo())
    print '---'

# put these lines into a file to /etc/cron.d/ and restart cron service.
#
#SHELL=/bin/sh
#PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
#*/5 * * * * root /usr/bin/fetch_data >> /var/log/fetch_data.log 2>&1
#
