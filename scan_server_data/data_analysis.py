# encoding:utf-8
"""
数据库操作
"""

from pymongo import MongoClient


def get_db():
    """
    获取数据库
    :return
    其他：可以完善
    """
    client = MongoClient('localhost', 27017)
    db = client['server_info']
    return db


def find_server(ip):
    db = get_db()
    collection = db['server_tcp_details']
    return collection.find({'state':'up','source':'whois','open_count':{'$gt':0}})
    # return collection.find({'state':'up','source':'whois','open_count':0})

def get_special_ip_info(ip):
    print ip
    ip = '209.250.78.20'
    db = get_db()
    collection = db['server_details']
    return collection.find({'ip':ip})


info = get_special_ip_info("ni")

for i in info:
    print i
    print i['filter_count']