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


def insert_detect_info(data):
    """
    插入探测信息
    :return:
    """
    db = get_db()
    collection = db['server_details']
    result = collection.insert_one(data)
    print "result.inserted_id: {}".format(result.inserted_id)

def insert_os_info(data):
    """
    插入探测的服务器信息
    :param data:
    :return:
    """
    db = get_db()
    collection = db['server_os_details']
    result = collection.insert_one(data)
    # print "result.inserted_id: {}".format(result.inserted_id)


def get_has_detected_server():
    """
    获取已经探测过的ip列表
    :return:
    """
    detected_ips = []
    db = get_db()
    collection = db['server_os_details']
    result = collection.find({},{'ip':1,"_id":0})
    for i in result:
        detected_ips.append(i['ip'])

    return detected_ips




def get_will_detect_server():
    """
    获取将要探测的服务器ip列表
    :return:
    """
    will_ips = []
    db = get_db()
    collection = db['server_details']
    will_ips = collection.distinct('ip',{'state':'up'})
    return will_ips
