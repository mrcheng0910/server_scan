# encoding:utf-8
"""
数据库操作
"""

from pymongo import MongoClient
from datetime import datetime,timedelta
import tldextract


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
    collection = db['server_tcp_details']
    result = collection.insert_one(data)
    print "result.inserted_id: {}".format(result.inserted_id)

# insert_detect_info("nihao")