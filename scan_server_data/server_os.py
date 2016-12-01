# encoding:utf-8

"""
使用nmap的tcp sys探测ip的端口开放情况，并且存入到数据库中
"""
from datetime import datetime
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from db_manage import get_will_detect_server,get_has_detected_server

class ServerInfo(object):



    def __init__(self,ip):
        """
        初始化函数
        :param ip:
        :param source:
        :param options:
        """
        self.ip = ip  # 探测的ip
        self.options = "-O"  #nmap探测命令

        # 参数
        self.detected_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.state = ''
        self.os_version = []
        # 原始数据
        self.raw_data = ""
        self.parsed = None


    def do_scan(self):
        """
        对targets进行扫描，并返回探测结果
        :param targets: 扫描目标
        :param options: 扫描选项
        :return:
        """
        nmproc = NmapProcess(self.ip, self.options)
        rc = nmproc.run()
        if rc != 0:
            print("nmap scan failed: {0}".format(nmproc.stderr))

        self.raw_data = nmproc.stdout

        try:
            self.parsed = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
            return

    def find_os(self):

        rep = self.parsed
        for _host in rep.hosts:
            self.state = 'up'
            if _host.is_up():
                if _host.os_fingerprinted:

                    for osm in _host.os.osmatches:
                        tmp_os = {}
                        tmp_os['os_name'] = osm.name
                        tmp_os['accuracy'] = osm.accuracy
                        self.os_version.append(tmp_os)
                else:
                    self.state = 'down'
                    print("No fingerprint available")


    def insert_db(self):

        os_dict = {
            'ip':self.ip,
            'detect_time':self.detected_time,
            'state':self.state,
            'raw_data':self.raw_data,
            'os_version':self.os_version
        }

        from db_manage import insert_os_info
        insert_os_info(os_dict)

        print self.ip,self.detected_time


    def scan_result(self):
        self.do_scan()
        self.find_os()


if __name__ == "__main__":

    will_detect = get_will_detect_server()
    has_detect = get_has_detected_server()
    detect_server = list(set(will_detect).difference(set(has_detect)))
    # detect_server = ['192.134.6.126']

    for ip in detect_server:
        t = ServerInfo(str(ip))
        t.scan_result()
        t.insert_db()