#encoding:utf-8

import os
import nmap


nm = nmap.PortScanner()
if (os.getuid() == 0):
    print('----------------------------------------------------')
    # Os detection (need root privileges)
    ip='196.2.12.73'
    ip='202.102.144.56'
    nm.scan(ip, arguments=" -sV -O -v ")
    if 'osmatch' in nm[ip]:
        for osmatch in nm[ip]['osmatch']:
            print('OsMatch.name : {0}'.format(osmatch['name']))
            print('OsMatch.accuracy : {0}'.format(osmatch['accuracy']))
            print('OsMatch.line : {0}'.format(osmatch['line']))
            print('')

            if 'osclass' in osmatch:
                for osclass in osmatch['osclass']:
                    print('OsClass.type : {0}'.format(osclass['type']))
                    print('OsClass.vendor : {0}'.format(osclass['vendor']))
                    print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
                    print('OsClass.osgen : {0}'.format(osclass['osgen']))
                    print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
                    print('')


    if 'fingerprint' in nm[ip]:
        print('Fingerprint : {0}'.format(nm[ip]['fingerprint']))

