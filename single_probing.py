from libnmap.process import NmapProcess

nm = NmapProcess("221.217.36.184", options="-sV -p U:53,111,137")
rc = nm.run()

if nm.rc == 0:
    print nm.stdout
else:
    print nm.stderr