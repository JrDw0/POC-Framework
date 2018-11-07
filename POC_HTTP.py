#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
    name: 微型HTTP Server
'''

import socket,struct,urllib2,time
from POC_Framework import POC

if __name__ == "__main__":

    a = POC()
    a.web_server_run()