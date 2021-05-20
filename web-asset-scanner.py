# coding: utf8
#!/usr/bin/python
# -*- coding:utf-8 -*-
import os
import getpass
import time
import socket
import re
import argparse

import threading
from Queue import Queue
import platform
import types
from subprocess import Popen, PIPE
from IPy import IP
import requests

import struct
import sys

from requests.models import ProtocolError


reload(sys)
sys.setdefaultencoding("UTF8")

import urllib3
urllib3.disable_warnings()

 
OK = 0x0
FINISH = 0x1
ERROR = 0x2

defaultPorts = "80,81,82,83,84,88,90,443,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,3000,5702,5703"
parser = argparse.ArgumentParser()
parser.add_argument('-n', '--networks', required=True, help="scan networks, '192.168.1.0/24,192.168.2.0/24'")
parser.add_argument('-p', '--ports', help="scan ports, default is '%s'" % defaultPorts, default=defaultPorts)
parser.add_argument('-t', '--timeout', help="set timeout, default is 10s",type=int, default=10)
parser.add_argument('-uo', '--outputUrlsFile', help="url output file name, default is './urls.txt'", default="urls.txt")
parser.add_argument('-mt', '--maxThread', help="set max thread, default is '200'",type=int, default=200)


class Thread(threading.Thread):
    def __init__(self, worker, task_queue, msg_queue, threadpool):
        super(Thread, self).__init__()
        self.worker = worker
        self.task_queue = task_queue
        self.threadpool = threadpool
        self.msg_queue = msg_queue

    def run(self):
        count = 0
        while True:
            self.threadpool.event.wait()
            if self.task_queue.empty():
                self.threadpool.InActiveOne()
                break
            task = self.task_queue.get()
            try:
                ret = self.worker(task)
                self.msg_queue.put((task, ret))
                if (not ret) and (ret[0] == FINISH):
                    self.threadpool.clearQueue()
            except Exception as e:
                self.msg_queue.put((task, ERROR))
            finally:
                self.task_queue.task_done()


class Threadpool(object):
    def __init__(self, worker, max_threads=10, thread=Thread,
                 queue=Queue, lock=threading.RLock()):
        self.worker = worker
        self.thread = thread
        self.event = threading.Event()
        self.lock = lock
        self.task_queue = queue()
        self.msg_queue = queue()
        self.max_threads = max_threads
        self.active_threads = 0

        self.start()

    def add(self, tasks):
        for task in tasks:
            self.task_queue.put(task)
        len_tasks = self.task_queue.qsize()

        self.lock.acquire()
        create_tasks = self.max_threads - self.active_threads
        if len_tasks < create_tasks:
            create_tasks = len_tasks
        for i in xrange(create_tasks):
            self.ActiveOne()
        self.lock.release()

    def ActiveOne(self):
        self.lock.acquire()
        t = self.thread(self.worker, self.task_queue, self.msg_queue, self)
        t.setDaemon(True)
        t.start()
        self.active_threads += 1
        self.lock.release()

    def InActiveOne(self):
        self.lock.acquire()
        self.active_threads -= 1
        self.lock.release()

    def status(self):
        return self.task_queue.qsize(), self.active_threads

    def join(self):
        self.task_queue.join()

    def printmsg(self):
        pass

    def clearQueue(self):
        self.stop()
        while True:
            if self.task_queue.empty():
                break
            self.task_queue.get()
            self.task_queue.task_done()
        self.start()

    def start(self):
        self.event.set()

    def stop(self):
        self.event.clear()


class Scanner:
    def __init__(self):
        self.max_thread = 200
        self.urlOutputFileName = 'urls.txt'
        self.webUrlFile = None
        self.network = []
        self.q = Queue()
        self.s = Queue()
        self.timeout = 100
        self.networkIPlistA = []
        self.portlist = [21, 22, 23, 25, 53, 80, 81, 139, 443, 445, 1433, 1521, 3306, 3398, 5800, 5900, 5901, 5902,
                         6379, 7001, 7002, 7070, 8080, 8081, 8181, 8888, 9090, 9200, 27017, 28018]
        self.networkIP_portOpen = {}

    def __portScan(self, scan):
        portConnect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        portConnect.settimeout(self.timeout)
        try:
            portConnect.connect((scan[0], scan[1]))
            portConnect.close()
            self.networkIP_portOpen[scan[0]] += str(scan[1]) + ','
        except Exception as e:
            pass

    def PortScan(self):
        print(u"Portscan started.")

        if self.network == []:
            print(u'network list is empty.')
        else:
            _pinglist = []
            for network in self.network:
                ips = IP(network)
                for ip in ips:
                    self.networkIPlistA.append(str(ip))

            for ip in self.networkIPlistA:
                self.networkIP_portOpen[ip] = ''

            _scanlist = []
            for ip in self.networkIPlistA:
                for port in self.portlist:
                    _scanlist.append([ip, int(port)])
            portT = Threadpool(self.__portScan, self.max_thread)
            portT.add(_scanlist)
            portT.join()
            print(u'PortScan end.')

            _portocolScan = []
            for ip in self.networkIPlistA:
                if(self.networkIP_portOpen[ip] != ''):
                    print(u'%s: %s' % (ip, self.networkIP_portOpen[ip]))
                portlist = self.networkIP_portOpen[ip].split(',')
                for port in portlist:
                    if port != '':
                        _portocolScan.append([ip, port])
            porsT = Threadpool(self._requestTest, self.max_thread)
            porsT.add(_portocolScan)
            print(u'WebScan started.')
            porsT.join()

        print(u'WebScan end.')

    def _requestTest(self, scan):
        ip = scan[0]
        port = scan[1]
        try:
            resp = requests.get('http://%s:%s/' % (ip, port), timeout=self.timeout)
            if(resp.status_code == 400):
                raise ProtocolError('maybe is https')
            else:
                self.writeWebUrl('http://%s:%s/' % (ip, port))
        except Exception as e:
            try:
                resp =  requests.get('https://%s:%s/' % (ip, port), verify=False, timeout=self.timeout)
                self.writeWebUrl('https://%s:%s/' % (ip, port))
            except Exception as e:
                pass
    
    def writeWebUrl(self, url):
        if (self.webUrlFile == None):
            self.webUrlFile = open(self.urlOutputFileName, 'a')
        self.webUrlFile.write(url + "\r")
    def Runall(self):
        pass


if __name__ == '__main__':
    args = parser.parse_args()
    out = Scanner()
    out.network = args.networks.split(',')
    out.timeout = int(args.timeout)
    out.max_thread = int(args.maxThread)
    out.urlOutputFileName = args.outputUrlsFile
    out.portlist = args.ports.split(',')
    out.PortScan()
