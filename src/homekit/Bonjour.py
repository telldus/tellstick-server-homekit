# -*- coding: utf-8 -*-

from board import Board
from threading import Thread
import fcntl
import pybonjour
import select
import socket
import struct

import logging

class Bonjour(object):
	def __init__(self, port):
		self.port = port
		self.thread = Thread(target=self.run, name='Bonjour')
		self.thread.daemon = True
		self.thread.start()

	def register(self, sdRef, flags, errorCode, name, regtype, domain):
		if errorCode == pybonjour.kDNSServiceErr_NoError:
			logging.info('Bonjour registered:')
			logging.info('  name    = %s', name)
			logging.info('  regtype = %s', regtype)
			logging.info('  domain  = %s', domain)
			logging.info('  port    = %s', self.port)

	def run(self):
		name = 'Mickes dator'  # TODO
		txt = {
			'pv': '1.0',
			'id': Bonjour.getMacAddr(Board.networkInterface()),
			'c#': '1',
			's#': '1',
			'sf': '1', # 1 = discoverable, 0 pair setup done
			'ff': '0', # 1 = haz da chip, 0 = does not
			'md': Board.product(),
			'ci': '2'
		}
		sdRef = pybonjour.DNSServiceRegister(name = name,
			regtype = '_hap._tcp',
			port = self.port,
			txtRecord = pybonjour.TXTRecord(txt),
			callBack = self.register
		)
		try:
			while True:
				ready = select.select([sdRef], [], [])
				if sdRef in ready[0]:
					pybonjour.DNSServiceProcessResult(sdRef)
		finally:
			sdRef.close()

	@staticmethod
	def getMacAddr(ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
		return ':'.join(['%02X' % ord(char) for char in info[18:24]])

