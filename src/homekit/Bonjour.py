# -*- coding: utf-8 -*-

import fcntl
import logging
import select
import socket
import struct
from threading import Thread

import pybonjour

from board import Board

class Bonjour(object):
	def __init__(self, port, c, sf):
		self.port = port
		self.txt = {
			'pv': '1.0',
			'id': Bonjour.getMacAddr(Board.networkInterface()),
			'c#': c, # Configuration number, must change anytime something changes. Rollover on 4294967295
			's#': '1',
			'sf': sf, # 1 = discoverable, 0 pair setup done
			'ff': '0', # 1 = haz da chip, 0 = does not
			'md': Board.product(),
			'ci': '2'
		}
		self.sdRef = None
		self.thread = Thread(target=self.run, name='Bonjour')
		self.thread.daemon = True
		self.thread.start()

	def register(self, __sdRef, __flags, errorCode, name, regtype, domain):
		if errorCode == pybonjour.kDNSServiceErr_NoError:
			logging.info('Bonjour registered:')
			logging.info('  name    = %s', name)
			logging.info('  regtype = %s', regtype)
			logging.info('  domain  = %s', domain)
			logging.info('  port    = %s', self.port)

	def run(self):
		name = 'TellStick'  # TODO
		self.sdRef = pybonjour.DNSServiceRegister(
			name=name,
			regtype='_hap._tcp',
			port=self.port,
			txtRecord=pybonjour.TXTRecord(self.txt),
			callBack=self.register
		)
		try:
			while True:
				ready = select.select([self.sdRef], [], [])
				if self.sdRef in ready[0]:
					pybonjour.DNSServiceProcessResult(self.sdRef)
		finally:
			self.sdRef.close()

	def updateRecord(self, **values):
		for k in values:
			self.txt[k] = values[k]
		pybonjour.DNSServiceUpdateRecord(self.sdRef, None, 0, pybonjour.TXTRecord(self.txt))

	@staticmethod
	def getMacAddr(ifname):
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(sock.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
		return ':'.join(['%02X' % ord(char) for char in info[18:24]])
