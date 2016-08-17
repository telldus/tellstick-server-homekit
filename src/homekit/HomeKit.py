# -*- coding: utf-8 -*-

from base import Application, Plugin, Settings, implements
from board import Board
from telldus import DeviceManager, IDeviceChange, Device
from Bonjour import Bonjour
from HapHandler import HapHandler
from SocketServer import TCPServer
from threading import Thread
from urlparse import urlparse, parse_qsl

from HapAccessory import HapAccessory, HapCharacteristic, HapService
import random
import ed25519

import logging
import json


class RequestHandler(HapHandler):
	def finish(self):
		HapHandler.finish(self)
		RequestHandler.HTTPDServer.lostConnection(self)

	def do_encrypted_GET(self):
		logging.warning('Encrypted GET to %s', self.path)
		hk = HomeKit(RequestHandler.HTTPDServer.context)
		url = urlparse(self.path)
		if url.path == '/accessories':
			hk.handleAccessories(self)

	def setup(self):
		HapHandler.setup(self)
		RequestHandler.HTTPDServer.newConnection(self)

class HTTPDServer(object):
	def __init__(self, port, context):
		RequestHandler.HTTPDServer = self
		self.context = context
		self.connections = []
		self.httpServer = TCPServer(('', port), RequestHandler)
		self.thread = Thread(target=self.httpServer.serve_forever, name='HomeKit http server')
		self.thread.daemon = True
		self.thread.start()
		Application().registerShutdown(self.sh)

	def lostConnection(self, conn):
		if conn in self.connections:
			self.connections.remove(conn)

	def newConnection(self, conn):
		if conn in self.connections:
			return
		self.connections.append(conn)
		HomeKit(self.context).newConnection(conn)

	def sh(self):
		logging.warning("Shutting down HAP server")
		#self.httpServer.shutdown()
		logging.warning("Server was shut down")

class HapDeviceStateCharacteristics(HapCharacteristic):
	def __init__(self):
		super(HapDeviceStateCharacteristics,self).__init__(value=self.value(), format='bool', type='25', perms=['pr', 'pw', 'ev'])

class HapBridgeAccessory(HapAccessory):
	def __init__(self):
		super(HapBridgeAccessory,self).__init__('Telldus Technologies', Board.product(), 'Mickes dator', HapHandler.getId())

class HapDeviceAccessory(HapAccessory):
	def __init__(self, device):
		super(HapDeviceAccessory,self).__init__('Acme', device.typeString(), device.name(), device.id())
		self.device = device
		service = HapService('43')
		service.addCharacteristics(HapCharacteristic(device.name(), type='23', perms=['pr']))
		service.addCharacteristics(HapDeviceStateCharacteristics())
		self.addService(service)

class HomeKit(Plugin):
	implements(IDeviceChange)

	def __init__(self):
		Application().queue(self.start)
		self.accessories = {}
		self.accessories[1] = HapBridgeAccessory()

	def start(self):
		self.port    = random.randint(8000, 8080)
		self.bonjour = Bonjour(port=self.port)
		self.httpServer = HTTPDServer(port=self.port, context=self.context)
		deviceManager = DeviceManager(self.context)
		for device in deviceManager.retrieveDevices():
			if not device.confirmed():
				continue
			self.deviceAdded(device)

	def handleAccessories(self, request):
		accessories = [{'aid': i, 'services': self.accessories[i].servicesJSON()} for i in self.accessories]
		request.sendEncryptedResponse({'accessories': accessories})

	def newConnection(self, conn):
		s = Settings('homekit')
		longTermKey = s.get('longTermKey', None)
		password = s.get('password', None)
		if longTermKey is None or password is None:
			# No public key, generate
			signingKey, verifyingKey = ed25519.create_keypair()
			longTermKey = signingKey.to_ascii(encoding='hex')
			pw = ''.join([str(random.randint(0,9)) for i in range(8)])
			password = '%s-%s-%s' % (pw[0:3], pw[3:5], pw[5:8])
			s['longTermKey'] = longTermKey
			s['password'] = password
		conn.setLongTermKey(longTermKey, password)

	# IDeviceChange
	def deviceAdded(self, device):
		if device.isDevice() == False:
			return
		i = max(self.accessories)+1
		self.accessories[i] = HapDeviceAccessory(device)

	# IDeviceChange
	def deviceConfirmed(self, device):
		self.deviceAdded(device)
