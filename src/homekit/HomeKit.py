# -*- coding: utf-8 -*-

from base import Application, Plugin, Settings, implements
from board import Board
from telldus import DeviceManager, IDeviceChange, Device
from Bonjour import Bonjour
from HapHandler import HapHandler
from SocketServer import TCPServer, ThreadingMixIn
from threading import Thread
from urlparse import urlparse, parse_qsl

from HapAccessory import HapAccessory, HapService
from HapCharacteristics import *
from TelldusCharacteristics import *
import random
import ed25519

import logging
import json
import colorsys

class HapConnection(HapHandler):
	def finish(self):
		HapHandler.finish(self)
		HapConnection.HTTPDServer.lostConnection(self)

	def addPairing(self, identifier, publicKey, permissions):
		return self.hk.addPairing(identifier, publicKey, permissions)

	def deviceAdded(self, device):
		if device.isDevice() == False:
			# Ignore sensors for now
			return

		# Use the deviceId as accessory id since it must persist over reboots.
		# ait=1 is already taken by TellStick so offset them by one
		i = device.id() + 1
		self.accessories[i] = HapDeviceAccessory(device)

	def deviceStateChanged(self, device, state, statevalue):
		value = True if state == Device.TURNON else False
		self.updateCharacteristicsValue(device.id() + 1, '49', HapCharacteristic.TYPE_ON, value)

	def removePairing(self, identifier):
		return self.hk.removePairing(identifier)

	def retrievePairings(self):
		retval = []
		clients = self.hk.clients
		for identifier in clients:
			retval.append({
				'identifier': identifier,
				'publicKey': clients[identifier]['publicKey'],
				'permissions': clients[identifier]['admin']}
			)
		return retval

	def do_encrypted_GET(self):
		logging.warning('Encrypted GET to %s', self.path)
		url = urlparse(self.path)
		if url.path == '/accessories':
			accessories = [{'aid': i, 'services': self.accessories[i].servicesJSON()} for i in self.accessories]
			self.sendEncryptedResponse({'accessories': accessories})
		elif url.path == '/characteristics':
			self.query = dict(parse_qsl(url.query))
			self.handleCharacteristicsGet()

	def do_encrypted_PUT(self):
		if self.path == '/characteristics':
			data = json.loads(self.parsedRequest)
			logging.warning('Encrypted PUT to %s: %s', self.path, data)
			self.handleCharacteristicsPut(data)

	def findCharacteristicByType(self, aid, serviceType, characteristicType):
		if aid not in self.accessories:
			return None
		service = self.accessories[aid].service(serviceType)
		if service is None:
			return None
		return service.characteristic(characteristicType=characteristicType)

	def handleCharacteristicsGet(self):
		if 'id' not in self.query:
			self.sendEncryptedResponse('', '400 Bad request')
			return
		retval = []
		errorFound = False
		ids = self.query['id'].split(',')
		for idPath in ids:
			path = idPath.split('.')
			if len(path) != 2:
				return
			aid = int(path[0])
			iid = int(path[1])
			if aid not in self.accessories:
				retval.append({'aid': aid, 'iid': iid, 'status': 1})
				errorFound = True
				continue
			accessory = self.accessories[aid]
			characteristic = accessory.characteristic(iid)
			if not characteristic:
				retval.append({'aid': aid, 'iid': iid, 'status': 2})
				errorFound = True
				continue
			data = {'aid': aid, 'iid': iid, 'value': characteristic['value']}
			# TODO: Check if the parameters meta, perms, type and/or ev was requested and return those too
			retval.append(data)
		if errorFound:
			for c in retval:
				if 'status' not in c:
					c['status'] = 0
		self.sendEncryptedResponse({'characteristics': retval})

	def handleCharacteristicsPut(self, body):
		if 'characteristics' not in body:
			return
		updatedAids = {}
		for c in body['characteristics']:
			if 'aid' not in c or 'iid' not in c:
				continue
			aid = int(c['aid'])
			iid = int(c['iid'])
			if aid not in self.accessories:
				logging.warning("Could not find accessory %s in %s", aid, self.accessories)
				continue
			characteristic = self.accessories[aid].characteristic(iid)
			if not characteristic:
				logging.error("Could not find characteristic")
				return
			if 'value' in c:
				characteristic.setValue(c['value'])
				updatedAids.setdefault(aid, []).append(iid)
			if 'ev' in c:
				characteristic['ev'] = c['ev']
		self.sendEncryptedResponse('', '204 No Content')
		for aid in updatedAids:
			self.accessories[aid].characteristicsWasUpdated(updatedAids[aid])

	def loadAccessories(self):
		self.accessories = {}
		self.accessories[1] = HapBridgeAccessory()
		deviceManager = DeviceManager(HapConnection.HTTPDServer.context)
		for device in deviceManager.retrieveDevices():
			if not device.confirmed():
				continue
			self.deviceAdded(device)

	def setup(self):
		HapHandler.setup(self)
		HapConnection.HTTPDServer.newConnection(self)
		self.hk = HomeKit(HapConnection.HTTPDServer.context)
		self.loadAccessories()

	def updateCharacteristicsValue(self, aid, serviceType, characteristicType, value):
		c = self.findCharacteristicByType(aid, serviceType, characteristicType)
		if c is None:
			return
		c.setValue(value)
		if c['ev'] == True:
			eventMsg = {'characteristics': [
				{'aid': aid, 'iid': c['iid'], 'value': c.value()}
			]}
			self.sendEncryptedResponse(eventMsg, protocol='EVENT/1.0')

class ThreadedTCPServer(ThreadingMixIn, TCPServer):
	daemon_threads = True

class HTTPDServer(object):
	def __init__(self, port, context):
		HapConnection.HTTPDServer = self
		self.context = context
		self.connections = []
		self.httpServer = ThreadedTCPServer(('', port), HapConnection)
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
		for c in self.connections:
			c.close_connection = 1
		self.httpServer.shutdown()
		self.httpServer.server_close()
		logging.warning("Server was shut down")

class HapBridgeAccessory(HapAccessory):
	def __init__(self):
		super(HapBridgeAccessory,self).__init__('Telldus Technologies', Board.product(), 'Mickes dator', HapHandler.getId())

class HapDeviceAccessory(HapAccessory):
	def __init__(self, device):
		super(HapDeviceAccessory,self).__init__('Acme', device.typeString(), device.name(), device.id())
		self.device = device
		methods = device.methods()
		if methods & (Device.DIM | Device.RGBW) > 0:
			# Supports Dim/RGBW - Type=Bulb
			service = HapService('43')
			service.addCharacteristics(OnCharacteristics(device))
			if methods & Device.DIM > 0:
				service.addCharacteristics(BrightnessCharacteristics(device))
			if methods & Device.RGBW > 0:
				service.addCharacteristics(HapHueCharacteristics())
				service.addCharacteristics(HapSaturationCharacteristics())
			self.addService(service)
		elif methods & (Device.TURNON | Device.TURNOFF) > 0:
			# Supports On/Off - Type=Switch
			service = HapService('49')
			service.addCharacteristics(OnCharacteristics(device))
			self.addService(service)

	def characteristicsWasUpdated(self, iids):
		# Convert iids to types
		types = {}
		for iid in iids:
			c = self.characteristic(iid)
			types[c['type']] = c
		if HapCharacteristic.TYPE_HUE in types or HapCharacteristic.TYPE_SATURATION in types:
			hue = types[HapCharacteristic.TYPE_HUE].value()
			saturation = types[HapCharacteristic.TYPE_SATURATION].value()
			r,g,b = colorsys.hsv_to_rgb(hue/360.0, saturation/100.0, 1)
			color = int('%02X%02X%02X00' % (r*255, g*255, b*255), 16)
			self.device.command(Device.RGBW, color, origin='HomeKit')
		if HapCharacteristic.TYPE_BRIGHTNESS in types:
			value = types[HapCharacteristic.TYPE_BRIGHTNESS].value()
			if value == 100:
				self.device.command(Device.TURNON, origin='HomeKit')
			elif value == 0:
				self.device.command(Device.TURNOFF, origin='HomeKit')
			else:
				self.device.command(Device.DIM, int(round(value/100.0*255.0)), origin='HomeKit')
		elif HapCharacteristic.TYPE_ON in types:
			value = types[HapCharacteristic.TYPE_ON].value()
			if value == 1:
				self.device.command(Device.TURNON, origin='HomeKit')
			elif value == 0:
				self.device.command(Device.TURNOFF, origin='HomeKit')

class HomeKit(Plugin):
	implements(IDeviceChange)

	def __init__(self):
		self.httpServer = None
		Application().queue(self.start)
		s = Settings('homekit')
		self.clients = s.get('clients', {})
		self.configurationNumber = s.get('configurationNumber', 1)
		self.longTermKey = s.get('longTermKey', None)
		self.password = s.get('password', None)

	def start(self):
		self.port    = random.randint(8000, 8080)
		sf = 1 if len(self.clients) == 0 else 0
		self.bonjour = Bonjour(port=self.port, c=self.configurationNumber, sf=sf)
		self.httpServer = HTTPDServer(port=self.port, context=self.context)

	def addPairing(self, identifier, publicKey, permissions):
		self.clients[identifier] = {
			'publicKey': publicKey,
			'admin': permissions
		}
		s = Settings('homekit')
		s['clients'] = self.clients
		# Non discoverable
		self.bonjour.updateRecord(sf=0)
		return True

	def removePairing(self, identifier):
		if identifier not in self.clients:
			return True
		del self.clients[identifier]
		s = Settings('homekit')
		s['clients'] = self.clients
		if len(self.clients) == 0:
			# Discoverable again
			self.bonjour.updateRecord(sf=1)
		return True

	def newConnection(self, conn):
		if self.longTermKey is None or self.password is None:
			# No public key, generate
			signingKey, verifyingKey = ed25519.create_keypair()
			self.longTermKey = signingKey.to_ascii(encoding='hex')
			pw = ''.join([str(random.randint(0,9)) for i in range(8)])
			self.password = '%s-%s-%s' % (pw[0:3], pw[3:5], pw[5:8])
			s['longTermKey'] = self.longTermKey
			s['password'] = self.password
		conn.setLongTermKey(self.longTermKey, self.password)

	# IDeviceChange
	def deviceAdded(self, device):
		if self.httpServer is None:
			# Too early, we have not started yet
			return
		for conn in self.httpServer.connections:
			conn.deviceAdded(device)

	# IDeviceChange
	def deviceConfirmed(self, device):
		self.deviceAdded(device)

	# IDeviceChange
	def stateChanged(self, device, state, statevalue):
		for conn in self.httpServer.connections:
			conn.deviceStateChanged(device, state, statevalue)
