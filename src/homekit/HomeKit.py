# -*- coding: utf-8 -*-

from base import Application, Plugin, configuration, implements, ConfigurationDict, ConfigurationNumber, ConfigurationString
from board import Board
from telldus import DeviceManager, IDeviceChange, Device
from telldus.web import IWebReactHandler, ConfigurationReactComponent
from Bonjour import Bonjour
from HapHandler import HapHandler
from SocketServer import TCPServer, ThreadingMixIn
from threading import Thread
from urlparse import urlparse, parse_qsl

from .HapAccessory import HapAccessory, HapService
from .HapCharacteristics import HapCharacteristic, HapCurrentRelativeHumidityCharacteristics, HapCurrentTemperatureCharacteristics
from .HapDeviceAccessory import HapDeviceAccessory
import random
import ed25519

import logging
import json

__name__ = 'HomeKit'  # pylint: disable=redefined-builtin

class HapConnection(HapHandler):
	def __init__(self, *args, **kwargs):
		self.accessories = {}
		self.hk = None
		self.query = None
		HapHandler.__init__(self, *args, **kwargs)

	def finish(self):
		HapHandler.finish(self)
		HapConnection.HTTPDServer.lostConnection(self)

	def addPairing(self, identifier, publicKey, permissions):
		return self.hk.addPairing(identifier, publicKey, permissions)

	def deviceAdded(self, device):
		if len(self.accessories) >= 100:
			# HomeKit only supports 100 accessories
			return

		# Use the deviceId as accessory id since it must persist over reboots.
		# ait=1 is already taken by TellStick so offset them by one
		i = device.id() + 1
		self.accessories[i] = HapDeviceAccessory(device)
		if device.isSensor():
			# Load sensor values dynamically since we might not always now all the types
			# initially
			values = device.sensorValues()
			for valueType in values:
				for v in values[valueType]:
					self.sensorValueUpdated(device, valueType, v['value'], v['scale'])

	def deviceRemoved(self, deviceId):
		aid = deviceId + 1
		if aid in self.accessories:
			del self.accessories[aid]

	def deviceStateChanged(self, device, state, statevalue):
		values = {}
		if state == Device.TURNON:
			values = {
				HapCharacteristic.TYPE_ON: True,
				HapCharacteristic.TYPE_BRIGHTNESS: 100,
				HapCharacteristic.TYPE_PROGRAMMABLE_SWITCH_EVENT: 1
			}
		elif state == Device.TURNOFF:
			values = {
				HapCharacteristic.TYPE_ON: False,
				HapCharacteristic.TYPE_BRIGHTNESS: 0,
				HapCharacteristic.TYPE_PROGRAMMABLE_SWITCH_EVENT: 0
			}
		elif state == Device.DIM:
			values = {
				HapCharacteristic.TYPE_ON: True,
				HapCharacteristic.TYPE_BRIGHTNESS: int(round(statevalue/255.0*100.0)),
			}
		else:
			return
		self.updateCharacteristicsValues(device.id() + 1, values)

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

	def findCharacteristicsByType(self, aid, characteristicType):
		retval = []
		if aid not in self.accessories:
			return retval
		for i in self.accessories[aid].services:
			service = self.accessories[aid].services[i]
			c = service.characteristic(characteristicType=characteristicType)
			if c is not None:
				retval.append(c)
		return retval

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
		self.accessories[1] = HapBridgeAccessory()
		deviceManager = DeviceManager(HapConnection.HTTPDServer.context)
		for device in deviceManager.retrieveDevices():
			if not device.confirmed():
				continue
			self.deviceAdded(device)

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

	def sensorValueUpdated(self, device, valueType, value, scale):
		aid = device.id() + 1
		if aid not in self.accessories:
			return
		if valueType == Device.TEMPERATURE:
			if scale != Device.SCALE_TEMPERATURE_CELCIUS:
				# Only celcius supported
				return False
			characteristicType = HapCharacteristic.TYPE_CURRENT_TEMPERATURE
			cObject = HapCurrentTemperatureCharacteristics
			serviceType = HapService.TYPE_TEMPERATURE_SENSOR
		elif valueType == Device.HUMIDITY:
			characteristicType = HapCharacteristic.TYPE_CURRENT_RELATIVE_HUMIDITY
			cObject = HapCurrentRelativeHumidityCharacteristics
			serviceType = HapService.TYPE_HUMIDITY_SENSOR
		else:
			return
		c = self.findCharacteristicsByType(aid, characteristicType)
		if len(c) == 0:
			accessory = self.accessories[aid]
			service = HapService(serviceType)
			service.addCharacteristics(cObject(value))
			accessory.addService(service)
			return True  # New value
		values = {
			characteristicType: value,
		}
		self.updateCharacteristicsValues(aid, values)
		return False

	def setup(self):
		HapHandler.setup(self)
		HapConnection.HTTPDServer.newConnection(self)
		self.hk = HomeKit(HapConnection.HTTPDServer.context)  # pylint: disable=too-many-function-args
		self.loadAccessories()

	def updateCharacteristicsValues(self, aid, values):
		eventMsg = []
		for characteristicType in values:
			for c in self.findCharacteristicsByType(aid, characteristicType):
				value = values[characteristicType]
				if value == c.value():
					continue
				c.setValue(value)
				if c['ev'] == True:
					eventMsg.append({'aid': aid, 'iid': c['iid'], 'value': c.value()})
		if len(eventMsg) > 0:
			self.sendEncryptedResponse({'characteristics': eventMsg}, protocol='EVENT/1.0')

# pylint: disable=too-few-public-methods
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
		HomeKit(self.context).newConnection(conn)  # pylint: disable=too-many-function-args

	def sh(self):
		for c in self.connections:
			c.close_connection = 1
		self.httpServer.shutdown()
		self.httpServer.server_close()
		logging.warning("Server was shut down")

class HapBridgeAccessory(HapAccessory):
	def __init__(self):
		super(HapBridgeAccessory,self).__init__('Telldus Technologies', Board.product(), 'TellStick', HapHandler.getId())

@configuration(
	password = ConfigurationReactComponent(
		component='homekit',
		defaultValue=None,
		writable=False,
	),
	clients = ConfigurationDict(
		hidden=True,
	),
	configurationNumber = ConfigurationNumber(
		defaultValue=1,
		hidden=True,
	),
	longTermKey = ConfigurationString(
		defaultValue='',
		readable=False,
		hidden=True,
	),
)
class HomeKit(Plugin):
	implements(IDeviceChange)
	implements(IWebReactHandler)

	def __init__(self):
		self.httpServer = None
		Application().queue(self.start)
		self.clients = self.config('clients')
		self.configurationNumber = self.config('configurationNumber')
		self.longTermKey = self.config('longTermKey')
		self.password = self.config('password')
		if self.password is None:
			# Generate password
			pw = ''.join([str(random.randint(0,9)) for i in range(8)])
			self.password = '%s-%s-%s' % (pw[0:3], pw[3:5], pw[5:8])
			self.setConfig('password', self.password)

	@staticmethod
	def getReactComponents():
		return {
			'homekit': {
				'title': 'HomeKit',
				'script': 'homekit/homekit.js',
			}
		}

	def start(self):
		self.port    = random.randint(8000, 8079)
		sf = 1 if len(self.clients) == 0 else 0
		self.bonjour = Bonjour(port=self.port, c=self.configurationNumber, sf=sf)
		self.httpServer = HTTPDServer(port=self.port, context=self.context)

	def addPairing(self, identifier, publicKey, permissions):
		self.clients[identifier] = {
			'publicKey': publicKey,
			'admin': permissions
		}
		self.setConfig('clients', self.clients)
		# Non discoverable
		self.bonjour.updateRecord(sf=0)
		return True

	def removePairing(self, identifier):
		if identifier not in self.clients:
			return True
		del self.clients[identifier]
		self.setConfig('clients', self.clients)
		if len(self.clients) == 0:
			# Discoverable again
			self.bonjour.updateRecord(sf=1)
		return True

	def newConnection(self, conn):
		if self.longTermKey == '':
			# No public key, generate
			signingKey, verifyingKey = ed25519.create_keypair()
			self.longTermKey = signingKey.to_ascii(encoding='hex')
			self.setConfig('longTermKey', self.longTermKey)
		conn.setLongTermKey(self.longTermKey, self.password)

	def increaseConfigurationNumber(self):
		self.configurationNumber += 1
		if self.configurationNumber >= 4294967295:
			self.configurationNumber = 1
		self.setConfig('configurationNumber', self.configurationNumber)
		self.bonjour.updateRecord(c=self.configurationNumber)

	# IDeviceChange
	def deviceAdded(self, device):
		if self.httpServer is None:
			# Too early, we have not started yet
			return
		if len(self.httpServer.connections) == 0:
			# No connections, ignore
			return
		for conn in self.httpServer.connections:
			conn.deviceAdded(device)
		self.increaseConfigurationNumber()

	# IDeviceChange
	def deviceConfirmed(self, device):
		self.deviceAdded(device)

	# IDeviceChange
	def deviceRemoved(self, deviceId):
		if self.httpServer is None:
			# Too early, we have not started yet
			return
		if len(self.httpServer.connections) == 0:
			# No connections, ignore
			return
		for conn in self.httpServer.connections:
			conn.deviceRemoved(deviceId)
		self.increaseConfigurationNumber()

	# IDeviceChange
	def sensorValueUpdated(self, device, valueType, value, scale):
		if self.httpServer is None:
			# Too early, we have not started yet
			return
		newValue = False
		for conn in self.httpServer.connections:
			if conn.sensorValueUpdated(device, valueType, value, scale):
				newValue = True
		if newValue:
			self.increaseConfigurationNumber()

	# IDeviceChange
	def stateChanged(self, device, state, statevalue):
		if self.httpServer is None:
			# Too early, we have not started yet
			return
		for conn in self.httpServer.connections:
			conn.deviceStateChanged(device, state, statevalue)
