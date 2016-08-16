# -*- coding: utf-8 -*-

import logging

class HapCharacteristic(object):
	def __init__(self, value = None, **kwargs):
		self.properties = kwargs
		if value is not None:
			self.properties['value'] = value
		if 'format' in kwargs:
			pass
		elif type(value) in [str, unicode]:
			self.properties['format'] = 'string'
		elif type(value) == bool:
			self.properties['format'] = 'bool'
		elif type(value) == int:
			self.properties['format'] = 'int'
		else:
			logging.error('Unkown HAP characteristic type %s', type(value))

	def toJSON(self):
		return self.properties

	def setValue(self, value):
		logging.warning("Setting characteristic %s to %s", self['type'], value)
		self.properties['value'] = value

	def value(self):
		self.properties.get('value', None)

	def __getitem__(self, attr):
		if attr == 'value':
			return self.value()
		return self.properties.get(attr, None)

	def __setitem__(self, attr, value):
		if attr == 'value':
			self.setValue(value)
		else:
			self.properties[attr] = value

class HapService(object):
	def __init__(self, serviceType):
		self.type = serviceType
		self.iid = None
		self.characteristics = []

	def addCharacteristics(self, characteristics):
		self.characteristics.append(characteristics)

	def characteristic(self, iid):
		for c in self.characteristics:
			if c['iid'] == iid:
				return c
		return None

	def characteristicsJSON(self):
		return [x.toJSON() for x in self.characteristics]

	def maxIid(self):
		return max(self.characteristics, key=lambda x: x['iid'])['iid']

	def setIid(self, iid):
		self.iid = iid
		for c in self.characteristics:
			iid += 1
			c['iid'] = iid

class HapAccessory(object):
	def __init__(self, manufacturer, model, name, serial):
		self.iid = 1
		self.services = {}
		service = HapService('3E')
		service.addCharacteristics(HapCharacteristic(format='bool', type='14', perms=['pw']))  # Identify
		service.addCharacteristics(HapCharacteristic(manufacturer, type='20', perms=['pr']))   # Manufacturer
		service.addCharacteristics(HapCharacteristic(model, type='21', perms=['pr']))          # Model
		service.addCharacteristics(HapCharacteristic(name, type='23', perms=['pr']))           # Name
		service.addCharacteristics(HapCharacteristic(str(serial), type='30', perms=['pr']))    # Serial Number
		self.addService(service)

	def addService(self, service):
		self.services[self.iid] = service
		service.setIid(self.iid)
		self.iid = self.services[self.iid].maxIid() + 1

	def characteristic(self, iid):
		for service in self.services:
			c = self.services[service].characteristic(iid)
			if c is not None:
				return c

	def servicesJSON(self):
		return [{'type': self.services[i].type, 'iid': self.services[i].iid, 'characteristics': self.services[i].characteristicsJSON()} for i in self.services]
