# -*- coding: utf-8 -*-

import logging
from HapCharacteristics import HapCharacteristic

class HapService(object):
	def __init__(self, serviceType):
		self.type = serviceType
		self.iid = int(serviceType, 16)*1000
		self.characteristics = []

	def addCharacteristics(self, characteristics):
		characteristics['iid'] = self.iid + int(characteristics['type'], 16)
		self.characteristics.append(characteristics)

	def characteristic(self, iid=None, characteristicType=None):
		if iid is None and characteristicType is None:
			# Must search by at least one criteria
			return None
		for c in self.characteristics:
			if iid is not None and c['iid'] != iid:
				continue
			if characteristicType is not None and c['type'] != characteristicType:
				continue
			return c
		return None

	def characteristicsJSON(self):
		return [x.toJSON() for x in self.characteristics]

class HapAccessory(object):
	def __init__(self, manufacturer, model, name, serial):
		self.services = {}
		service = HapService('3E')
		service.iid = 1  # This service must have iid=1 for some unknown Apple reason
		service.addCharacteristics(HapCharacteristic(format='bool', type='14', perms=['pw']))  # Identify
		service.addCharacteristics(HapCharacteristic(manufacturer, type='20', perms=['pr']))   # Manufacturer
		service.addCharacteristics(HapCharacteristic(model, type='21', perms=['pr']))          # Model
		service.addCharacteristics(HapCharacteristic(name, type='23', perms=['pr']))           # Name
		service.addCharacteristics(HapCharacteristic(str(serial), type='30', perms=['pr']))    # Serial Number
		self.addService(service)

	def addService(self, service):
		self.services[service.type] = service

	def characteristic(self, iid=None, characteristicType=None):
		for service in self.services:
			c = self.services[service].characteristic(iid=iid, characteristicType=characteristicType)
			if c is not None:
				return c

	def characteristicsWasUpdated(self, iids):
		pass

	def service(self, serviceType):
		return self.services.get(serviceType, None)

	def servicesJSON(self):
		return [{'type': self.services[i].type, 'iid': self.services[i].iid, 'characteristics': self.services[i].characteristicsJSON()} for i in self.services]
