# -*- coding: utf-8 -*-

import logging

class HapCharacteristic(object):
	TYPE_HUE = '13'

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
		elif type(value) == float:
			self.properties['format'] = 'float'
		else:
			logging.error('Unkown HAP characteristic type %s', type(value))

	def toJSON(self):
		return self.properties

	def setValue(self, value):
		self.properties['value'] = value

	def value(self):
		return self.properties.get('value', None)

	def __getitem__(self, attr):
		if attr == 'value':
			return self.value()
		return self.properties.get(attr, None)

	def __setitem__(self, attr, value):
		if attr == 'value':
			self.setValue(value)
		else:
			self.properties[attr] = value

class HapHueCharacteristics(HapCharacteristic):
	def __init__(self):
		super(HapHueCharacteristics,self).__init__(
			value=0,
			type=HapCharacteristic.TYPE_HUE,
			perms=['pr', 'pw', 'ev'],
			minValue=0,
			maxValue=360,
			minStep=1,
			unit='arcdegrees'
		)
