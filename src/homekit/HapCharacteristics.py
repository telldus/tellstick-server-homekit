# -*- coding: utf-8 -*-

import logging

class HapCharacteristic(object):
	TYPE_BRIGHTNESS = '8'
	TYPE_CURRENT_TEMPERATURE = '11'
	TYPE_HUE = '13'
	TYPE_ON = '25'
	TYPE_SATURATION = '2F'

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
		value = self.properties.get('value', None)
		if self.properties['format'] == 'string':
			return str(value)
		if self.properties['format'] == 'bool':
			return bool(value)
		if self.properties['format'] == 'int' or self.properties['format'] == 'float':
			value = float(value)
			if 'minStep' in self.properties:
				# Respect minStep
				value = round(value/self.properties['minStep'])*self.properties['minStep']
			if 'minValue' in self.properties:
				value = max(value, self.properties['minValue'])
			if 'maxValue' in self.properties:
				value = min(value, self.properties['maxValue'])
			if self.properties['format'] == 'int':
				return int(value)
			return float(value)
		return value

	def __getitem__(self, attr):
		if attr == 'value':
			return self.value()
		return self.properties.get(attr, None)

	def __setitem__(self, attr, value):
		if attr == 'value':
			self.setValue(value)
		else:
			self.properties[attr] = value

class HapBrightnessCharacteristics(HapCharacteristic):
	def __init__(self, initialValue):
		super(HapBrightnessCharacteristics,self).__init__(
			value=initialValue,
			type=HapCharacteristic.TYPE_BRIGHTNESS,
			perms=['pr', 'pw', 'ev'],
			minValue=0,
			maxValue=100,
			minStep=1,
			unit='percentage',
			format='int'
		)

class HapCurrentTemperatureCharacteristics(HapCharacteristic):
	def __init__(self, initialValue):
		super(HapCurrentTemperatureCharacteristics,self).__init__(
			value=initialValue,
			type=HapCharacteristic.TYPE_CURRENT_TEMPERATURE,
			perms=['pr', 'ev'],
			minValue=0,
			maxValue=100,
			minStep=0.1,
			unit='celsius',
			format='float'
		)


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

class HapOnCharacteristics(HapCharacteristic):
	def __init__(self, initialValue):
		super(HapOnCharacteristics,self).__init__(
			value=initialValue,
			format='bool',
			type=HapCharacteristic.TYPE_ON,
			perms=['pr', 'pw', 'ev']
		)

class HapSaturationCharacteristics(HapCharacteristic):
	def __init__(self):
		super(HapSaturationCharacteristics,self).__init__(
			value=0,
			type=HapCharacteristic.TYPE_SATURATION,
			perms=['pr', 'pw', 'ev'],
			minValue=0,
			maxValue=100,
			minStep=1,
			unit='percentage'
		)
