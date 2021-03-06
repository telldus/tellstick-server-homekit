# -*- coding: utf-8 -*-

import colorsys
from telldus import Device

from .HapAccessory import HapAccessory, HapService
from .HapCharacteristics import \
	HapBatteryLevelCharacteristics, \
	HapCharacteristic, \
	HapChargingStateCharacteristics, \
	HapHueCharacteristics, \
	HapSaturationCharacteristics, \
	HapStatusLowBatteryCharacteristics
from .TelldusCharacteristics import \
	BrightnessCharacteristics, \
	OnCharacteristics, \
	ProgrammableSwitchEventCharacteristics


class HapDeviceAccessory(HapAccessory):
	def __init__(self, device):
		super(HapDeviceAccessory, self).__init__(
			'Unknown',
			device.typeString(),
			device.name(),
			device.id()
		)
		self.device = device
		methods = device.methods()
		if methods & (Device.DIM | Device.RGBW) > 0:
			# Supports Dim/RGBW - Type=Bulb
			service = HapService(HapService.TYPE_LIGHTBULB)
			service.addCharacteristics(OnCharacteristics(device))
			if methods & Device.DIM > 0:
				service.addCharacteristics(BrightnessCharacteristics(device))
			if methods & Device.RGBW > 0:
				service.addCharacteristics(HapHueCharacteristics())
				service.addCharacteristics(HapSaturationCharacteristics())
			self.addService(service)
		elif methods & (Device.TURNON | Device.TURNOFF) > 0:
			# Supports On/Off - Type=Switch
			service = HapService(HapService.TYPE_SWITCH)
			service.addCharacteristics(OnCharacteristics(device))
			self.addService(service)
		elif methods == 0 and device.isSensor() is False:
			# No methods but not sensor. Probably magnet switch or motion sensor
			service = HapService(HapService.TYPE_STATELESS_PROGRAMMABLE_SWITCH)
			service.addCharacteristics(ProgrammableSwitchEventCharacteristics(device))
			self.addService(service)
		if device.battery() is not None:
			level = device.battery()
			service = HapService(HapService.TYPE_BATTERY)
			service.addCharacteristics(HapBatteryLevelCharacteristics(level))
			service.addCharacteristics(HapChargingStateCharacteristics(0))
			service.addCharacteristics(HapStatusLowBatteryCharacteristics(0))
			self.addService(service)

	def characteristicsWasUpdated(self, iids):
		# Convert iids to types
		types = {}
		for iid in iids:
			characteristic = self.characteristic(iid)
			types[characteristic['type']] = characteristic
		if HapCharacteristic.TYPE_HUE in types or HapCharacteristic.TYPE_SATURATION in types:
			if HapCharacteristic.TYPE_HUE in types:
				hue = types[HapCharacteristic.TYPE_HUE].value()
			else:
				hue = self.characteristic(characteristicType=HapCharacteristic.TYPE_HUE).value()
			if HapCharacteristic.TYPE_SATURATION in types:
				saturation = types[HapCharacteristic.TYPE_SATURATION].value()
			else:
				saturation = self.characteristic(characteristicType=HapCharacteristic.TYPE_SATURATION).value()
			red, green, blue = colorsys.hsv_to_rgb(hue/360.0, saturation/100.0, 1)
			color = int('%02X%02X%02X00' % (red*255, green*255, blue*255), 16)
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
