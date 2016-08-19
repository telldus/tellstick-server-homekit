# -*- coding: utf-8 -*-

from telldus import Device

from HapCharacteristics import *

class BrightnessCharacteristics(HapBrightnessCharacteristics):
	def __init__(self, device):
		state, stateValue = device.state()
		if state == Device.DIM:
			initialValue = int(round(int(stateValue)/255.0*100.0))
		elif state == Device.TURNON:
			initialValue = 100
		elif state == Device.TURNOFF:
			initialValue = 0
		else:
			initialValue = 100
		super(BrightnessCharacteristics,self).__init__(initialValue)

class OnCharacteristics(HapOnCharacteristics):
	def __init__(self, device):
		state, stateValue = device.state()
		initialValue = True if state != Device.TURNOFF else False
		super(OnCharacteristics,self).__init__(initialValue)

