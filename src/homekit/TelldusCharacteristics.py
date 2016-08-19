# -*- coding: utf-8 -*-

from telldus import Device

from HapCharacteristics import *

class OnCharacteristics(HapOnCharacteristics):
	def __init__(self, device):
		state, stateValue = device.state()
		initialValue = True if state != Device.TURNOFF else False
		super(OnCharacteristics,self).__init__(initialValue)

