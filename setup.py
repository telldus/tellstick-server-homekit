#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from setuptools import setup
except ImportError:
	from distutils.core import setup

setup(
	name='HomeKit',
	version='1.0',
	icon='homekit.png',
	color='#fcc201',
	author='Micke Prag',
	author_email='micke.prag@telldus.se',
	description='Connects TellStick to the Apple Home app in iOS',
	long_description="""HomeKit allows seamless integration between iOS devices and home automation accessories, by promoting a common protocol and providing a public API for configuring and communicating with accessories. HomeKit enables a single app to coordinate and control a range of accessories from multiple vendors. Multiple accessories can act as a single coherent whole, without requiring vendors to coordinate directly with each other.""",
	required_features=['mips'],
	packages=['homekit'],
	package_dir = {'':'src'},
	entry_points={ \
		'telldus.startup': ['c = homekit:HomeKit [cREQ]'],
	},
	extras_require = dict(cREQ = 'Base>=0.1\nBoard>=0.1\nTelldus>=0.1'),
)
