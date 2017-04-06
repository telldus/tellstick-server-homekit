#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
	from setuptools import setup
	from setuptools.command.bdist_egg import bdist_egg
except ImportError:
	from distutils.core import setup
	from distutils.command.bdist_egg import bdist_egg
import os

class buildweb(bdist_egg):
	def run(self):
		print("generate web application")
		if os.system('npm install') != 0:
			raise Exception("Could not install npm packages")
		if os.system('npm run build') != 0:
			raise Exception("Could not build web application")
		bdist_egg.run(self)

setup(
	name='HomeKit',
	version='1.1',
	icon='homekit.png',
	color='#fcc201',
	author='Micke Prag',
	author_email='micke.prag@telldus.se',
	category='appliances',
	description='Connects TellStick to the Apple Home app in iOS',
	long_description="""HomeKit allows seamless integration between iOS devices and home automation accessories, by promoting a common protocol and providing a public API for configuring and communicating with accessories. HomeKit enables a single app to coordinate and control a range of accessories from multiple vendors. Multiple accessories can act as a single coherent whole, without requiring vendors to coordinate directly with each other.""",
	required_features=['mips'],
	packages=['homekit'],
	package_dir = {'':'src'},
	cmdclass={'bdist_egg': buildweb},
	entry_points={ \
		'telldus.startup': ['c = homekit:HomeKit [cREQ]'],
	},
	extras_require = dict(cREQ = 'Base>=0.1\nBoard>=0.1\nTelldus>=0.1'),
	package_data={'homekit' : [
		'htdocs/*.js',
		'htdocs/*.png',
	]}

)
