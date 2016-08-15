# -*- coding: utf-8 -*-

from base import Application, Plugin
from Bonjour import Bonjour
from HapHandler import HapHandler
from SocketServer import TCPServer
from threading import Thread
import random

import logging
import json
from board import Board

class RequestHandler(HapHandler):
	def do_encrypted_GET(self):
		logging.warning('Encrypted GET to %s', self.path)

class HTTPDServer(object):
	def __init__(self, port):
		self.httpServer = TCPServer(('', port), RequestHandler)
		self.thread = Thread(target=self.httpServer.serve_forever, name='HomeKit http server')
		self.thread.daemon = True
		self.thread.start()
		Application().registerShutdown(self.sh)

	def sh(self):
		logging.warning("Shutting down HAP server")
		#self.httpServer.shutdown()
		logging.warning("Server was shut down")

class HomeKit(Plugin):
	def __init__(self):
		Application().queue(self.start)

	def start(self):
		self.port    = random.randint(8000, 8080)
		self.bonjour = Bonjour(port=self.port)
		self.httpServer = HTTPDServer(port=self.port)

