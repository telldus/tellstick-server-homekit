# -*- coding: utf-8 -*-

from base import Application, Plugin, Settings
from Bonjour import Bonjour
from HapHandler import HapHandler
from SocketServer import TCPServer
from threading import Thread
import random
import ed25519

import logging
import json
from board import Board

class RequestHandler(HapHandler):
	def do_encrypted_GET(self):
		logging.warning('Encrypted GET to %s', self.path)

	def setup(self):
		HapHandler.setup(self)
		RequestHandler.HTTPDServer.newConnection(self)

class HTTPDServer(object):
	def __init__(self, port, context):
		RequestHandler.HTTPDServer = self
		self.context = context
		self.connections = []
		self.httpServer = TCPServer(('', port), RequestHandler)
		self.thread = Thread(target=self.httpServer.serve_forever, name='HomeKit http server')
		self.thread.daemon = True
		self.thread.start()
		Application().registerShutdown(self.sh)

	def newConnection(self, conn):
		HomeKit(self.context).newConnection(conn)

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
		self.httpServer = HTTPDServer(port=self.port, context=self.context)

	def newConnection(self, conn):
		s = Settings('homekit')
		longTermKey = s.get('longTermKey', None)
		password = s.get('password', None)
		if longTermKey is None or password is None:
			# No public key, generate
			signingKey, verifyingKey = ed25519.create_keypair()
			longTermKey = signingKey.to_ascii(encoding='hex')
			pw = ''.join([str(random.randint(0,9)) for i in range(8)])
			password = '%s-%s-%s' % (pw[0:3], pw[3:5], pw[5:8])
			s['longTermKey'] = longTermKey
			s['password'] = password
		conn.setLongTermKey(longTermKey, password)


