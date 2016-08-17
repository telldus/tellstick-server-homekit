# -*- coding: utf-8 -*-

from board import Board
from Crypto.Util.number import bytes_to_long, long_to_bytes
from http_parser.parser import HttpParser
from SimpleHTTPServer import SimpleHTTPRequestHandler
import chacha20
import curve25519
import ed25519
import fcntl
import hashlib
import hkdf
import json
import poly1305
import srp
import socket
import struct
import tlv

import logging


class HapHandler(SimpleHTTPRequestHandler):
	def __init__(self, *args, **kwargs):
		self.encrypted = False
		self.receiveCounter = 0
		self.sendCounter = 0
		self.sessionStorage = {}
		SimpleHTTPRequestHandler.__init__(self, *args, **kwargs)

	def pairSetupStep1(self):
		username = 'Pair-Setup'

		(self.salt, verifier, bits) = srp.newVerifier(username, self.password, 3072)
		self.sv = srp.Server(username, self.salt, verifier, bits)
		self.B = long_to_bytes(self.sv.seed())

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 2})
		response.append({'type': 'public_key', 'length': len(self.B), 'data': self.B})
		response.append({'type': 'salt', 'length': len(self.salt), 'data': self.salt})
		output = tlv.pack(response)

		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)

	def pairSetupStep2(self, tlvData):
		publicKey = ''.join([chr(x) for x in (tlvData['public_key']['data'])])
		proof = ''.join([chr(x) for x in (tlvData['proof']['data'])])

		# TODO: Handle failure if the password if wrong
		serverProof = self.sv.proof(bytes_to_long(publicKey), proof)

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 4})
		response.append({'type': 'proof', 'length': len(serverProof), 'data': serverProof})
		output = tlv.pack(response)

		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)

	def pairSetupStep3(self, tlvData):
		encryptedData = tlvData['encrypted_data']['data']

		messageData = encryptedData[:-16]
		authTagData = encryptedData[-16:]

		S_private = self.sv.key()

		encSalt = b'Pair-Setup-Encrypt-Salt'

		encInfo = b'Pair-Setup-Encrypt-Info'

		h = hkdf.Hkdf(encSalt, S_private, hash=hashlib.sha512)
		outputKey = h.expand(encInfo, length=32)

		try:
			plainText = HapHandler.verifyAndDecrypt(outputKey, 'PS-Msg05', messageData, authTagData) #ok
		except Exception as e:
			logging.warning('Verification failed: %s', e)
			return

		unpackedTLV = tlv.unpack(plainText) #ok

		clientUsername = ''.join([chr(x) for x in unpackedTLV['identifier']['data']])
		clientLTPK = ''.join([chr(x) for x in unpackedTLV['public_key']['data']])
		clientProof = ''.join([chr(x) for x in unpackedTLV['signature']['data']])

		hkdfEncKey = outputKey
		self.pairSetupStep4(clientUsername, clientLTPK, clientProof)
		self.pairSetupStep5(hkdfEncKey)

	def pairSetupStep4(self, clientUsername, clientLTPK, clientProof):
		S_private = self.sv.key()

		controllerSalt = 'Pair-Setup-Controller-Sign-Salt'
		controllerInfo = 'Pair-Setup-Controller-Sign-Info'

		h = hkdf.Hkdf(controllerSalt, S_private, hash=hashlib.sha512)
		outputKey = h.expand(controllerInfo, length=32)

		completeData = outputKey + clientUsername + clientLTPK

		verifyingKey = ed25519.VerifyingKey(clientLTPK)

		self.addPairing(clientUsername, ed25519.VerifyingKey(clientLTPK).to_ascii(encoding='hex'), 1)

		try:
			verifyingKey.verify(clientProof, completeData)
		except ed25519.BadSignatureError as e:
			logging.warning('Could not verify signature in pairSetup step 4')
			raise e

	def pairSetupStep5(self, hkdfEncKey):
		S_private = self.sv.key()
		accessorySalt = 'Pair-Setup-Accessory-Sign-Salt'
		accessoryInfo = 'Pair-Setup-Accessory-Sign-Info'

		h = hkdf.Hkdf(accessorySalt, S_private, hash=hashlib.sha512)
		AccessoryX = h.expand(accessoryInfo, length=32)

		signingKey = ed25519.SigningKey(self.longTermKey, encoding='hex')
		verifyingKey = signingKey.get_verifying_key()

		AccessoryLTPK = verifyingKey.to_bytes()

		AccessoryPairingID = HapHandler.getId()

		material = AccessoryX + AccessoryPairingID + AccessoryLTPK

		AccessorySignature = signingKey.sign(material)

		response = []
		response.append({'type': 'identifier', 'length': len(AccessoryPairingID), 'data': AccessoryPairingID})
		response.append({'type': 'public_key', 'length': len(AccessoryLTPK), 'data': AccessoryLTPK})
		response.append({'type': 'signature', 'length': len(AccessorySignature), 'data': AccessorySignature})
		output = tlv.pack(response)

		ciphertext, mac = HapHandler.encryptAndSeal(hkdfEncKey, 'PS-Msg06', [ord(x) for x in output])

		ciphertext = ''.join([chr(x) for x in ciphertext])
		mac = ''.join([chr(x) for x in mac])

		# Todo
		#txt['sf'] = 0
		#pybonjour.DNSServiceUpdateRecord(sdRef, None, 0, pybonjour.TXTRecord(txt))

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 6})
		response.append({'type': 'encrypted_data', 'length': len(ciphertext + mac), 'data': ciphertext + mac})
		output = tlv.pack(response)

		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)

	def pairVerifyStep1(self, tlvData):
		publicKey = tlvData['public_key']['data']

		AccessoryLTSK = ed25519.SigningKey(self.longTermKey, encoding='hex')
		AccessoryLTPK = AccessoryLTSK.get_verifying_key()

		AccessoryPairingID = HapHandler.getId()

		iosDevicePublicKey = curve25519.Public(''.join([chr(x) for x in publicKey]))

		# Step 1
		private = curve25519.Private()
		public = private.get_public()
		publicSerialized = public.serialize()

		# Step 2
		shared = private.get_shared_key(iosDevicePublicKey, hashfunc=lambda x: x)

		# Step 3
		AccessoryPairingInfo = publicSerialized + AccessoryPairingID + iosDevicePublicKey.serialize()

		# Step 4
		AccessorySignature = AccessoryLTSK.sign(AccessoryPairingInfo)

		# Step 5
		response = []
		response.append({'type': 'identifier', 'length': len(AccessoryPairingID), 'data': AccessoryPairingID})
		response.append({'type': 'signature', 'length': len(AccessorySignature), 'data': AccessorySignature})
		subTLV = tlv.pack(response)

		# Step 6
		InputKey = shared
		Salt = 'Pair-Verify-Encrypt-Salt'
		Info = 'Pair-Verify-Encrypt-Info'

		h = hkdf.Hkdf(Salt, InputKey, hash=hashlib.sha512)
		sessionKey = h.expand(Info, length=32)

		h = hkdf.Hkdf('Control-Salt', shared, hash=hashlib.sha512)
		writeKey = h.expand('Control-Write-Encryption-Key', length=32)

		h = hkdf.Hkdf('Control-Salt', shared, hash=hashlib.sha512)
		readKey = h.expand('Control-Read-Encryption-Key', length=32)


		self.sessionStorage = {
			'clientPublicKey': iosDevicePublicKey.serialize(),
			'secretKey': private.serialize(),
			'publicKey': publicSerialized,
			'sharedSec': shared,
			'hkdfPairEncKey': sessionKey,
			'writeKey': writeKey,
			'readKey': readKey
		}

		# Step 7
		ciphertext, mac = HapHandler.encryptAndSeal(sessionKey, 'PV-Msg02', [ord(x) for x in subTLV])

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 2})
		response.append({'type': 'public_key', 'length': len(publicSerialized), 'data': publicSerialized})
		response.append({'type': 'encrypted_data', 'length': len(ciphertext + mac), 'data': ciphertext + mac})
		output = tlv.pack(response)

		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)

	def pairVerifyStep2(self, tlvData):
		publicKey = tlvData['encrypted_data']['data']

		# TODO Verify encrypted_data
		self.encrypted = True

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 4})
		output = tlv.pack(response)

		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)

	def addPairing(self, identifier, publicKey, admin):
		return False

	def removePairing(self, identifier):
		return False

	def __addPairing(self, tlvData):
		identifier = ''.join([chr(x) for x in tlvData['identifier']['data']])
		publicKey = ''.join(['%x' % x for x in tlvData['public_key']['data']])
		admin = tlvData['permissions']['data'][0]
		logging.warning('Identifier %s', identifier)
		logging.warning('PublicKey %s', publicKey)
		logging.warning('Permissions %s', admin)

		# TODO: Check admin bit

		response = []
		if self.addPairing(identifier, publicKey, admin):
			response.append({'type': 'state', 'length': 1, 'data': 2})
		else:
			response.append({'type': 'state', 'length': 1, 'data': 2})
			response.append({'type': 'error', 'length': 1, 'data': 1})
		output = tlv.pack(response)

		self.sendEncryptedResponse(output, contentType='application/pairing+tlv8')

	def __removePairing(self, tlvData):
		identifier = ''.join([chr(x) for x in tlvData['identifier']['data']])
		# TODO: Check admin bit

		logging.warning("Remove pairing %s", identifier)
		response = []
		if self.removePairing(identifier):
			response.append({'type': 'state', 'length': 1, 'data': 2})
		else:
			response.append({'type': 'state', 'length': 1, 'data': 2})
			response.append({'type': 'error', 'length': 1, 'data': 1})
		output = tlv.pack(response)
		self.sendEncryptedResponse(output, contentType='application/pairing+tlv8')

	def do_encrypted_POST(self):
		if self.path == '/pairings':
			tlvData = tlv.unpack(self.parsedRequest)
			if tlvData['method']['data'][0] == 3:
				self.__addPairing(tlvData)
			elif tlvData['method']['data'][0] == 4:
				self.__removePairing(tlvData)

	def do_POST(self):
		logging.warning('POST to %s', self.path)
		if 'Content-Length' not in self.headers:
			self.close_connection = 1
			return
		length = int(self.headers['Content-Length'])
		data = self.rfile.read(length)
		tlvData = tlv.unpack(data)

		if self.path == '/pair-setup':
			if tlvData['state']['data'][0] == 1:
				self.pairSetupStep1()
			if tlvData['state']['data'][0] == 3:
				self.pairSetupStep2(tlvData)
			if tlvData['state']['data'][0] == 5:
				self.pairSetupStep3(tlvData)
		elif self.path == '/pair-verify':
			if tlvData['state']['data'][0] == 1:
				self.pairVerifyStep1(tlvData)
			if tlvData['state']['data'][0] == 3:
				self.pairVerifyStep2(tlvData)
		else:
			logging.error('Got call to un unknown HomeKit path: %s', self.path)
			self.close_connection = 1

	def handle_one_request(self):
		if self.encrypted == False:
			# We have not yet started encrypting this stream. Use parent handling
			SimpleHTTPRequestHandler.handle_one_request(self)
			return
		self.handle_one_encrypted_request()

	def handle_one_encrypted_request(self):
		try:
			addData = self.rfile.read(1)
			if len(addData) == 0:
				logging.warning('HomeKit socket closed')
				self.close_connection = 1
				return
			addData = addData + self.rfile.read(1)
			length =ord(addData[0]) | ord(addData[1]) << 8
			ciphertext =[ord(x) for x in self.rfile.read(length)]
			mac = [ord(x) for x in self.rfile.read(16)]

			nonce = []
			noneVal = self.receiveCounter
			for i in range(8):
				nonce.append(chr(noneVal & 0xFF))
				noneVal >>= 8
			nonce = ''.join(nonce)

			raw_requestline = ''.join([chr(x) for x in HapHandler.verifyAndDecrypt(self.sessionStorage['writeKey'], nonce, ciphertext, mac, addData= [ord(x) for x in addData])])
			self.receiveCounter = self.receiveCounter + 1

			if len(raw_requestline) > 65536:
				self.requestline = ''
				self.request_version = ''
				self.command = ''
				self.send_error(414)
				return
			if not raw_requestline:
				self.close_connection = 1
				return

			self.command = None# set in case of error on the first line
			self.request_version = version = self.default_request_version
			self.close_connection = 1
			requestline = raw_requestline.split('\r\n')[0]
			requestline = requestline.rstrip('\r\n')
			self.requestline = requestline
			words = requestline.split()
			if len(words) == 3:
				command, path, version = words
				if version[:5] != 'HTTP/':
					self.send_error(400, 'Bad request version (%r)' % version)
					return
				try:
					base_version_number = version.split('/', 1)[1]
					version_number = base_version_number.split('.')
					# RFC 2145 section 3.1 says there can be only one '.' and
					# - major and minor numbers MUST be treated as
					#separate integers;
					# - HTTP/2.4 is a lower version than HTTP/2.13, which in
					#turn is lower than HTTP/12.3;
					# - Leading zeros MUST be ignored by recipients.
					if len(version_number) != 2:
						raise ValueError
					version_number = int(version_number[0]), int(version_number[1])
				except (ValueError, IndexError):
					self.send_error(400, 'Bad request version (%r)' % version)
					return
				if version_number >= (1, 1) and self.protocol_version >= 'HTTP/1.1':
					self.close_connection = 0
				if version_number >= (2, 0):
					self.send_error(505,
							'Invalid HTTP Version (%s)' % base_version_number)
					return
			elif len(words) == 2:
				command, path = words
				self.close_connection = 1
				if command != 'GET':
					self.send_error(400,
									'Bad HTTP/0.9 request type (%r)' % command)
					return
			elif not words:
				return
			else:
				self.send_error(400, 'Bad request syntax (%r)' % requestline)
				return
			self.command, self.path, self.request_version = command, path, version
			self.close_connection = 0  # keepalive

			p = HttpParser()
			p.execute(raw_requestline, len(raw_requestline))
			self.parsedRequest = p.recv_body()

			mname = 'do_encrypted_' + self.command
			if not hasattr(self, mname):
				self.send_error(501, 'Unsupported method (%r)' % self.command)
				return
			method = getattr(self, mname)
			method()
			self.wfile.flush()
		except socket.timeout, e:
			# a read or a write timed out.Discard this connection
			self.log_error('Request timed out: %r', e)
			self.close_connection = 1
		return

	def output(self, data):
		for c in data:
			self.wfile.write(c)

	def sendEncryptedResponse(self, msg, status='200 OK', contentType='application/hap+json'):
		if type(msg) is dict:
			msg = json.dumps(msg)
		output = 'HTTP/1.1 %s\r\nContent-Type: %s\r\nConnection: keep-alive\r\nContent-Length: %i\r\n\r\n%s' % (
			status,
			contentType,
			len(msg),
			msg
		)
		l = len(output)
		addData = [l&0xFF, (l>>8)&0xFF]
		nonce = []
		noneVal = self.sendCounter
		for i in range(8):
			nonce.append(chr(noneVal & 0xFF))
			noneVal >>= 8
		nonce = ''.join(nonce)
		ciphertext, mac = HapHandler.encryptAndSeal(self.sessionStorage['readKey'], nonce, [ord(x) for x in output], addData=addData)

		r = addData + ciphertext + mac
		encryptedRequest = ''.join([chr(x) for x in r])
		self.wfile.write(encryptedRequest)
		self.sendCounter = self.sendCounter + 1

	def setLongTermKey(self, key, password):
		self.longTermKey = key
		self.password = password

	@staticmethod
	def verifyAndDecrypt(key,nonce,ciphertext,mac,addData=None):
		ctx = chacha20.keysetup(nonce, key)
		zeros = [0]*64

		poly1305key = chacha20.encrypt_bytes(ctx, zeros, len(zeros))
		poly1305ctx = poly1305.poly1305(poly1305key)

		addDataLength = 0
		if addData is not None:
			addDataLength = len(addData)
			poly1305ctx.update(addData)

			if addDataLength % 16 != 0:
				poly1305ctx.update([0] * (16-(len(addData)%16)))

		poly1305ctx.update(ciphertext)
		length = len(ciphertext)
		if length % 16 != 0:
			poly1305ctx.update([0] * (16-(len(ciphertext)%16)))

		for i in range(8):
			poly1305ctx.update([addDataLength & 0xFF])
			addDataLength >>= 8
		for i in range(8):
			poly1305ctx.update([length & 0xFF])
			length >>= 8

		p = poly1305ctx.finish()
		if p != mac:
			raise Exception('Verification failed')

		return chacha20.decrypt_bytes(ctx, ciphertext, len(ciphertext))

	@staticmethod
	def encryptAndSeal(key, nonce, plaintext, addData=None):
		ctx = chacha20.keysetup(nonce, key)
		zeros = [0]*64

		poly1305key = chacha20.encrypt_bytes(ctx, zeros, len(zeros))
		poly1305ctx = poly1305.poly1305(poly1305key)

		ciphertext = chacha20.encrypt_bytes(ctx, plaintext, len(plaintext))

		addDataLength = 0
		if addData is not None:
			addDataLength = len(addData)
			poly1305ctx.update(addData)

			if addDataLength % 16 != 0:
				poly1305ctx.update([0] * (16-(len(addData)%16)))
		poly1305ctx.update(ciphertext)
		length = len(plaintext)
		if len(ciphertext) % 16 != 0:
			poly1305ctx.update([0] * (16-(len(ciphertext)%16)))

		for i in range(8):
			poly1305ctx.update([addDataLength & 0xFF])
			addDataLength >>= 8
		for i in range(8):
			poly1305ctx.update([length & 0xFF])
			length >>= 8

		mac = poly1305ctx.finish()

		return ciphertext, mac

	@staticmethod
	def getId():
		ifname = Board.networkInterface()
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
		return ':'.join(['%02X' % ord(char) for char in info[18:24]])
