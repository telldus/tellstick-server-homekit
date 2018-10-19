# -*- coding: utf-8 -*-

import hashlib
import json
import logging
from SimpleHTTPServer import SimpleHTTPRequestHandler
import socket

import ed25519
import netifaces
import curve25519
from Crypto.Util.number import bytes_to_long, long_to_bytes
from http_parser.parser import HttpParser

from board import Board

from .chacha20 import encrypt_bytes, decrypt_bytes, keysetup
from .hkdf import Hkdf
from .poly1305 import poly1305
from .srp import Server, newVerifier
from .tlv import pack, unpack

# pylint: disable=R0904,R0902
class HapHandler(SimpleHTTPRequestHandler):
	def __init__(self, *args, **kwargs):
		self.encrypted = False
		self.close_connection = 0
		self.command = ''
		self.parsedRequest = None
		self.path = ''
		self.receiveCounter = 0
		self.request_version = None
		self.requestline = ''
		self.sendCounter = 0
		self.sessionStorage = {}
		self.srpServer = None
		self.longTermKey = None
		self.password = None

		SimpleHTTPRequestHandler.__init__(self, *args, **kwargs)

	def pairSetupStep1(self):
		username = 'Pair-Setup'

		(salt, verifier, bits) = newVerifier(username, self.password, 3072)
		self.srpServer = Server(username, salt, verifier, bits)
		seedBytes = long_to_bytes(self.srpServer.seed())

		self.sendTLVResponse([
			{'type': 'state', 'length': 1, 'data': 2},
			{'type': 'public_key', 'length': len(seedBytes), 'data': seedBytes},
			{'type': 'salt', 'length': len(salt), 'data': salt},
		])

	def pairSetupStep2(self, tlvData):
		publicKey = ''.join([chr(x) for x in tlvData['public_key']['data']])
		proof = ''.join([chr(x) for x in tlvData['proof']['data']])

		# TODO: Handle failure if the password if wrong
		serverProof = self.srpServer.proof(bytes_to_long(publicKey), proof)

		self.sendTLVResponse([
			{'type': 'state', 'length': 1, 'data': 4},
			{'type': 'proof', 'length': len(serverProof), 'data': serverProof},
		])

	def pairSetupStep3(self, tlvData):
		encryptedData = tlvData['encrypted_data']['data']

		messageData = encryptedData[:-16]
		authTagData = encryptedData[-16:]

		sPrivate = self.srpServer.key()

		encSalt = b'Pair-Setup-Encrypt-Salt'

		encInfo = b'Pair-Setup-Encrypt-Info'

		key = Hkdf(encSalt, sPrivate, hash=hashlib.sha512)
		outputKey = key.expand(encInfo, length=32)

		try:
			plainText = HapHandler.verifyAndDecrypt(outputKey, 'PS-Msg05', messageData, authTagData) #ok
		except Exception as error:
			logging.warning('Verification failed: %s', error)
			return

		unpackedTLV = unpack(plainText)  # tlv

		clientUsername = ''.join([chr(x) for x in unpackedTLV['identifier']['data']])
		clientLTPK = ''.join([chr(x) for x in unpackedTLV['public_key']['data']])
		clientProof = ''.join([chr(x) for x in unpackedTLV['signature']['data']])

		hkdfEncKey = outputKey
		logging.warning("setup step 4")
		self.pairSetupStep4(clientUsername, clientLTPK, clientProof)
		logging.warning("setup step 5")
		self.pairSetupStep5(hkdfEncKey)
		logging.warning("done")

	def pairSetupStep4(self, clientUsername, clientLTPK, clientProof):
		sPrivate = self.srpServer.key()

		controllerSalt = 'Pair-Setup-Controller-Sign-Salt'
		controllerInfo = 'Pair-Setup-Controller-Sign-Info'

		key = Hkdf(controllerSalt, sPrivate, hash=hashlib.sha512)
		outputKey = key.expand(controllerInfo, length=32)

		completeData = outputKey + clientUsername + clientLTPK

		verifyingKey = ed25519.VerifyingKey(clientLTPK)

		self.addPairing(clientUsername, ed25519.VerifyingKey(clientLTPK).to_ascii(encoding='hex'), 1)

		try:
			verifyingKey.verify(clientProof, completeData)
		except ed25519.BadSignatureError as error:
			logging.warning('Could not verify signature in pairSetup step 4')
			raise error

	def pairSetupStep5(self, hkdfEncKey):
		sPrivate = self.srpServer.key()
		accessorySalt = 'Pair-Setup-Accessory-Sign-Salt'
		accessoryInfo = 'Pair-Setup-Accessory-Sign-Info'

		key = Hkdf(accessorySalt, sPrivate, hash=hashlib.sha512)
		accessoryX = key.expand(accessoryInfo, length=32)

		signingKey = ed25519.SigningKey(self.longTermKey, encoding='hex')
		verifyingKey = signingKey.get_verifying_key()

		accessoryLTPK = verifyingKey.to_bytes()

		accessoryPairingID = HapHandler.getId()

		material = accessoryX + accessoryPairingID + accessoryLTPK

		accessorySignature = signingKey.sign(material)

		response = []
		response.append({
			'type': 'identifier',
			'length': len(accessoryPairingID),
			'data': accessoryPairingID
		})
		response.append({
			'type': 'public_key',
			'length': len(accessoryLTPK),
			'data': accessoryLTPK
		})
		response.append({
			'type': 'signature',
			'length': len(accessorySignature),
			'data': accessorySignature
		})
		output = pack(response)  # tlv

		ciphertext, mac = HapHandler.encryptAndSeal(hkdfEncKey, 'PS-Msg06', [ord(x) for x in output])

		ciphertext = ''.join([chr(x) for x in ciphertext])
		mac = ''.join([chr(x) for x in mac])

		self.sendTLVResponse([
			{'type': 'state', 'length': 1, 'data': 6},
			{'type': 'encrypted_data', 'length': len(ciphertext + mac), 'data': ciphertext + mac},
		])

	def pairVerifyStep1(self, tlvData):
		publicKey = tlvData['public_key']['data']

		accessoryLTSK = ed25519.SigningKey(self.longTermKey, encoding='hex')
		# accessoryLTPK = accessoryLTSK.get_verifying_key()

		accessoryPairingID = HapHandler.getId()

		iosDevicePublicKey = curve25519.Public(''.join([chr(x) for x in publicKey]))

		# Step 1
		private = curve25519.Private()
		public = private.get_public()
		publicSerialized = public.serialize()

		# Step 2
		shared = private.get_shared_key(iosDevicePublicKey, hashfunc=lambda x: x)

		# Step 3
		accessoryPairingInfo = publicSerialized + accessoryPairingID + iosDevicePublicKey.serialize()

		# Step 4
		accessorySignature = accessoryLTSK.sign(accessoryPairingInfo)

		# Step 5
		response = []
		response.append({
			'type': 'identifier',
			'length': len(accessoryPairingID),
			'data': accessoryPairingID
		})
		response.append({
			'type': 'signature',
			'length': len(accessorySignature),
			'data': accessorySignature
		})
		subTLV = pack(response)  # tlv

		# Step 6
		inputKey = shared
		salt = 'Pair-Verify-Encrypt-Salt'
		info = 'Pair-Verify-Encrypt-Info'

		key = Hkdf(salt, inputKey, hash=hashlib.sha512)
		sessionKey = key.expand(info, length=32)

		key = Hkdf('Control-Salt', shared, hash=hashlib.sha512)
		writeKey = key.expand('Control-Write-Encryption-Key', length=32)

		key = Hkdf('Control-Salt', shared, hash=hashlib.sha512)
		readKey = key.expand('Control-Read-Encryption-Key', length=32)


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

		self.sendTLVResponse([
			{'type': 'state', 'length': 1, 'data': 2},
			{'type': 'public_key', 'length': len(publicSerialized), 'data': publicSerialized},
			{'type': 'encrypted_data', 'length': len(ciphertext + mac), 'data': ciphertext + mac},
		])

	def pairVerifyStep2(self, tlvData):
		# Step 1
		encryptedData = tlvData['encrypted_data']['data']
		messageData = encryptedData[:-16]
		authTagData = encryptedData[-16:]

		try:
			plainText = HapHandler.verifyAndDecrypt(
				self.sessionStorage['hkdfPairEncKey'],
				'PV-Msg03',
				messageData,
				authTagData
			)
		except Exception as __error:
			self.sendTLVResponse([
				{'type': 'state', 'length': 1, 'data': 4},
				{'type': 'error', 'length': 1, 'data': 2},
			])
			return

		# Step 2
		unpackedTLV = unpack(plainText)  # tlv

		# Step 3
		iOSDevicePairingID = ''.join([chr(x) for x in unpackedTLV['identifier']['data']])
		iOSDeviceSignature = ''.join([chr(x) for x in unpackedTLV['signature']['data']])
		pairing = None
		for storedPairing in self.retrievePairings():
			if iOSDevicePairingID == storedPairing['identifier']:
				pairing = storedPairing
				break
		if pairing is None:
			self.sendTLVResponse([
				{'type': 'state', 'length': 1, 'data': 4},
				{'type': 'error', 'length': 1, 'data': 2},
			])
			return
		self.sessionStorage['clientID'] = iOSDevicePairingID
		self.sessionStorage['clientLTPK'] = pairing['publicKey']
		self.sessionStorage['admin'] = pairing['permissions']

		# Step 4
		iOSDeviceInfo = self.sessionStorage['clientPublicKey'] \
			+ iOSDevicePairingID \
			+ self.sessionStorage['publicKey']
		verifyingKey = ed25519.VerifyingKey(self.sessionStorage['clientLTPK'], encoding='hex')
		try:
			verifyingKey.verify(iOSDeviceSignature, iOSDeviceInfo)
		except ed25519.BadSignatureError:
			self.sendTLVResponse([
				{'type': 'state', 'length': 1, 'data': 4},
				{'type': 'error', 'length': 1, 'data': 2},
			])
			return

		# Step 5
		self.encrypted = True

		self.sendTLVResponse([
			{'type': 'state', 'length': 1, 'data': 4}
		])

	@staticmethod
	def addPairing(__identifier, __publicKey, __admin):
		# Overloaded in HapConnection
		return False

	@staticmethod
	def removePairing(__identifier):
		# Overloaded in HapConnection
		return False

	@staticmethod
	def retrievePairings():
		# Overloaded in HapConnection
		return []

	def __addPairing(self, tlvData):
		identifier = ''.join([chr(x) for x in tlvData['identifier']['data']])
		publicKey = ''.join(['%02x' % x for x in tlvData['public_key']['data']])
		admin = tlvData['permissions']['data'][0]

		response = []
		response.append({'type': 'state', 'length': 1, 'data': 2})
		if self.sessionStorage['admin'] != 1:
			response.append({'type': 'error', 'length': 1, 'data': 2})
		elif not self.addPairing(identifier, publicKey, admin):
			response.append({'type': 'error', 'length': 1, 'data': 1})
		output = pack(response)  # tlv

		self.sendEncryptedResponse(output, contentType='application/pairing+tlv8')

	def __removePairing(self, tlvData):
		identifier = ''.join([chr(x) for x in tlvData['identifier']['data']])

		logging.warning("Remove pairing %s", identifier)
		response = []
		response.append({'type': 'state', 'length': 1, 'data': 2})
		if self.sessionStorage['admin'] != 1:
			response.append({'type': 'error', 'length': 1, 'data': 2})
		elif not self.removePairing(identifier):
			response.append({'type': 'error', 'length': 1, 'data': 1})
		output = pack(response)  # tlv
		self.sendEncryptedResponse(output, contentType='application/pairing+tlv8')

	def pairings(self, __tlvData):
		response = []
		response.append({'type': 'state', 'length': 1, 'data': 2})
		for pairing in self.retrievePairings():
			if len(response) > 1:
				response.append({'type': 'separator', 'length': 0, 'data': ''})
			response.append({
				'type': 'identifier',
				'length': len(pairing['identifier']),
				'data': str(pairing['identifier'])
			})
			response.append({
				'type': 'public_key',
				'length': len(pairing['publicKey']),
				'data': str(pairing['publicKey'])
			})
			response.append({'type': 'permissions', 'length': 1, 'data': pairing['permissions']})
		output = pack(response)  # tlv

		self.sendEncryptedResponse(output, contentType='application/pairing+tlv8')

	def do_encrypted_POST(self):
		if self.path == '/pairings':
			tlvData = unpack(self.parsedRequest)  # tlv
			if tlvData['method']['data'][0] == 3:
				self.__addPairing(tlvData)
			elif tlvData['method']['data'][0] == 4:
				self.__removePairing(tlvData)
			elif tlvData['method']['data'][0] == 5:
				self.pairings(tlvData)

	def do_POST(self):
		logging.warning('POST to %s', self.path)
		if 'Content-Length' not in self.headers:
			self.close_connection = 1
			return
		length = int(self.headers['Content-Length'])
		data = self.rfile.read(length)
		tlvData = unpack(data)  # tlv

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
		if not self.encrypted:
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
			length = ord(addData[0]) | ord(addData[1]) << 8
			ciphertext = [ord(x) for x in self.rfile.read(length)]
			mac = [ord(x) for x in self.rfile.read(16)]

			nonce = []
			noneVal = self.receiveCounter
			for __i in range(8):
				nonce.append(chr(noneVal & 0xFF))
				noneVal >>= 8
			nonceStr = ''.join(nonce)

			raw_requestline = ''.join([
				chr(x) for x in HapHandler.verifyAndDecrypt(
					self.sessionStorage['writeKey'],
					nonceStr,
					ciphertext,
					mac,
					addData=[ord(x) for x in addData]
				)
			])
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

			parser = HttpParser()
			parser.execute(raw_requestline, len(raw_requestline))
			self.parsedRequest = parser.recv_body()

			mname = 'do_encrypted_' + self.command
			if not hasattr(self, mname):
				self.send_error(501, 'Unsupported method (%r)' % self.command)
				return
			method = getattr(self, mname)
			try:
				method()
			except Exception as error:
				logging.exception(error)
				self.send_error(500, 'Error during call (%r)' % self.command)
				return
			self.wfile.flush()
		except socket.timeout, error:
			# a read or a write timed out.Discard this connection
			self.log_error('Request timed out: %r', error)
			self.close_connection = 1
		return

	def output(self, data):
		for char in data:
			self.wfile.write(char)

	def sendTLVResponse(self, tlvData):
		if isinstance(tlvData, list):
			output = pack(tlvData)  # tlv
		else:
			output = tlvData
		self.send_response(200)
		self.send_header('Content-Type', 'application/pairing+tlv8')
		self.send_header('Connection', 'keep-alive')
		self.send_header('Content-Length', len(output))
		self.end_headers()
		self.output(output)


	def sendEncryptedResponse(
		self,
		msg,
		status='200 OK',
		contentType='application/hap+json',
		protocol='HTTP/1.1'
	):
		if isinstance(msg, dict):
			msg = json.dumps(msg)
		output = '%s %s\r\nContent-Type: %s\r\nConnection: keep-alive\r\nContent-Length: %i\r\n\r\n%s' % (
			protocol,
			status,
			contentType,
			len(msg),
			msg
		)
		while len(output):
			data = output[:1024]
			output = output[1024:]
			length = len(data)
			addData = [length&0xFF, (length>>8)&0xFF]
			nonce = []
			noneVal = self.sendCounter
			for __i in range(8):
				nonce.append(chr(noneVal & 0xFF))
				noneVal >>= 8
			nonceStr = ''.join(nonce)
			ciphertext, mac = HapHandler.encryptAndSeal(
				self.sessionStorage['readKey'],
				nonceStr,
				[ord(x) for x in data],
				addData=addData
			)

			request = addData + ciphertext + mac
			encryptedRequest = ''.join([chr(x) for x in request])
			try:
				self.wfile.write(encryptedRequest)
			except Exception as error:
				logging.error("Error writing to socket")
				logging.exception(error)
				self.close_connection = 1
				return
			self.sendCounter = self.sendCounter + 1

	def setLongTermKey(self, key, password):
		self.longTermKey = key
		self.password = password

	@staticmethod
	def verifyAndDecrypt(key, nonce, ciphertext, mac, addData=None):
		ctx = keysetup(nonce, key)  # chacha20
		zeros = [0]*64

		poly1305key = encrypt_bytes(ctx, zeros, len(zeros))  # chacha20
		poly1305ctx = poly1305(poly1305key)

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

		for __i in range(8):
			poly1305ctx.update([addDataLength & 0xFF])
			addDataLength >>= 8
		for __i in range(8):
			poly1305ctx.update([length & 0xFF])
			length >>= 8

		poly = poly1305ctx.finish()
		if poly != mac:
			raise Exception('Verification failed')

		return decrypt_bytes(ctx, ciphertext, len(ciphertext))  # chacha20

	@staticmethod
	def encryptAndSeal(key, nonce, plaintext, addData=None):
		ctx = keysetup(nonce, key)
		zeros = [0]*64

		poly1305key = encrypt_bytes(ctx, zeros, len(zeros))
		poly1305ctx = poly1305(poly1305key)

		ciphertext = encrypt_bytes(ctx, plaintext, len(plaintext))

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

		for __i in range(8):
			poly1305ctx.update([addDataLength & 0xFF])
			addDataLength >>= 8
		for __i in range(8):
			poly1305ctx.update([length & 0xFF])
			length >>= 8

		mac = poly1305ctx.finish()

		return ciphertext, mac

	@staticmethod
	def getId():
		ifname = Board.networkInterface()
		addrs = netifaces.ifaddresses(ifname)
		try:
			mac = addrs[netifaces.AF_LINK][0]['addr']
		except (IndexError, KeyError) as __error:
			return ''
		return str(mac)
