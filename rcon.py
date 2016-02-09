# -*- coding: utf-8 -*-
"""This package is created to execute rcon commands on a given source dedicated server



Attributes:
    SERVERDATA_AUTH (int): Typically, the first packet sent by the client will be a SERVERDATA_AUTH packet,
    	which is used to authenticate the connection with the server,
    	values in packet: (packet_id, packet_type=3, packet_body=[rcon password])

    SERVERDATA_AUTH_RESPONSE (int): This packet is a notification of the connection's current auth status.
    	When the server receives an auth request,
    	it will respond with an empty SERVERDATA_RESPONSE_VALUE,
    	followed immediately by a SERVERDATA_AUTH_RESPONSE indicating whether authentication succeeded or failed.
		Note that the status code is returned in the packet id field, 
		so when pairing the response with the original auth request, 
		you may need to look at the packet id of the preceeding SERVERDATA_RESPONSE_VALUE.
		If authentication was successful, the ID assigned by the request. If auth failed, -1 (0xFF FF FF FF)
		values in packet: (packet_id, packet_type=2, packet_body=\x00)

    SERVERDATA_EXECCOMMAND (int): This packet type represents a command issued to the server by a client.
		This can be a ConCommand such as mp_switchteams or changelevel,
		a command to set a cvar such as sv_cheats 1,
		or a command to fetch the value of a cvar, such as sv_cheats.
		The response will vary depending on the command issued.
		values in packet: (packet_id, packet_type=2, packet_body=[the command to be executed on the server])

    SERVERDATA_RESPONSE_VALUE (int): A SERVERDATA_RESPONSE_VALUE packet is the response to a SERVERDATA_EXECCOMMAND request.
		values in packet: 
		(packet_id, packet_type=0, packet_body=[server's response to the command or \0x00])
"""
import select, socket, struct, logging as log
from exceptions_ import ErrorInvalidPacketType

SERVERDATA_AUTH = 3

SERVERDATA_AUTH_RESPONSE = 2

SERVERDATA_EXECCOMMAND = 2

SERVERDATA_RESPONSE_VALUE = 0

#package types end

class Rcon(object):
	"""Summary

	Attributes:
		host (str): ip or hostname
		port (int): port number
		password (str): rcon password
		timeout (float): timeout
		tcp_con (object): connection to the srcds server
		packet_id (int): unique id for each request
	"""

	def __init__(self, host, port, password, verbose=False, timeout=1.0):
		"""Summary
		
		Args:
		    host (TYPE): ip or hostname
		    port (TYPE): port number
		    password (TYPE): rcon password
		    verbose (bool, optional): verbose
		    timeout (float, optional): timeout
		"""
		self.host = host
		self.port = port
		self.password = password
		self.timeout = timeout
		self.tcp_con = None
		self.packet_id = 0
		
		if verbose:
			#logs everything.
			log.basicConfig(format='Rcon %(levelname)s: %(message)s', level=log.DEBUG)
			log.info('Verbose output.')
		else:
			#logs WARNING and ERRORS.
			log.basicConfig(format='Rcon %(levelname)s: %(message)s')

	def disconnect(self):
		"""Disconnect from server
		
		Returns:
		    TYPE: Description
		"""
		if self.tcp_con:
			self.tcp_con.close()

	def connect(self):
		"""Connect to source dedicated server

		Returns:
		    TYPE: Description
		"""

		self.tcp_con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.tcp_con.settimeout(self.timeout)
		try:
			self.tcp_con.connect((self.host, self.port))
			log.info('Connected to: %s:%d' % (self.host, self.port))
		except Exception as e:
			log.error('Could not connect to: %s:%d. Exception: %s' % (self.host, self.port, e))

	def send(self, packet_type, package_body):
		"""This function sends a package to the srcds
		
		package structure:
		________________________________________
		| Field |             Type             |
		|-------|------------------------------|
		| Size  | signed integer little-endian |
		| ID    | signed integer little-endian |
		| Type  | signed integer little-endian |
		| Body  | Null-terminated ASCII String |
		| Empty | 0x00                         |
		|_______|______________________________|
		
		Args:
		    packet_type (int): packet type see:
		    	:py:attr:'.SERVERDATA_AUTH'
		    	:py:attr:'.SERVERDATA_EXECCOMMAND'
		    package_body (TYPE): packet type determines how the package body is intepreted by the server
		    	example: if the packet type is SERVERDATA_AUTH,
		    	the server will expect the packet_body to be an rcon password.
		
		Returns:
		    TYPE: Description
		"""
		if packet_type != SERVERDATA_AUTH and packet_type != SERVERDATA_AUTH_RESPONSE:
			#check for valid packet_type
			raise ErrorInvalidPacketType

		#Increments unique package id.
		self.packet_id += 1
		#Creates packet content in order: (package_id, package_type, package_body, 0x00).
		content = struct.pack('<l', self.packet_id) + struct.pack('<l', packet_type) + package_body + '\x00\x00'
		try:
			#Inserts content size in front of content and sends.
			self.tcp_con.send(struct.pack('<l', len(content)) + content)
			log.info('Sent %d bytes' % (len(content) + 4))
		except Exception as e:
			log.error('Failed to send. Exception: %s' % e)

	def recv(self, sent_packet_type=SERVERDATA_EXECCOMMAND):
		"""Summary
		
		Returns:
		    TYPE: Description
		
		Args:
		    sent_packet_type (str, optional): Description
		"""
		packet_size = 0
		packet_id = 0
		packet_type = 0
		packet_body = ''

		recv_next_bytes = 4
		while 1:

			try:
				recv = self.tcp_con.recv(recv_next_bytes)
				if len(recv) >= 4:
					if packet_size == 0:
						packet_size = struct.unpack('<l', recv)[0]
						recv_next_bytes = packet_size
						print packet_size
					else:
						packet_id = struct.unpack('<l', recv[:4])[0]
						packet_type = struct.unpack('<l', recv[4:8])[0]
						package_body = recv[8:]
						print packet_type, package_body
						if sent_packet_type == SERVERDATA_AUTH:
							self.recv()
						break
			except socket.timeout:
				print 'timeout'
				break
			except:
				print 'faen!'
				break
		return packet_type, package_body


if __name__ == '__main__':
	rcon = Rcon('192.168.1.36', 27015, 'karasjok', True)
	rcon.connect()
	rcon.send(3, 'karasjok')
	rcon.recv(SERVERDATA_AUTH)
	
	rcon.send(2, 'status')
	rcon.recv()
	
	rcon.disconnect()
	