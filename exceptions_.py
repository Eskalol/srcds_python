"""
	
"""

class ErrorInvalidPacketType(Exception):
	"""This Exception is thrown when a user pass a invalid packet_type to send function"""
	def __str__(self):
		"""returns str of the Exception
		
		Returns:
		    str: a usefull message
		"""
		return repr('Invalid packet type, must be 3 or 2')