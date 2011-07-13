#!/usr/bin/env python
#
# pywallet.py 1.1
#
# based on http://github.com/gavinandresen/bitcointools
#
# Usage: pywallet.py [options]
#
# Options:
#   --version            show program's version number and exit
#   -h, --help           show this help message and exit
#   --dumpwallet         dump wallet in json format
#   --importprivkey=KEY  import private key from vanitygen
#   --datadir=DATADIR    wallet directory (defaults to bitcoin default)

from bsddb.db import *
import os, sys, time
import json
import logging
import struct
import StringIO
import traceback
import socket
import types
import string
import exceptions
import hashlib
from ctypes import *

json_db = {}
private_keys = []
addrtype = 0

def determine_db_dir():
	import os
	import os.path
	import platform
	if platform.system() == "Darwin":
		return os.path.expanduser("~/Library/Application Support/Bitcoin/")
	elif platform.system() == "Windows":
		return os.path.join(os.environ['APPDATA'], "Bitcoin")
	return os.path.expanduser("~/.bitcoin")

dlls = list()
if 'win' in sys.platform:
    for d in ('libeay32.dll', 'libssl32.dll', 'ssleay32.dll'):
        try:
            dlls.append( cdll.LoadLibrary(d) )
        except:
            pass
else:
    dlls.append( cdll.LoadLibrary('libssl.so') )
            
class BIGNUM_Struct (Structure):
    _fields_ = [("d",c_void_p),("top",c_int),("dmax",c_int),("neg",c_int),("flags",c_int)]
                
class BN_CTX_Struct (Structure):
    _fields_ = [ ("_", c_byte) ]

BIGNUM = POINTER( BIGNUM_Struct )
BN_CTX = POINTER( BN_CTX_Struct )

def load_func( name, args, returns = c_int):
    d = sys.modules[ __name__ ].__dict__
    f = None
    
    for dll in dlls:
        try:
            f = getattr(dll, name)
            f.argtypes = args
            f.restype  = returns
            d[ name ] = f
            return
        except:
            pass
    raise ImportError('Unable to load required functions from SSL dlls')
    
load_func( 'BN_new', [], BIGNUM )
load_func( 'BN_CTX_new', [], BN_CTX )
load_func( 'BN_CTX_free', [BN_CTX], None   )
load_func( 'BN_num_bits', [BIGNUM], c_int )
load_func( 'BN_bn2bin',  [BIGNUM, c_char_p] )
load_func( 'BN_bin2bn',  [c_char_p, c_int, BIGNUM], BIGNUM )
load_func( 'EC_KEY_new_by_curve_name', [c_int], c_void_p )
load_func( 'EC_KEY_get0_group', [c_void_p], c_void_p)
load_func( 'EC_KEY_get0_private_key', [c_void_p], BIGNUM)
load_func( 'EC_POINT_new', [c_void_p], c_void_p)
load_func( 'EC_POINT_free', [c_void_p])
load_func( 'EC_POINT_mul', [c_void_p, c_void_p, BIGNUM, c_void_p, BIGNUM, BN_CTX], c_int)
load_func( 'EC_KEY_set_private_key', [c_void_p, BIGNUM], c_void_p)
load_func( 'EC_KEY_set_public_key', [c_void_p, c_void_p], c_void_p)
load_func( 'i2d_ECPrivateKey', [ c_void_p, POINTER(POINTER(c_char))], c_int )
load_func( 'i2o_ECPublicKey', [ c_void_p, POINTER(POINTER(c_char))], c_int )

def BN_num_bytes(a):
    return ((BN_num_bits(a)+7)/8)

NID_secp256k1 = 714

pkey = 0

def EC_KEY_regenerate_key(eckey, priv_key):
	group = EC_KEY_get0_group(eckey)
	ctx = BN_CTX_new()
	pub_key = EC_POINT_new(group)
	EC_POINT_mul(group, pub_key, priv_key, None, None, ctx)
	EC_KEY_set_private_key(eckey, priv_key)
	EC_KEY_set_public_key(eckey, pub_key)
	EC_POINT_free(pub_key)
	BN_CTX_free(ctx)

def GetSecret(pkey):
	bn = EC_KEY_get0_private_key(pkey)
	nSize = BN_num_bytes(bn)
	b = create_string_buffer(nSize)
	BN_bn2bin(bn, b)
	return b.raw
	
def GetPrivKey(pkey):
	nSize = i2d_ECPrivateKey(pkey, None)
	p = create_string_buffer(nSize)
 	i2d_ECPrivateKey(pkey, byref(cast(p, POINTER(c_char))))
	return p.raw

def GetPubKey(pkey):
	nSize = i2o_ECPublicKey(pkey, None)
	p = create_string_buffer(nSize)
	i2o_ECPublicKey(pkey, byref(cast(p, POINTER(c_char))))
	return p.raw

def Hash(data):
	s1 = hashlib.sha256()
	s1.update(data)
	h1 = s1.digest()
	s2 = hashlib.sha256()
	s2.update(h1)
	h2 = s2.digest()
	return h2

def EncodeBase58Check(vchIn):
	hash = Hash(vchIn)
	return b58encode(vchIn + hash[0:4])

def DecodeBase58Check(psz):
	vchRet = b58decode(psz, None)
	key = vchRet[0:-4]
	csum = vchRet[-4:]
	hash = Hash(key)
	cs32 = hash[0:4]
	if cs32 != csum:
		return None
	else:
		return key

def SecretToASecret(privkey):
	vchSecret = privkey[9:9+32]
	# add 1-byte version number
	vchIn = "\x80" + vchSecret
	return EncodeBase58Check(vchIn)

def ASecretToSecret(key):
	vch = DecodeBase58Check(key)
	if vch:
		return vch[1:]
	else:
		return False

def importprivkey(db, key):

	vchSecret = ASecretToSecret(key)

	if not vchSecret:
		return False

	pkey = EC_KEY_new_by_curve_name(NID_secp256k1)
	bn = BN_bin2bn(vchSecret, 32, BN_new())
	EC_KEY_regenerate_key(pkey, bn)

	secret = GetSecret(pkey)
	private_key = GetPrivKey(pkey)
	public_key = GetPubKey(pkey)
	addr = public_key_to_bc_address(public_key)

	print "Address: %s" % addr
	print "Privkey: %s" % SecretToASecret(private_key)

	update_wallet(db, 'key', { 'public_key' : public_key, 'private_key' : private_key })
	update_wallet(db, 'name', { 'hash' : addr, 'name' : '' })

	return True

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
	""" encode v, which is a string of bytes, to base58.		
	"""

	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += (256**i) * ord(c)

	result = ''
	while long_value >= __b58base:
		div, mod = divmod(long_value, __b58base)
		result = __b58chars[mod] + result
		long_value = div
	result = __b58chars[long_value] + result

	# Bitcoin does a little leading-zero-compression:
	# leading 0-bytes in the input become leading-1s
	nPad = 0
	for c in v:
		if c == '\0': nPad += 1
		else: break

	return (__b58chars[0]*nPad) + result

def b58decode(v, length):
	""" decode v into a string of len bytes
	"""
	long_value = 0L
	for (i, c) in enumerate(v[::-1]):
		long_value += __b58chars.find(c) * (__b58base**i)

	result = ''
	while long_value >= 256:
		div, mod = divmod(long_value, 256)
		result = chr(mod) + result
		long_value = div
	result = chr(long_value) + result

	nPad = 0
	for c in v:
		if c == __b58chars[0]: nPad += 1
		else: break

	result = chr(0)*nPad + result
	if length is not None and len(result) != length:
		return None

	return result

def hash_160(public_key):
	s1 = hashlib.sha256()
	s1.update(public_key)
	h1 = s1.digest()
	s2 = hashlib.new('ripemd160')
	s2.update(h1)
	h2 = s2.digest()
	return h2

def public_key_to_bc_address(public_key):
	h160 = hash_160(public_key)
	return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160):
	vh160 = chr(addrtype) + h160
	h3 = Hash(vh160)
	addr = vh160 + h3[0:4]
	return b58encode(addr)

def bc_address_to_hash_160(addr):
	bytes = b58decode(addr, 25)
	return bytes[1:21]

def long_hex(bytes):
	return bytes.encode('hex_codec')

def short_hex(bytes):
	t = bytes.encode('hex_codec')
	if len(t) < 32:
		return t
	return t[0:32]+"..."+t[-32:]

def create_env(db_dir=None):
	if db_dir is None:
		db_dir = determine_db_dir()
	db_env = DBEnv(0)
	r = db_env.open(db_dir, (DB_CREATE|DB_INIT_LOCK|DB_INIT_LOG|DB_INIT_MPOOL|DB_INIT_TXN|DB_THREAD|DB_RECOVER))
	return db_env

def parse_CAddress(vds):
	d = {'ip':'0.0.0.0','port':0,'ntime': 0}
	try:
		d['nVersion'] = vds.read_int32()
		d['nTime'] = vds.read_uint32()
		d['nServices'] = vds.read_uint64()
		d['pchReserved'] = vds.read_bytes(12)
		d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
		d['port'] = vds.read_uint16()
	except:
		pass
	return d

def deserialize_CAddress(d):
	return d['ip']+":"+str(d['port'])#+" (lastseen: %s)"%(time.ctime(d['nTime']),)

def parse_setting(setting, vds):
	if setting[0] == "f":	# flag (boolean) settings
		return str(vds.read_boolean())
	elif setting[0:4] == "addr": # CAddress
		d = parse_CAddress(vds)
		return deserialize_CAddress(d)
	elif setting == "nTransactionFee":
		return vds.read_int64()
	elif setting == "nLimitProcessors":
		return vds.read_int32()
	return 'unknown setting'

class SerializationError(Exception):
	""" Thrown when there's a problem deserializing or serializing """

class BCDataStream(object):
	def __init__(self):
		self.input = None
		self.read_cursor = 0

	def clear(self):
		self.input = None
		self.read_cursor = 0

	def write(self, bytes):	# Initialize with string of bytes
		if self.input is None:
			self.input = bytes
		else:
			self.input += bytes

	def map_file(self, file, start):	# Initialize with bytes from file
		self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
		self.read_cursor = start
	def seek_file(self, position):
		self.read_cursor = position
	def close_file(self):
		self.input.close()

	def read_string(self):
		# Strings are encoded depending on length:
		# 0 to 252 :	1-byte-length followed by bytes (if any)
		# 253 to 65,535 : byte'253' 2-byte-length followed by bytes
		# 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
		# ... and the Bitcoin client is coded to understand:
		# greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
		# ... but I don't think it actually handles any strings that big.
		if self.input is None:
			raise SerializationError("call write(bytes) before trying to deserialize")

		try:
			length = self.read_compact_size()
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return self.read_bytes(length)

	def write_string(self, string):
		# Length-encoded as with read-string
		self.write_compact_size(len(string))
		self.write(string)

	def read_bytes(self, length):
		try:
			result = self.input[self.read_cursor:self.read_cursor+length]
			self.read_cursor += length
			return result
		except IndexError:
			raise SerializationError("attempt to read past end of buffer")

		return ''

	def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
	def read_int16(self): return self._read_num('<h')
	def read_uint16(self): return self._read_num('<H')
	def read_int32(self): return self._read_num('<i')
	def read_uint32(self): return self._read_num('<I')
	def read_int64(self): return self._read_num('<q')
	def read_uint64(self): return self._read_num('<Q')

	def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
	def write_int16(self, val): return self._write_num('<h', val)
	def write_uint16(self, val): return self._write_num('<H', val)
	def write_int32(self, val): return self._write_num('<i', val)
	def write_uint32(self, val): return self._write_num('<I', val)
	def write_int64(self, val): return self._write_num('<q', val)
	def write_uint64(self, val): return self._write_num('<Q', val)

	def read_compact_size(self):
		size = ord(self.input[self.read_cursor])
		self.read_cursor += 1
		if size == 253:
			size = self._read_num('<H')
		elif size == 254:
			size = self._read_num('<I')
		elif size == 255:
			size = self._read_num('<Q')
		return size

	def write_compact_size(self, size):
		if size < 0:
			raise SerializationError("attempt to write size < 0")
		elif size < 253:
			 self.write(chr(size))
		elif size < 2**16:
			self.write('\xfd')
			self._write_num('<H', size)
		elif size < 2**32:
			self.write('\xfe')
			self._write_num('<I', size)
		elif size < 2**64:
			self.write('\xff')
			self._write_num('<Q', size)

	def _read_num(self, format):
		(i,) = struct.unpack_from(format, self.input, self.read_cursor)
		self.read_cursor += struct.calcsize(format)
		return i

	def _write_num(self, format, num):
		s = struct.pack(format, num)
		self.write(s)

def open_wallet(db_env, writable=False):
	db = DB(db_env)
	flags = DB_THREAD | (DB_CREATE if writable else DB_RDONLY)
	try:
		r = db.open("wallet.dat", "main", DB_BTREE, flags)
	except DBError:
		r = True

	if r is not None:
		logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
		sys.exit(1)
	
	return db

def parse_wallet(db, item_callback):
	kds = BCDataStream()
	vds = BCDataStream()

	for (key, value) in db.items():
		d = { }

		kds.clear(); kds.write(key)
		vds.clear(); vds.write(value)

		type = kds.read_string()

		d["__key__"] = key
		d["__value__"] = value
		d["__type__"] = type

		try:
			if type == "tx":
				d["tx_id"] = kds.read_bytes(32)
        		#d.update(parse_WalletTx(vds))
			elif type == "name":
				d['hash'] = kds.read_string()
				d['name'] = vds.read_string()
			elif type == "version":
				d['version'] = vds.read_uint32()
			elif type == "setting":
				d['setting'] = kds.read_string()
				d['value'] = parse_setting(d['setting'], vds)
			elif type == "key":
				d['public_key'] = kds.read_bytes(kds.read_compact_size())
				d['private_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "wkey":
				d['public_key'] = kds.read_bytes(kds.read_compact_size())
				d['private_key'] = vds.read_bytes(vds.read_compact_size())
				d['created'] = vds.read_int64()
				d['expires'] = vds.read_int64()
				d['comment'] = vds.read_string()
			elif type == "defaultkey":
				d['key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "pool":
				d['n'] = kds.read_int64()
				d['nVersion'] = vds.read_int32()
				d['nTime'] = vds.read_int64()
				d['public_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "acc":
				d['account'] = kds.read_string()
				d['nVersion'] = vds.read_int32()
				d['public_key'] = vds.read_bytes(vds.read_compact_size())
			elif type == "acentry":
				d['account'] = kds.read_string()
				d['n'] = kds.read_uint64()
				d['nVersion'] = vds.read_int32()
				d['nCreditDebit'] = vds.read_int64()
				d['nTime'] = vds.read_int64()
				d['otherAccount'] = vds.read_string()
				d['comment'] = vds.read_string()
			
			item_callback(type, d)

		except Exception, e:
			traceback.print_exc()
			print("ERROR parsing wallet.dat, type %s" % type)
			print("key data in hex: %s"%key.encode('hex_codec'))
			print("value data in hex: %s"%value.encode('hex_codec'))
			sys.exit(1)
	
def update_wallet(db, type, data):
	"""Write a single item to the wallet.
	db must be open with writable=True.
	type and data are the type code and data dictionary as parse_wallet would
	give to item_callback.
	data's __key__, __value__ and __type__ are ignored; only the primary data
	fields are used.
	"""
	d = data
	kds = BCDataStream()
	vds = BCDataStream()

	# Write the type code to the key
	kds.write_string(type)
	vds.write("")						 # Ensure there is something

	try:
		if type == "tx":
			raise NotImplementedError("Writing items of type 'tx'")
			kds.write(d['tx_id'])
			#d.update(parse_WalletTx(vds))
		elif type == "name":
			kds.write_string(d['hash'])
			vds.write_string(d['name'])
		elif type == "version":
			vds.write_uint32(d['version'])
		elif type == "setting":
			raise NotImplementedError("Writing items of type 'setting'")
			kds.write_string(d['setting'])
			#d['value'] = parse_setting(d['setting'], vds)
		elif type == "key":
			kds.write_string(d['public_key'])
			vds.write_string(d['private_key'])
		elif type == "wkey":
			kds.write_string(d['public_key'])
			vds.write_string(d['private_key'])
			vds.write_int64(d['created'])
			vds.write_int64(d['expires'])
			vds.write_string(d['comment'])
		elif type == "defaultkey":
			vds.write_string(d['key'])
		elif type == "pool":
			kds.write_int64(d['n'])
			vds.write_int32(d['nVersion'])
			vds.write_int64(d['nTime'])
			vds.write_string(d['public_key'])
		elif type == "acc":
			kds.write_string(d['account'])
			vds.write_int32(d['nVersion'])
			vds.write_string(d['public_key'])
		elif type == "acentry":
			kds.write_string(d['account'])
			kds.write_uint64(d['n'])
			vds.write_int32(d['nVersion'])
			vds.write_int64(d['nCreditDebit'])
			vds.write_int64(d['nTime'])
			vds.write_string(d['otherAccount'])
			vds.write_string(d['comment'])
		else:
			print "Unknown key type: "+type

		# Write the key/value pair to the database
		db.put(kds.input, vds.input)

	except Exception, e:
		print("ERROR writing to wallet.dat, type %s"%type)
		print("data dictionary: %r"%data)
		traceback.print_exc()

def rewrite_wallet(db_env, destFileName, pre_put_callback=None):
	db = open_wallet(db_env)

	db_out = DB(db_env)
	try:
		r = db_out.open(destFileName, "main", DB_BTREE, DB_CREATE)
	except DBError:
		r = True

	if r is not None:
		logging.error("Couldn't open %s."%destFileName)
		sys.exit(1)

	def item_callback(type, d):
		if (pre_put_callback is None or pre_put_callback(type, d)):
			db_out.put(d["__key__"], d["__value__"])

	parse_wallet(db, item_callback)
	db_out.close()
	db.close()

def read_wallet(json_db, db_env, print_wallet, print_wallet_transactions, transaction_filter):
	db = open_wallet(db_env)

	json_db['keys'] = []
	json_db['pool'] = []
	json_db['names'] = {}

	def item_callback(type, d):

		if type == "name":
			json_db['names'][d['hash']] = d['name']

		elif type == "version":
			json_db['version'] = d['version']

		elif type == "setting":
			if not json_db.has_key('settings'): json_db['settings'] = {}
			json_db["settings"][d['setting']] = d['value']

		elif type == "defaultkey":
			json_db['defaultkey'] = public_key_to_bc_address(d['key'])

		elif type == "key":
			addr = public_key_to_bc_address(d['public_key'])
			sec = SecretToASecret(d['private_key'])
			private_keys.append(sec)
			json_db['keys'].append({'addr' : addr, 'sec' : sec})

		elif type == "wkey":
			if not json_db.has_key('wkey'): json_db['wkey'] = []
			json_db['wkey']['created'] = d['created']

		elif type == "pool":
			json_db['pool'].append( {'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']), 'nTime' : d['nTime'] } )

		elif type == "acc":
			json_db['acc'] = d['account']
			print("Account %s (current key: %s)"%(d['account'], public_key_to_bc_address(d['public_key'])))

		elif type == "acentry":
			json_db['acentry'] = (d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment'])

		else:
			json_db[type] = 'unsupported'


	parse_wallet(db, item_callback)

	db.close()

	for k in json_db['keys']:
		addr = k['addr']
		if (addr in json_db['names'].keys()):
			k["label"] = json_db['names'][addr]
		else:
			k["reserve"] = 1
	
	del(json_db['pool'])
	del(json_db['names'])

from optparse import OptionParser

def main():
	parser = OptionParser(usage="%prog [options]", version="%prog 1.0")

	parser.add_option("--dumpwallet", dest="dump", action="store_true",
		help="dump wallet in json format")

	parser.add_option("--importprivkey", dest="key", 
		help="import private key from vanitygen")

	parser.add_option("--datadir", dest="datadir", 
		help="wallet directory (defaults to bitcoin default)")

	(options, args) = parser.parse_args()

	if options.dump is None and options.key is None:
		print "A mandatory option is missing\n"
		parser.print_help()
		exit(0)

	if options.datadir is None:
		db_dir = determine_db_dir()
	else:
		db_dir = options.datadir

	db_env = create_env(db_dir)

	read_wallet(json_db, db_env, True, True, "")

	if options.dump:		
		print json.dumps(json_db, sort_keys=True, indent=4)

	elif options.key:
		if (options.key not in private_keys):
			db = open_wallet(db_env, writable=True)

			if importprivkey(db, options.key):
				print "Imported successfully"
			else:
				print "Bad private key"

			db.close()
		else:
			print "Already exists"

if __name__ == '__main__':
	main()
