#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Copyright © 2013 by its contributors. See AUTHORS for details.
#
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#

from base64 import standard_b64encode, standard_b64decode
import calendar
from datetime import datetime, timedelta
import numbers
import operator
import six
import sys

# ===----------------------------------------------------------------------===

from bitcoin.address import *
from bitcoin.crypto import *
from bitcoin.base58 import *
from bitcoin.mixins import *
from bitcoin.script import *
from bitcoin.serialize import *
from bitcoin.tools import *

# ===----------------------------------------------------------------------===

# https://bugs.launchpad.net/pycrypto/+bug/328027

from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Util.number import GCD, ceil_div, long_to_bytes, bytes_to_long
from Crypto.Util.strxor import strxor

def make_mgf1(hash):
    """Make an MFG1 function using the given hash function.

    Given a hash function implementing the standard hashlib function interface,
    this function returns a Mask Generation Function using that hash.
    """
    def mgf1(mgfSeed,maskLen):
        """Mask Generation Function based on a hash function.

        Given a seed byte string 'mgfSeed', this function will generate
        and return a mask byte string  of length 'maskLen' in a manner
        approximating a Random Oracle.

        The algorithm is from PKCS#1 version 2.1, appendix B.2.1.
        """
        hLen = hash().digest_size
        if maskLen > 2**32 * hLen:
            raise ValueError("mask too long")
        T = ""
        for counter in range(ceil_div(maskLen, hLen)):
            C = long_to_bytes(counter)
            C = ('\x00'*(4 - len(C))) + C
            assert len(C) == 4, "counter was too big"
            T += hash(mgfSeed + C).digest()
        assert len(T) >= maskLen, "generated mask was too short"
        return T[:maskLen]
    return mgf1
MGF1_HASH160 = make_mgf1(hash160)

class OAEP(object):
    """Class implementing OAEP encoding/decoding.

    This class can be used to encode/decode byte strings using the
    Optimal Asymmetric Encryption Padding Scheme.  It requires a source
    of random bytes, a hash function and a mask generation function.
    By default bitcoin's hash160 is used as the hash function, and
    MGF1-HASH160 is used as the mask generation function.

    The method 'encode' will encode a byte string using this padding
    scheme, and the complimentary method 'decode' will decode it.

    The algorithms are from PKCS#1 version 2.1, section 7.1
    """
    def __init__(self,randbytes,hash=hash160,mgf=MGF1_HASH160):
        self.randbytes = randbytes
        self.hash = hash
        self.mgf = mgf

    def encode(self,k,M,L=""):
        """Encode a message using OAEP.

        This method encodes a byte string 'M' using Optimal Asymmetric
        Encryption Padding.  The argument 'k' must be the size of the
        private key modulus in bytes.  If specified, 'L' is a label
        for the encoding.
        """
        # Calculate label hash, unless it is too long
        if L:
            limit = getattr(self.hash,"input_limit",None)
            if limit and len(L) > limit:
                raise ValueError("label too long")
        lHash = self.hash(L).digest()
        # Check length of message against size of key modulus
        mLen = len(M)
        hLen = len(lHash)
        if mLen > k - 2*hLen - 2:
            raise ValueError("message too long")
        # Perform the encoding
        PS = "\x00" * (k - mLen - 2*hLen - 2)
        DB = lHash + PS + "\x01" + M
        assert len(DB) == k - hLen - 1, "DB length is incorrect"
        seed = self.randbytes(hLen)
        dbMask = self.mgf(seed,k - hLen - 1)
        maskedDB = strxor(DB,dbMask)
        seedMask = self.mgf(maskedDB,hLen)
        maskedSeed = strxor(seed,seedMask)
        return "\x00" + maskedSeed + maskedDB

    def decode(self,k,EM,L=""):
        """Decode a message using OAEP.

        This method decodes a byte string 'EM' using Optimal Asymmetric
        Encryption Padding.  The argument 'k' must be the size of the
        private key modulus in bytes.  If specified, 'L' is the label
        used for the encoding.
        """
        # Generate label hash, for sanity checking
        lHash = self.hash(L).digest()
        hLen = len(lHash)
        # Split the encoded message
        Y = EM[0]
        maskedSeed = EM[1:hLen+1]
        maskedDB = EM[hLen+1:]
        # Perform the decoding
        seedMask = self.mgf(maskedDB,hLen)
        seed = strxor(maskedSeed,seedMask)
        dbMask = self.mgf(seed,k - hLen - 1)
        DB = strxor(maskedDB,dbMask)
        # Split the DB string
        lHash1 = DB[:hLen]
        x01pos = hLen
        while x01pos < len(DB) and DB[x01pos] != "\x01":
            x01pos += 1
        PS = DB[hLen:x01pos]
        M = DB[x01pos+1:]
        # All sanity-checking done at end, to avoid timing attacks
        valid = True
        if x01pos == len(DB):  # No \x01 byte
            valid = False
        if lHash1 != lHash:    # Mismatched label hash
            valid = False
        if Y != "\x00":        # Invalid leading byte
            valid = False
        if not valid:
            raise ValueError("decryption error")
        return M

def test_oaep():
    """Run through the OAEP encode/decode for lots of random values."""
    from os import urandom
    p = OAEP(urandom)
    for k in xrange(45,300):
        for i in xrange(0,1000):
            b = i % (k - 2*20 - 3)  # message length
            if b == 0:
                j = -1
            else:
                j = i % b           # byte to corrupt
            print "test %s:%s (%s bytes, corrupt at %s)" % (k,i,b,j)
            msg = urandom(b)
            pmsg = p.encode(k,msg)
            #  Test that padding actually does something
            assert msg != pmsg, "padded message was just the message"
            #  Test that padding is removed correctly
            assert p.decode(k,pmsg) == msg, "message was not decoded properly"
            #  Test that corrupted padding gives an error
            try:
                if b == 0: raise ValueError
                newb = urandom(1)
                while newb == pmsg[j]:
                    newb = urandom(1)
                pmsg2 = pmsg[:j] + newb + pmsg[j+1:]
                p.decode(k,pmsg2)
            except ValueError:
                pass
            else:
                raise AssertionError("corrupted padding was still decoded")

# ===----------------------------------------------------------------------===

# SQLAlchemy object-relational mapper
from sqlalchemy import *

class LittleEndian(TypeDecorator):
    impl = LargeBinary

    def __init__(self, length=None, *args, **kwargs):
        super(LittleEndian, self).__init__(length, *args, **kwargs)

    def process_bind_param(self, value, dialect):
        return serialize_leint(value, self.impl.length)
    def process_result_value(self, value, dialect):
        return deserialize_leint(StringIO(value), len(value))
    def copy(self):
        return self.__class__(self.impl.length)

class Hash160(LittleEndian):
    def __init__(self, length=20, *args, **kwargs):
        super(Hash160, self).__init__(length, *args, **kwargs)

class Hash256(LittleEndian):
    def __init__(self, length=32, *args, **kwargs):
        super(Hash256, self).__init__(length, *args, **kwargs)

class BigEndian(TypeDecorator):
    impl = LargeBinary

    def __init__(self, length=None, *args, **kwargs):
        super(BigEndian, self).__init__(length, *args, **kwargs)

    def process_bind_param(self, value, dialect):
        return serialize_beint(value, self.impl.length)
    def process_result_value(self, value, dialect):
        return deserialize_beint(StringIO(value), len(value))
    def copy(self):
        return self.__class__(self.impl.length)

class RsaKey(TypeDecorator):
    impl = LargeBinary

    def __init__(self, length=None, *args, **kwargs):
        super(RsaKey, self).__init__(length, *args, **kwargs)

    def process_bind_param(self, value, dialect):
        return value.exportKey('DER')
    def process_result_value(self, value, dialect):
        return RSA.importKey(value)
    def copy(self):
        return self.__class__(self.impl.length)

class EcdsaCompactSignature(TypeDecorator):
    impl = LargeBinary

    def __init__(self, length=65, *args, **kwargs):
        super(EcdsaCompactSignature, self).__init__(length, *args, **kwargs)

    def process_bind_param(self, value, dialect):
        return value.serialize()
    def process_result_value(self, value, dialect):
        return CompactSignature.deserialize(StringIO(value))
    def copy(self):
        return self.__class__(self.impl.length)

class BitcoinScript(TypeDecorator):
    impl = LargeBinary

    def process_bind_param(self, value, dialect):
        return deserialize_varchar(StringIO(value.serialize()))
    def process_result_value(self, value, dialect):
        return Script.deserialize(StringIO(serialize_varchar(value)))
    def copy(self):
        return self.__class__(self.impl.length)

class UNIXDateTime(TypeDecorator):
    impl = DateTime

    def __init__(self, *args, **kwargs):
        super(UNIXDateTime, self).__init__(*args, **kwargs)
    def process_bind_param(self, value, dialect):
        if isinstance(value, numbers.Integral):
            value = datetime.fromtimestamp(value)
        return value
    def copy(self):
        return self.__class__(self.impl.timezone)

class BlockTime(TypeDecorator):
    impl = DateTime

    from bitcoin.defaults import LOCKTIME_THRESHOLD as THRESHOLD_UNIXTIME
    THRESHOLD_DATETIME = datetime.utcfromtimestamp(THRESHOLD_UNIXTIME)

    def __init__(self, *args, **kwargs):
        super(BlockTime, self).__init__(*args, **kwargs)

    def process_bind_param(self, value, dialect):
        if isinstance(value, datetime):
            if value < self.THRESHOLD_DATETIME:
                raise ValidationError(u"unixtime below lock-time threshold")
            else:
                return value
        if isinstance(value, numbers.Integral):
            if value < self.THRESHOLD_UNIXTIME:
                return datetime.utcfromtimestamp(value)
            else:
                raise ValidationError(u"block height above lock-time threshold")
        raise ValidationError(u"unexpected data type: %s" % repr(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value < self.THRESHOLD_DATETIME:
            return calendar.timegm(value.utctimetuple())
        return value

    def copy(self):
        return self.__class__(self.impl.timezone)

# SQLAlchemy ORM event registration
from sqlalchemy import event, orm

@event.listens_for(orm.Session, 'before_flush')
def lazy_defaults(session, flush_context, instances):
    "Sets default values that are left unspecified by the application."
    for target in session.new.union(session.dirty):
        if hasattr(target, '__lazy_slots__'):
            # This code may look like it does nothing, but in fact we are using
            # properties to lazily generate values for some columns, so calling
            # `getattr()` evaluates those lazy expressions. This is slightly
            # kludgy.. but necessary as SQLAlchemy never calls `getattr()` before
            # passing the field values to the database layer.
            for attr in target.__lazy_slots__:
                getattr(target, attr)

from sqlalchemy.ext.associationproxy import association_proxy
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.ext.orderinglist import ordering_list

Base = declarative_base()

from bitcoin.mixins import HashableMixin
class HybridHashableMixin(HashableMixin):
    hash = hybrid_property(HashableMixin.hash.fget,
                           HashableMixin.hash.fset,
                           HashableMixin.hash.fdel,
                           lambda cls:cls._hash)

# ===----------------------------------------------------------------------===

from bitcoin import core

class Output(core.Output, Base):
    __tablename__ = 'output'
    __table_args__ = (
        UniqueConstraint('hash', 'index',
            name = '__'.join([__tablename__,'hash','index','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    # Identification of the asset type of the output. For the host currency
    # (e.g. Bitcoin), this is the hash160 of the genesis block header.
    assetid = Column(Hash160, nullable=False)

    # Identification of the transaction containing this output, and
    # the index within its output list.
    hash = Column(Hash256, nullable=False)
    index = Column(SmallInteger, nullable=False)

    # Subject to the constraint: 0 <= amount <= 2^53 - 1
    # NOTE: See the Freimarkets whitepaper for an explanation of the
    #   constant 2^53 - 1.
    amount = Column(BigInteger,
        CheckConstraint('0 <= amount and amount <= 9007199254740991'),
        nullable = False)

    # What the Satoshi client calls scriptPubKey:
    contract = Column(BitcoinScript, nullable=False)

    # Coin in rpc wallet:
    is_mine = Column(Boolean, nullable=False)
    # Coin is known to be spent as-of current block:
    is_spent = Column(Boolean, nullable=False)

# ===----------------------------------------------------------------------===

# Phase 0: Offer
#
# In the initial stage of operation, participating nodes broadcast offers to
# participate in a CoinJoin transaction. Such an offer includes the provided
# inputs, required outputs, a verifying key for blinded signature operations,
# and various meta-restrictions such as expiry and transaction size.
#
# The offer is signed by the provided inputs so as to provide proof of
# ownership.
#
# For a given offer, some outputs are explicit (change outputs), and some
# are blinded (mix outputs). A blinding key for the entire offer, and a factor
# for each blinded output is generated and stored for future use.

from collections import namedtuple
OfferParameters = namedtuple('OfferParameters',
    'min_duration max_duration max_sigops bits exponent'.split())

class Offer(SerializableMixin, HashableMixin, Base):
    __tablename__ = 'offer'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    # Offer restrictions:
    expiry       = Column(DateTime, nullable=False)
    min_duration = Column(Interval, nullable=False)
    max_duration = Column(Interval, nullable=False)
    max_sigops   = Column(SmallInteger, nullable=False)
    max_outputs  = Column(SmallInteger, nullable=False)

    # The RSA key and denormalized parameters:
    bits     = Column(SmallInteger, nullable=False)
    exponent = Column(Integer, nullable=False)

    verifying_key = Column(RsaKey, nullable=False)

    # Provided inputs:
    inputs = orm.relationship(lambda: OfferInput,
        collection_class = ordering_list('position'),
        order_by         = lambda: OfferInput.position)
    outpoints = association_proxy('inputs', 'outpoint',
        creator = lambda o:OfferInput(outpoint=o))

    # Provided outputs:
    outputs = orm.relationship(lambda: OfferOutput,
        collection_class = ordering_list('position'),
        order_by         = lambda: OfferOutput.position)

    # Authorizing signatures:
    signature_set = orm.relationship(lambda: OfferSignature,
        collection_class = ordering_list('position'),
        order_by         = lambda: OfferSignature.position)
    signatures = association_proxy('signature_set', 'signature',
        creator = lambda sig:OfferSignature(signature=sig))

    # Secret blinding factors and private key:
    secret = orm.relationship(lambda: OfferSecret, uselist=False)

class OfferInput(Base):
    __tablename__ = 'offer_input'
    __table_args__ = (
        UniqueConstraint('offer_id', 'position',
            name = '__'.join([__tablename__,'offer_id','position','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)
    offer_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    offer = orm.relationship(lambda: Offer)
    position = Column(SmallInteger, nullable=False)

    # A coin provided as input to the join offer:
    outpoint_id = Column(Integer, ForeignKey('output.id'), nullable=False)
    outpoint = orm.relationship(lambda: Output)

class OfferOutput(Base):
    __tablename__ = 'offer_output'
    __table_args__ = (
        UniqueConstraint('offer_id', 'position',
            name = '__'.join([__tablename__,'offer_id','position','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)
    offer_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    offer = orm.relationship(lambda: Offer)
    position = Column(SmallInteger, nullable=False)

    # The asset identifier tag (hash160 of the genesis block for the host
    # currency):
    assetid = Column(Hash160, nullable=False)

    # The amount of coins to place in the output (measured in kria):
    amount = Column(BigInteger,
        CheckConstraint('0 <= amount and amount <= 9007199254740991'),
        nullable = False)

    # Polymorphic type: record will be `OfferOutputExplicit` if blinded
    # is False, `OfferOutputBlinded` if it is True.
    blinded = Column(Boolean, nullable=False)
    __mapper_args__ = {
        'polymorphic_on': blinded,
    }

class OfferOutputExplicit(OfferOutput):
    __tablename__ = 'offer_output_explicit'
    __mapper_args__ = {
        'polymorphic_identity': False}
    id = Column(Integer,
        ForeignKey('offer_output.id'),
        primary_key = True)
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('blinded', False)
        super(OfferOutputExplicit, self).__init__(*args, **kwargs)

    # The scriptPubKey for the output:
    contract = Column(BitcoinScript, nullable=False)

class OfferOutputBlinded(OfferOutput):
    __tablename__ = 'offer_output_blinded'
    __mapper_args__ = {
        'polymorphic_identity': True}
    id = Column(Integer,
        ForeignKey('offer_output.id'),
        primary_key = True)
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('blinded', True)
        super(OfferOutputBlinded, self).__init__(*args, **kwargs)

class OfferSecret(Base):
    __tablename__ = 'offer_secret'
    id = Column(Integer,
        ForeignKey('offer.id'),
        primary_key = True)
    offer = orm.relationship(lambda: Offer)

    signing_key = Column(RsaKey, nullable=False)

    unblinded_outputs = orm.relationship(lambda: UnblindedOutput,
        collection_class = ordering_list('position'),
        order_by         = lambda: UnblindedOutput.position)

class UnblindedOutput(Base):
    __tablename__ = 'unblinded_output'
    __table_args__ = (
        UniqueConstraint('offer_secret_id', 'position',
            name = '__'.join([__tablename__,'offer_secret_id','position','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    offer_secret_id = Column(Integer, ForeignKey('offer_secret.id'), nullable=False)
    offer_secret = orm.relationship(lambda: OfferSecret)

    position = Column(SmallInteger, nullable=False)

    contract = Column(BitcoinScript, nullable=False)

    blinding_factor = Column(BigEndian, nullable=False)

class OfferSignature(Base):
    __tablename__ = 'offer_signature'
    __table_args__ = (
        UniqueConstraint('offer_id', 'position',
            name = '__'.join([__tablename__,'offer_id','position','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    offer_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    offer = orm.relationship(lambda: Offer)

    position = Column(SmallInteger, nullable=False)

    signature = Column(EcdsaCompactSignature, nullable=False)

# ===----------------------------------------------------------------------===

# Phase 1: Proposal
#
# Once a set of acceptable offers is observed, anyone can combine them into an
# integration proposal. This request is mostly a marker establishing the start
# of the CoinJoin transaction negotiation protocol.
#
# The ordering of the offers determines the ordering of the inputs of the final
# transaction.

class Join(SerializableMixin, HashableMixin, Base):
    __tablename__ = 'join'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    expiry = Column(DateTime, nullable=False)

    version = Column(SmallInteger, nullable=False)
    @orm.validates('version')
    def version_range(self, key, version):
        assert version in (1,)
        return version

    offers_set = orm.relationship(lambda: JoinOffer,
        collection_class = ordering_list('position'),
        order_by         = lambda: JoinOffer.position)
    offers = association_proxy('offers_set', 'offer',
        creator = lambda offer:JoinOffer(offer=offer))

    def serialize(self):
        return b''.join([])
    @classmethod
    def deserialize(cls, file_):
        pass # FIXME: implement

class JoinOffer(Base):
    __tablename__ = 'join_offer'
    __table_args__ = (
        UniqueConstraint('join_id', 'position',
            name = '__'.join([__tablename__,'join_id','position','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    join_id = Column(Integer, ForeignKey('join.id'), nullable=False)
    join = orm.relationship(lambda: Join)

    position = Column(SmallInteger, nullable=False)

    offer_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    offer = orm.relationship(lambda: Offer)

# ===----------------------------------------------------------------------===

# Phase 2: blinding
#
# The participants affirmatively respond to a proposed join by blinding their
# outputs to the key of each of the participants, including themselves (M*N
# signatures, for N participants and M outputs).

class BlindedJoin(Base):
    __tablename__ = 'blinded_join'
    __table_args__ = (
        UniqueConstraint('owner_id', 'signer_id',
            name = '__'.join([__tablename__,'owner_id','signer_id','unique'])),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    owner_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    owner = orm.relationship(lambda: Offer,
        primaryjoin = 'Offer.id == BlindedJoin.owner_id')

    signer_id = Column(Integer, ForeignKey('offer.id'), nullable=False)
    signer = orm.relationship(lambda: Offer,
        primaryjoin = 'Offer.id == BlindedJoin.signer_id')

    outputs = orm.relationship(lambda: BlindedJoinOutput,
        order_by = lambda: BlindedJoinOutput.token)
    tokens = association_proxy('outputs', 'token',
        creator = lambda token:BlindedJoinOutput(token=token))

class BlindedJoinOutput(Base):
    __tablename__ = 'blinded_join_output'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    blinded_join_id = Column(Integer, ForeignKey('blinded_join.id'), nullable=False)
    blinded_join = orm.relationship(lambda: BlindedJoin)

    token = Column(BigEndian, nullable=False)

# ===----------------------------------------------------------------------===

# Phase 3: request
#
# Once all participants have received a full set of blinded tokens, then any
# one participant is able to construct a request object representing a random
# shuffle of blind-signed outputs.

class Request(Base):
    __tablename__ = 'request'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    join_offer_id = Column(Integer, ForeignKey('join.id'), nullable=False)
    join_offer = orm.relationship(lambda: Join)

class RequestOutput(Base):
    __tablename__ = 'request_output'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    request_id = Column(Integer, ForeignKey('request.id'), nullable=False)
    request = orm.relationship(lambda: Request)

    position = Column(SmallInteger, nullable=False)

    assetid = Column(Hash160, nullable=False)

    amount = Column(BigInteger,
        CheckConstraint('0 <= amount and amount <= 9007199254740991'),
        nullable = False)

    blinded = Column(Boolean, nullable=False)
    __mapper_args__ = {
        'polymorphic_on': blinded,
    }

class RequestOutputExplicit(RequestOutput):
    __tablename__ = 'request_output_explicit'
    __mapper_args__ = {
        'polymorphic_identity': False}
    id = Column(Integer,
        ForeignKey('request_output.id'),
        primary_key = True)

    contract = Column(BitcoinScript, nullable=False)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('blinded', False)
        super(RequestOutputExplicit, self).__init__(*args, **kwargs)

class RequestOutputBlinded(RequestOutput):
    __tablename__ = 'request_output_blinded'
    __mapper_args__ = {
        'polymorphic_identity': True}
    id = Column(Integer,
        ForeignKey('request_output.id'),
        primary_key = True)

    blinded_signature = Column(BigEndian, nullable=False)

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('blinded', True)
        super(RequestOutputBlinded, self).__init__(*args, **kwargs)

# ===----------------------------------------------------------------------===

# Phase 4: revelation
#
# For each output owned, a separate revelation is constructed, revealing the
# contract for that output and unblinding its corresponding signature.

class Revelation(SerializableMixin, HashableMixin, Base):
    __tablename__ = 'revelation'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    request_id = Column(Integer, ForeignKey('request.id'), nullable=False)
    request = orm.relationship(lambda: Request)

    position = Column(SmallInteger, nullable=False)

    contract = Column(BitcoinScript, nullable=False)

    signature = Column(BigEndian, nullable=False)

# ===----------------------------------------------------------------------===

# Phase 5: endorsement
#
# Once all unblinded signatures are received, the signatures match, and the
# output contracts are as expected (for the ones we care about, at least),
# then the necessary information is available to sign the resulting
# transaction.

class Endorsement(SerializableMixin, HashableMixin, Base):
    __tablename__ = 'endorsement'
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    request_id = Column(Integer, ForeignKey('request.id'), nullable=False)
    request = orm.relationship(lambda: Request)

    position = Column(SmallInteger, nullable=False)

    endorsement = Column(BitcoinScript, nullable=False)

# ===----------------------------------------------------------------------===

engine = create_engine('sqlite:///coinjoin.sqlite', echo=False)

Base.metadata.create_all(engine)

from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)

# ===----------------------------------------------------------------------===

def hash_string_to_integer(string, size=32):
    return deserialize_hash(StringIO(string.decode('hex')[::-1]), size)

def hash_integer_to_string(integer, size=32):
    return serialize_hash(integer, size)[::-1].encode('hex')

def amount_decimal_to_int64(decimal):
    return int(decimal * 10**8)

def script_from_hex_string(string):
    return Script.deserialize(StringIO(serialize_varchar(string.decode('hex'))))

# ===----------------------------------------------------------------------===

def get_chain_id(rpc):
    genesis_block_hash_string = rpc.getblockhash(0)
    genesis_block_dict = rpc.getblock(genesis_block_hash_string)
    genesis_block = core.Block(
        version     = genesis_block_dict['version'],
        parent_hash = 0,
        merkle_hash = hash_string_to_integer(genesis_block_dict['merkleroot']),
        time        = genesis_block_dict['time'],
        bits        = int(u'0x' + genesis_block_dict['bits'], base=16),
        nonce       = genesis_block_dict['nonce'])
    assert (hash256(genesis_block.serialize()).intdigest() ==
            hash_string_to_integer(genesis_block_hash_string))
    return hash160(genesis_block.serialize()).intdigest()

# ===----------------------------------------------------------------------===

from collections import namedtuple
OutPoint = namedtuple('OutPoint', ('hash', 'index'))
Contract = namedtuple('Contract', ('amount', 'script'))

def sync_unspent_outputs(rpc, session):
    assetid = get_chain_id(rpc)

    unspent_outputs = dict()
    result = rpc.listunspent()
    for obj in result:
        outpoint = OutPoint(
            hash  = hash_string_to_integer(obj['txid']),
            index = obj['vout'])
        contract = Contract(
            amount = amount_decimal_to_int64(obj['amount']),
            script = script_from_hex_string(obj['scriptPubKey']))
        unspent_outputs[outpoint] = contract

    num_insert = 0
    num_update = 0
    num_delete = 0

    for outpoint,contract in six.iteritems(unspent_outputs):
        output = (session.query(Output)
                         .filter((Output.hash  == outpoint.hash) &
                                 (Output.index == outpoint.index))
                         .first())

        if output is not None:
            assert output.amount   == contract.amount
            assert output.contract == contract.script
            if output.is_mine is True and output.is_spent is False:
                continue
            print 'Update %064x:%d' % (outpoint.hash, outpoint.index)
            output.is_mine  = True
            output.is_spent = False
            num_update += 1

        else:
            print 'Insert %064x:%d' % (outpoint.hash, outpoint.index)
            output = Output(
                assetid  = assetid,
                hash     = outpoint.hash,
                index    = outpoint.index,
                amount   = contract.amount,
                contract = contract.script,
                is_mine  = True,
                is_spent = False)
            num_insert += 1

        session.add(output)
    session.flush()

    outputs = (session.query(Output)
                      .filter((Output.is_mine  == True) &
                              (Output.is_spent == False)))
    if outputs.count() != len(unspent_outputs):
        for output in outputs.all():
            outpoint = OutPoint(hash=output.hash, index=output.index)
            if outpoint not in unspent_outputs:
                print 'Delete %064x:%d' % (outpoint.hash, outpoint.index)
                output.is_spent = True
                num_delete += 1
                session.add(output)

    session.commit()

    print 'Added % 5d previously unknown outputs' % num_insert
    print 'Reorg\'d % 3d spent outputs as unspent'  % num_update
    print 'Marked % 4d existing outputs as spent' % num_delete

# ===----------------------------------------------------------------------===

def _pad_message(key, message):
    # REVIEW: I need a professional cryptographer to look at this. I have
    #   removed the non-determinism so as to prevent having to record and
    #   later send the padded when the contract is revealed.. Does it matter
    #   in this particular applicaiton if the padding is deterministic instead
    #   of random?
    oaep = OAEP(randbytes=lambda x:'\x00'*x)

    padded_message = oaep.encode(
        ceil_div(key.n.bit_length(), 256)*32,
        long_to_bytes(message))

    return bytes_to_long(padded_message)

def blind_message(blinding_key, blinding_factor, message):
    return blinding_key.blind(_pad_message(blinding_key, message), blinding_factor)

def sign_blinded_message(signing_key, blinded_message):
    # The second parameter, the random K value is not actually used by the
    # RSA digital signature algorithm. It can be replaced by a constant value,
    # but should we switch to a different asymmetric encryption system, it'll
    # have to go back to being a cryptographically secure random number.
    #k = random.randint(1, signing_key.n)
    k = None
    return signing_key.sign(blinded_message, k)[0]

def unblind_signature(blinding_key, blinding_factor, blinded_signature):
    return blinding_key.unblind(blinded_signature, blinding_factor)

def verify_signed_message(verifying_key, signature, message):
    return verifying_key.verify(_pad_message(verifying_key, message), (signature,None))

# ===----------------------------------------------------------------------===

import gflags
FLAGS = gflags.FLAGS

gflags.DEFINE_string('host', u"localhost",
    u"Hostname or network address of RPC server",
    short_name='h')

gflags.DEFINE_integer('port', 8332,
    u"Network port of RPC server",
    short_name='P')
gflags.RegisterValidator('port',
    lambda rpcport: 1 <= rpcport <= 65535,
    message=u"Valid TCP/IP port numbers must be positive integers from 1 to 65535.")

gflags.DEFINE_string('sslcert', None,
    u"File containing server's public key. If specified, the connection must "
    u"be encrypted and the server's SSL certificate match.")

gflags.DEFINE_string('sslciphers',
    u"TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH",
    u"Allowed SSL ciphers. See the OpenSSL documentation for syntax.")

gflags.DEFINE_string('username', None,
    u"Username for connection to RPC server",
    short_name='u')
gflags.MarkFlagAsRequired('username')

gflags.DEFINE_string('password', None,
    u"Username for connection to RPC server",
    short_name='p')
gflags.MarkFlagAsRequired('password')

gflags.DEFINE_integer('timeout', 15,
    u"Timeout for communication with RPC server, or zero to disable")
gflags.RegisterValidator('timeout',
    lambda timeout: 0 <= timeout,
    message=u"Valid timeout setting must be a positive number of seconds, or zero.")

gflags.DEFINE_boolean('testnet', False,
    u"Change bitcoin addresses to use testnet prefixes.")

if __name__ == '__main__':
    try:
        argv = FLAGS(sys.argv)
    except gflags.FlagsError, e:
        print '%s\n\nUsage %s ARGS \n%s' % (e, sys.argv[0], FLAGS)
        sys.exit(1)

    if FLAGS.testnet:
        class BitcoinTestnetAddress(BitcoinAddress):
            PUBKEY_HASH = 111
            SCRIPT_HASH = 196
        BitcoinAddress = BitcoinTestnetAddress

    else:
        print '%s is NOT ready for primetime; run with --testnet' % sys.argv[0]
        sys.exit(0)

    kwargs = {}
    kwargs['username'] = FLAGS.username
    kwargs['password'] = FLAGS.password
    kwargs['timeout'] = FLAGS.timeout
    from bitcoin.rpc import Proxy
    rpc = Proxy('http://%s:%d/' % (FLAGS.host, FLAGS.port), **kwargs)

    session = Session()

    sync_unspent_outputs(rpc, session)

    import IPython
    IPython.embed()

#
# End of File
#
