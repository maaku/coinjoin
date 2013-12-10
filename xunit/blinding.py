# -*- coding: utf-8 -*-

#
# Copyright © 2013 by its contributors. See AUTHORS for details.
#
# Distributed under the MIT/X11 software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.
#

from unittest2 import TestCase

from coinjoin import *
from Crypto.PublicKey import RSA

class TestBlinding(TestCase):
    def test_blind_long(self):
        signing_key = RSA.generate(1024)
        verifying_key = signing_key.publickey()
        blinding_factor = random.randint(1, signing_key.n)

        for exp in xrange(256):
            message = long(2 ** exp)
            blinded_message = blind_message(signing_key, blinding_factor, message)
            blinded_signature = sign_blinded_message(signing_key, blinded_message)
            signature = unblind_signature(signing_key, blinding_factor, blinded_signature)
            self.assertTrue(verify_signed_message(verifying_key, signature, message))
            self.assertFalse(verify_signed_message(verifying_key, signature, message+1))

#
# End of File
#
