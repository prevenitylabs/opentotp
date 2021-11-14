import unittest

from time import sleep
from opentotp import OpenTOTP


class TestOpenTOTP(unittest.TestCase):
    TEST_SECRET = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    TEST_ALPHABET = "abdefhijkprstuvwxyzACEFHJKLMNPRTUVWXY3479"

    def test_create_object_OpenTOTP(self):
        self.assertIsNotNone(OpenTOTP())

    def test_create_object_OpenTOTP_kwargs(self):
        custom_secret = "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969"
        custom_alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        custom_otp_length = 12
        custom_otp_change_interval = 90
        custom_otp_drift = 5
        totp = OpenTOTP(secret=custom_secret,
                        alphabet=custom_alphabet,
                        otp_length=custom_otp_length,
                        otp_change_interval=custom_otp_change_interval,
                        otp_drift=custom_otp_drift)
        self.assertIsNotNone(totp)
        self.assertEqual(bytearray.fromhex(custom_secret), totp.secret)
        self.assertEqual(custom_alphabet.encode("utf-8"), totp.alphabet)
        self.assertEqual(custom_otp_length, totp.otp_length)
        self.assertEqual(custom_otp_change_interval, totp.otp_change_interval)
        self.assertEqual(custom_otp_drift, totp.otp_drift)

    def test_nonce_generate(self):
        nonce = OpenTOTP.generate_nonce()
        self.assertIsInstance(nonce, str)
        self.assertGreater(len(nonce), 1)

    def test_get_timestamp_current(self):
        timestamp = OpenTOTP()._get_base_timestamp()
        self.assertIsInstance(timestamp, int)
        self.assertGreater(timestamp, 1)

    def test_get_timestamp_range(self):
        timestamp = 1636734300
        expected_results = range(1636734150, 1636734480, 30)
        timestamp_range = OpenTOTP(otp_change_interval=30, otp_drift=5)._get_timestamps_range(timestamp=timestamp)
        self.assertEqual(11, len(timestamp_range))
        self.assertEqual(expected_results, timestamp_range)

    def test_encode_hash(self):
        hashed_value = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e".encode("utf-8")
        result = OpenTOTP(alphabet=self.TEST_ALPHABET)._encode_bytes(hashed_value)
        expected = "efxavadKPNdbVe9Uy43pkVXsxAUK3id3MdHsvzTveCiJVCfNLJFJMh7EywWAXsR9aCUCvHNPrL9FLU9Et3Jfiiv9jEvRHvFH"
        self.assertEqual(expected, result)

    def test_truncate_encoded_hash(self):
        hashed_value = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        expected = "a591a6d4"
        self.assertEqual(expected, OpenTOTP(otp_length=8)._truncate_encoded_string(hashed_value))

    def test_nonce(self):
        totp = OpenTOTP(secret=self.TEST_SECRET,
                        alphabet=self.TEST_ALPHABET,
                        otp_length=8,
                        otp_change_interval=30,
                        otp_drift=0)
        expected_results = {
            '33903c93d12f4bd9bd199c18d1241032': [1636721070, "iFyhpbCJ", True],
            'b88066bc513f45d386af0fbcf13d9eab': [1636734270, "bAiVjwKW", True],
            '734166340a1d4250a7d0badcf57dd2ac': [1636734270, "xs9MHvti", False]
        }
        for nonce in expected_results:
            if expected_results[nonce][2]:
                self.assertEqual(expected_results[nonce][1],
                                 totp.generate(timestamp=expected_results[nonce][0], nonce=nonce))
            self.assertEqual(expected_results[nonce][2],
                             totp.verify(expected_results[nonce][1],
                                         timestamp=expected_results[nonce][0],
                                         nonce=nonce))

    def test_generate_OTP(self):
        expected_length = 32
        totp = OpenTOTP(otp_length=expected_length)
        self.assertEqual(expected_length, len(totp.generate()))
        self.assertEqual(expected_length, len(totp()))

    def test_generate_OTP_length(self):
        for length in range(1, 33, 1):
            self.assertEqual(length, len(OpenTOTP(otp_length=length).generate()))

    def test_generate_OTP_timestamp(self):
        totp = OpenTOTP(secret=self.TEST_SECRET,
                        alphabet=self.TEST_ALPHABET,
                        otp_length=8,
                        otp_change_interval=30,
                        otp_drift=0)
        self.assertEqual("rHWjpYHF", totp.generate(timestamp=1636720320))
        self.assertNotEqual("tE9xAMhJ", totp.generate(timestamp=1636720320))

    def test_verify_OTP_timestamp_current(self):
        totp = OpenTOTP(otp_change_interval=2, otp_drift=0)
        self.assertTrue(totp.verify(totp.generate()))
        totp.otp_change_interval = 1
        totp.otp_drift = 1
        otp_value = totp.generate()
        sleep(2)
        self.assertFalse(totp.verify(otp_value))

    def test_verify_OTP_timestamp(self):
        totp = OpenTOTP(otp_change_interval=2, otp_drift=0)
        timestamp = 1636721070
        self.assertTrue(totp.verify(totp.generate(timestamp=timestamp), timestamp=timestamp))
        self.assertFalse(totp.verify(totp.generate(timestamp=timestamp), timestamp=(timestamp + 10)))

    def test_verify_OTP_drift(self):
        totp = OpenTOTP(otp_change_interval=2, otp_drift=0)
        timestamp = 1000000000
        expected_results = {
            0: [False, False, False, True, False, False, False],
            1: [False, False, True, True, True, False, False],
            2: [False, True, True, True, True, True, False],
            3: [True, True, True, True, True, True, True]
        }
        for drift_value in expected_results:
            totp.otp_drift = drift_value
            simulated_drift = -3
            for expected_value in expected_results[drift_value]:
                simulated_timestamp = timestamp + (simulated_drift * totp.otp_change_interval)
                otp_value = totp.generate(timestamp=simulated_timestamp)
                verification_result = totp.verify(otp_value, timestamp)
                self.assertEqual(expected_value, verification_result,
                                 f"otp_drift={drift_value} does not work correctly at position [{simulated_drift}]")
                simulated_drift += 1


if __name__ == "__main__":
    unittest.main()
