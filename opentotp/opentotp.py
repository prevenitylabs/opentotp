import hmac

from base58 import b58encode
from datetime import datetime
from uuid import uuid4
from hashlib import sha256


class OpenTOTP:
    """
    OpenTOTP generates and verifies time-based one-time-passwords (TOTPs)
    """
    secret = "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
    alphabet = "abdefhijkprstuvwxyzACEFHJKLMNPRTUVWXY3479"
    otp_length = 8
    otp_change_interval = 30
    otp_drift = 1

    def __init__(self,
                 secret: str = None,
                 alphabet: str = None,
                 otp_length: int = None,
                 otp_change_interval: int = None,
                 otp_drift: int = None):
        """
        :param secret: Shared secret (preferable: random 64-characters long hex-string)
            ATTENTION: Default secret value is for DEMO purposes only and MUST NOT be used in a production environment!
        :param alphabet: Set of output characters used to generate OTP values
            Default value excludes misleading characters such as: lI1/co/O0/QD/qg/mn/S5/2Z/8B/G6
        :param otp_length: Default length of OTP generated. Must not exceed 32.
        :param otp_change_interval: Frequency of OTP change [in seconds]
        :param otp_drift: How many older/newer OTPs are accepted
        """
        self.secret = OpenTOTP._convert_to_secret(secret if secret is not None else self.secret)
        self.alphabet = (alphabet if alphabet is not None else self.alphabet).encode("utf-8")
        if otp_length is not None:
            self.otp_length = otp_length
        if otp_change_interval is not None:
            self.otp_change_interval = otp_change_interval
        if otp_drift is not None:
            self.otp_drift = otp_drift

    def _get_base_timestamp(self) -> int:
        """
        Get a current UTC Epoch timestamp rounded down to the nearest timestamp as per self.otp_change_interval

        :returns: Base timestamp for OTP
        """
        epoch_timestamp = int(datetime.utcnow().timestamp())
        base_timestamp = (epoch_timestamp // self.otp_change_interval) * self.otp_change_interval

        return base_timestamp

    def _get_timestamps_range(self, timestamp: int) -> range:
        """
        Get a set of timestamps that shell be deemed as accepted (as per self.otp_change_interval and self.otp_drift

        :param timestamp: Base timestamp to build a range from/to
        :returns: A range of valid timestamps
        """
        base_timestamp = (timestamp // self.otp_change_interval)
        start = (base_timestamp - self.otp_drift) * self.otp_change_interval
        end = (base_timestamp + self.otp_drift + 1) * self.otp_change_interval

        return range(start, end, self.otp_change_interval)

    def _encode_bytes(self,
                      input_bytes: bytes) -> str:
        """
        Encode bytes using Base58 algorithm and custom output alphabet

        :param input_bytes: Bytes to encode
        :returns: string encoded using custom alphabet"""

        return b58encode(input_bytes, self.alphabet).decode("utf-8")

    def _truncate_encoded_string(self,
                                 input_string: str) -> str:
        """
        Truncate string to a specific length

        :param input_string: Input string
        :returns: Truncated strings (as per self.otp_length)
        """
        # Default truncation method is trivial and not very secure, but should be sufficient for most of use cases
        # If more secure truncation is needed, then override this method with a custom one
        # One example of a more secure truncation method: split the digest into blocks, XOR them, and encode the output
        # Note, though, that regardless of the method, any truncation increase the chances of results collisions.
        # As a rule - the more lengthy OTP code is, the more security (and collisions resistance) it provides.

        return input_string[:self.otp_length]

    @staticmethod
    def _convert_to_secret(input_string: str) -> bytes:
        """
        Convert hex-string (or string) to set of bytes than can be used as a secret for the purpose of HMAC

        :param input_string: Hexadecimal 64-bytes long string or a regular string
        :returns: Array of bytes that represents input hex string, or sha256(input_string) for other strings
        """
        try:
            assert len(input_string) == 64, "String is not 64 characters long!"
            assert isinstance(int(input_string, 16), int), "String is not a hexadecimal string!"
        except (AssertionError, ValueError):
            return sha256(input_string.encode("utf-8")).digest()
        except TypeError as e:
            raise Exception(e)

        return bytearray.fromhex(input_string)

    @staticmethod
    def generate_nonce() -> str:
        """
        Generates random NONCE value

        :returns: Random NONCE
        """
        # Override this method if want to change the default mechanism to generate NONCE

        return uuid4().hex

    def generate(self,
                 timestamp: int = None,
                 nonce: str = None) -> str:
        """
        Generate OTP based on a current or provided UTC Epoch timestamp and (optionally) NONCE

        :param timestamp: Timestamp to use for the purpose of OTP generation
        :param nonce: Optional random value that can be used as a one-time mechanism (to prevent replay attacks)
        :returns: OTP value
        """
        if timestamp is None:
            timestamp = self._get_base_timestamp()
        elif timestamp < 0:
            raise ValueError("Timestamp must be a positive integer")
        if nonce is None:
            nonce = "NONE"
        key = self.secret
        message = "|".join([str(timestamp), nonce]).encode("utf-8")
        hmac_digest_bytes = hmac.digest(key, message, "sha256")
        encoded_hmac_digest = self._encode_bytes(hmac_digest_bytes)
        truncated_encoded_hmac = self._truncate_encoded_string(encoded_hmac_digest)

        return truncated_encoded_hmac

    def __call__(self, **kwargs) -> str:
        """
        Generate OTP based on a current or provided UTC Epoch timestamp and (optionally) NONCE
        """

        return self.generate(*kwargs)

    def verify(self,
               otp_to_verify: str,
               timestamp: int = None,
               nonce: str = None) -> bool:
        """
        Verify if OTP is valid considering OTP drift and OTP change interval

        :param otp_to_verify: One-time password to verify if it is correct
        :param timestamp: Timestamp used to generate OTP
        :param nonce: Optional random value that was used to generate OTP
        :returns: True if OTP is successfully verified, False otherwise
        """
        # Note that this method does not invalidate any OTPs already successfully verified.
        # It is the responsibility of the implementation program to mark successfully validated OTPs
        # as already used ones, to ensure one-time only use of an OTP.
        # Alternatively, the NONCE value can be used for that purpose.
        if timestamp is None:
            timestamp = self._get_base_timestamp()
        elif timestamp < 0:
            raise ValueError("Timestamp must be a positive integer")
        valid_timestamps = self._get_timestamps_range(timestamp)
        for t in valid_timestamps:
            calculated_otp = self.generate(timestamp=t, nonce=nonce)
            if otp_to_verify == calculated_otp:
                return True

        return False
