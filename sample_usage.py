#!/usr/bin/env python3

from opentotp import OpenTOTP
from uuid import uuid4

otp = OpenTOTP(secret=uuid4().hex,
               alphabet="0123456789",
               otp_length=6,
               otp_change_interval=30,
               otp_drift=3)

otp_value = otp.generate()
result = otp.verify(otp_value)

print("------------------------------------------")
print(f"OTP: {otp_value}")
print(f"OTP verification status: {'SUCCESS' if result else 'FAILURE'}")
print("------------------------------------------")
