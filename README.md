# OpenTOTP

[OpenTOTP](https://github.com/prevenitylabs/opentotp) is yet another time-based, one-time passwords (OTPs) generator/verifier inspired by [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238).

It generates and validates OTPs based on:
1. Shared secret
2. Current UTC time

OpenTOTP uses *HMAC-SHA256* to generate OTPs, encodes them using any alphabet (predefined set of output characters) you may need, and truncates OTPs to the expected length.

To ensure generated passwords can be used one-time only, applications that use this package must either mark successfully verified OTPs as already used ones (and temporarily store them in a database until OTP expires) so used OTPs can be rejected, or can use optional, one-time *nonce* value while generating OTP.

As defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238), the OpenTOTP verification mechanism allows for an OTP drift so a specified number of older/newer OTP values are also accepted as valid ones. This helps to increase the chance of successful verification when the current UTC time on the client and server sides are slightly different.

Note that the *shared secret* value can be customized in any manner, effectively limiting the validation scope of an OTP, for instance:
- Per application (shared secret = application-level secret)
- Per user/session (shared secret = user/session unique random secret)
- Per transaction (shared secret = transaction unique random secret)

Needless to say, the *shared secret* must be kept secret. Once its confidentiality or integrity is breached, the intruder can impersonate the user.

## Installation

1. You can install the OpenTOTP from [PyPI](https://pypi.org/project/opentotp/):
   ```shell
   python -m pip install opentotp
   ```

## Quick start

1. Generate OTP (using default settings)
    ```shell
    python -m opentotp generate
    ```

3. Verify OTP
    ```shell
    python -m opentotp verify OTP_VALUE
    ```

## Command line usage

1. Generate OTP using **custom secret**
    ```shell
    TOTP_SECRET=`python -c "import os; print(os.urandom(32).hex())"`
    python -m opentotp --secret ${TOTP_SECRET} generate
    ```
   
2. Generate OTP using **verbose mode**
    ```shell
    python -m opentotp -v generate
    ```
   
3. Generate OTP that changes **every 30 seconds**
    ```shell
    python -m opentotp --otp-change-interval 30 generate 
    ```
4. Generate OTP that uses **only Arabic numerals** as the output alphabet
   ```shell
   python -m opentotp --alphabet "0123456789" generate
   ```

5. Verify if **OTP is correct**
    ```shell
    # Sample OTP value: yfPXifub
    python -m opentotp --secret "REPLACE_WITH_SECRET_USED_TO_GENERATE_OTP" verify yfPXifub 
    ```

6. When verifying, also accept **4 older/newer OTPs**
    ```shell
    # Sample OTP value: yfPXifub
    python -m opentotp --otp-change-interval 30 --otp-drift 4 verify yfPXifub 
    ```

## Command line parameters

```
usage: opentotp.py [-h] [--timestamp TIMESTAMP] [--secret SECRET] [--alphabet ALPHABET] [--otp-length OTP_LENGTH] [--otp-change-interval OTP_CHANGE_INTERVAL] [--otp-drift OTP_DRIFT]
                   [--nonce NONCE] [--version] [-v | -q]
                   {generate,verify} ...

Generate or verify Time-based One-Time Passwords (TOTPs) based on shared secret and current UTC timestamp.

  To generate new OTP:
       python -m opentotp generate

  To verify OTP: 
       python -m opentotp verify OTP_VALUE

optional arguments:
  -h, --help            show this help message and exit
  --timestamp TIMESTAMP
                        Custom UTC Epoch timestamp to use
  --secret SECRET       Shared secret value
  --alphabet ALPHABET   Custom encoding (output) alphabet
  --otp-length OTP_LENGTH
                        Length of OTP
  --otp-change-interval OTP_CHANGE_INTERVAL
                        OTP change interval [in seconds]
  --otp-drift OTP_DRIFT
                        A number of previous/next OTPs to accept
  --nonce NONCE         A one-time-only NONCE value to prevent replay-attacks
  --version             show program's version number and exit
  -v, --verbose         Include configuration parameters in result screen
  -q, --quiet           Quiet mode. Print OTP only or return result of verification (TRUE or FALSE)

sub-commands:
  {generate,verify}     OpenTOTP mode of operation
    generate            Generate new OTP
    verify              Verify if provided OTP is correct
```

## Module usage

Sample code snippet

```python
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
```

## Docker usage

For some, this may be the fastest and cleanest way to try OpenTOTP:

1. Build docker image and run the container
   ```shell
   git clone https://github.com/prevenitylabs/opentotp.git opentotp
   cd opentotp
   docker build -t opentotp .
   docker run --rm opentotp --help
   ```
   
2. Generate OTP
   ```shell
   docker run --rm opentotp generate
   ```

3. Verify OTP
   ```shell
   docker run --rm opentotp -v verify OTP_VALUE
   ```
