#!/usr/bin/env python3

import sys
import argparse

from opentotp import OpenTOTP, __version__

__all__ = ["main"]


def cmd_generate(otp: OpenTOTP,
                 args: argparse.Namespace) -> int:
    """Sub-command to generate OTP"""
    if not args.quiet:
        param_use_verbose_mode(otp, args)
        print("One-time password: ", end="")
    print(otp.generate(args.timestamp, args.nonce))
    return 0


def cmd_verify(otp: OpenTOTP,
               args: argparse.Namespace) -> int:
    """Sub-command to verify OTP"""
    otp_value = sys.stdin.readline().strip() if args.otp_value == "-" else args.otp_value
    result = otp.verify(otp_value,
                        args.timestamp,
                        args.nonce)
    if not args.quiet:
        param_use_verbose_mode(otp, args)
        print(f"Verification result: {'SUCCESS' if result else 'FAILURE'}")
    else:
        print(f"{'TRUE' if result else 'FALSE'}")

    return int(not result)


def param_use_verbose_mode(otp: OpenTOTP,
                           args: argparse.Namespace) -> None:
    """Print OpenTOTP configuration if verbose mode is enabled"""
    if args.verbose:
        print("--- OpenTOTP CONFIGURATION ----------------------------------------------------")
        print(f"Secret: {otp.secret.hex()}")
        print(f"Alphabet: {otp.alphabet.decode('utf-8')}")
        print(f"OTP Length: {otp.otp_length}")
        print(f"OTP Change Interval: {otp.otp_change_interval}")
        print(f"OTP Drift (+/-): {otp.otp_drift}")
        print(f"Base timestamp: {args.timestamp if args.timestamp else otp._get_base_timestamp()}")
        print(f"Nonce: {args.nonce}")
        print("-------------------------------------------------------------------------------")


def argparse_init() -> argparse.ArgumentParser:
    """Initialize argument parser"""
    parser = argparse.ArgumentParser(description="Generate or verify Time-based One-Time Passwords (TOTPs) based " +
                                                 "on shared secret and current UTC timestamp.\n\n" +
                                                 "  To generate new OTP:\n       python -m opentotp generate\n\n" +
                                                 "  To verify OTP: \n       python -m opentotp verify OTP_VALUE\n",
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--timestamp', help="Custom UTC Epoch timestamp to use", type=int, default=None)
    parser.add_argument('--secret', help="Shared secret value", default=None)
    parser.add_argument('--alphabet', help="Custom encoding (output) alphabet", default=None)
    parser.add_argument('--otp-length', help="Length of OTP", type=int, default=None)
    parser.add_argument('--otp-change-interval', help="OTP change interval [in seconds]", type=int, default=None)
    parser.add_argument('--otp-drift', help="A number of previous/next OTPs to accept", type=int, default=None)
    parser.add_argument('--nonce', help="A one-time-only NONCE value to prevent replay-attacks", default=None)
    parser.add_argument('--version', action='version', version=__version__)

    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument('-v', '--verbose',
                               help="Include configuration parameters in result screen",
                               action="store_true")
    verbose_group.add_argument('-q', '--quiet',
                               help="Quiet mode. Print OTP only or return result of verification (TRUE or FALSE)",
                               action="store_true")

    subparsers = parser.add_subparsers(title="sub-commands", dest="subcommand_name",
                                       help="OpenTOTP mode of operation", required=True)

    generate_parser = subparsers.add_parser('generate', help="Generate new OTP")
    generate_parser.set_defaults(func=cmd_generate)

    verify_parser = subparsers.add_parser('verify', help="Verify if provided OTP is correct")
    verify_parser.add_argument('otp_value', metavar="OTP_VALUE",
                               help="OTP value to verify, or '-' if OTP should be read from STDIN", default=None)
    verify_parser.set_defaults(func=cmd_verify)

    return parser


def main():
    """OpenTOTP Command Line Interface (CLI)"""
    parser = argparse_init()
    if len(sys.argv) > 1:
        try:
            args = parser.parse_args()
            otp = OpenTOTP(secret=args.secret,
                           alphabet=args.alphabet,
                           otp_length=args.otp_length,
                           otp_change_interval=args.otp_change_interval,
                           otp_drift=args.otp_drift)
            result = args.func(otp, args)
            parser.exit(result)
        except Exception as e:
            parser.error(repr(e))
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
