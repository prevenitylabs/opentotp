import unittest
import subprocess


class TestMainCLI(unittest.TestCase):
    main_cli = "python3 -m opentotp"

    def run_parameter(self, cmd):
        command = (self.main_cli + " " + cmd).split()
        result = subprocess.run(command, stdout=subprocess.PIPE)
        return result

    def test_main_help(self):
        result = self.run_parameter("--help")
        self.assertEqual(0, result.returncode)
        self.assertIsNone(result.stderr)
        self.assertGreater(len(result.stdout), 100)

    def test_main_generate_verify(self):
        result = self.run_parameter("-q generate")
        self.assertEqual(0, result.returncode)
        otp = result.stdout.decode("utf-8").rstrip()
        result = self.run_parameter(f"-q verify {otp}")
        self.assertEqual(0, result.returncode)
        self.assertEqual("TRUE", result.stdout.decode("utf-8").rstrip())
        result = self.run_parameter(f"-q verify {otp + '12345678'}")
        self.assertEqual(1, result.returncode)
        self.assertEqual("FALSE", result.stdout.decode("utf-8").rstrip())


if __name__ == "__main__":
    unittest.main()
