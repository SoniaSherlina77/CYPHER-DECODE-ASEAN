import unittest

from scamhelper.lang import detect_language


class LanguageTests(unittest.TestCase):
    def test_chinese(self):
        self.assertEqual(detect_language("我是警察，请转账"), "zh")

    def test_malay(self):
        self.assertEqual(
            detect_language("Ada orang call kata dari polis, suruh transfer duit ke akaun selamat."), "ms"
        )

    def test_english(self):
        self.assertEqual(detect_language("Please click the link to verify your account"), "en")

    def test_manglish_particles(self):
        self.assertEqual(
            detect_language("Eh you got call from police ah, they say your account got problem lah"),
            "manglish",
        )

    def test_manglish_mixed_malay_english(self):
        self.assertEqual(detect_language("Please bagi nombor akaun you sekarang"), "manglish")


if __name__ == "__main__":
    unittest.main()
