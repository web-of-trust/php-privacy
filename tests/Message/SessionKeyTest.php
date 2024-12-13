<?php declare(strict_types=1);

namespace OpenPGP\Tests\Message;

use OpenPGP\OpenPGP;
use OpenPGP\Enum\{AeadAlgorithm, SymmetricAlgorithm};
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for session key.
 */
class SessionKeyTest extends OpenPGPTestCase
{
    const PASSPHRASE = "password";

    private static string $rfc9580PublicKey = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----
EOT;

    private static string $rfc9580PrivateKey = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----
EOT;

    private static string $alicePublicKey = <<<EOT
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE
ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy
MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO
dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4
OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s
E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb
DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn
0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=
=iIGO
-----END PGP PUBLIC KEY BLOCK-----
EOT;

    private static string $alicePrivateKey = <<<EOT
-----BEGIN PGP PRIVATE KEY BLOCK-----

xVgEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u10AAP9XBeW6lzGOLx7zHH9AsUDUTb2pggYGMzd0P3ulJ2AfvQ4RzSZBbGlj
ZSBMb3ZlbGFjZSA8YWxpY2VAb3BlbnBncC5leGFtcGxlPsKQBBMWCAA4AhsDBQsJ
CAcCBhUKCQgLAgQWAgMBAh4BAheAFiEE64W7X6M6deFelE5j8jFVDE9H444FAl2l
nzoACgkQ8jFVDE9H447pKwD6A5xwUqIDprBzrHfahrImaYEZzncqb25vkLV2arYf
a78A/R3AwtLQvjxwLDuzk4dUtUwvUYibL2sAHwj2kGaHnfICx10EXEcE6RIKKwYB
BAGXVQEFAQEHQEL/BiGtq0k84Km1wqQw2DIikVYrQrMttN8d7BPfnr4iAwEIBwAA
/3/xFPG6U17rhTuq+07gmEvaFYKfxRB6sgAYiW6TMTpQEK7CeAQYFggAIBYhBOuF
u1+jOnXhXpROY/IxVQxPR+OOBQJcRwTpAhsMAAoJEPIxVQxPR+OOWdABAMUdSzpM
hzGs1O0RkWNQWbUzQ8nUOeD9wNbjE3zR+yfRAQDbYqvtWQKN4AQLTxVJN5X5AWyb
Pnn+We1aTBhaGa86AQ==
=3GfK
-----END PGP PRIVATE KEY BLOCK-----
EOT;

    public function testGenerateSessionKey()
    {
        $sessionKey = OpenPGP::generateSessionKey([
            OpenPGP::readPublicKey(self::$rfc9580PublicKey),
        ]);
        $this->assertSame(
            $sessionKey->getSymmetric(),
            SymmetricAlgorithm::Aes256
        );
        $this->assertSame(
            $sessionKey->getAead(),
            AeadAlgorithm::Ocb
        );

        $sessionKey = OpenPGP::generateSessionKey([
            OpenPGP::readPublicKey(self::$alicePublicKey),
        ]);
        $this->assertSame(
            $sessionKey->getSymmetric(),
            SymmetricAlgorithm::Aes256
        );
        $this->assertTrue(empty($sessionKey->getAead()));

        $sessionKey = OpenPGP::generateSessionKey([
            OpenPGP::readPublicKey(self::$rfc9580PublicKey),
            OpenPGP::readPublicKey(self::$alicePublicKey),
        ]);
        $this->assertSame(
            $sessionKey->getSymmetric(),
            SymmetricAlgorithm::Aes256
        );
        $this->assertTrue(empty($sessionKey->getAead()));
    }

    public function testSessionKeyEncryption()
    {
        $sessionKey = OpenPGP::generateSessionKey([
            OpenPGP::readPublicKey(self::$rfc9580PublicKey),
            OpenPGP::readPublicKey(self::$alicePublicKey),
        ]);

        $eskPackets = OpenPGP::encryptSessionKey(
            $sessionKey,
            [
                OpenPGP::readPublicKey(self::$rfc9580PublicKey),
                OpenPGP::readPublicKey(self::$alicePublicKey),
            ],
            [self::PASSPHRASE]
        );

        $decryptSessionKey = OpenPGP::decryptSessionKey($eskPackets, [
            OpenPGP::readPrivateKey(self::$rfc9580PrivateKey)
        ]);
        $this->assertSame(
            $sessionKey->getEncryptionKey(),
            $decryptSessionKey->getEncryptionKey()
        );
        $this->assertSame(
            $sessionKey->getSymmetric(),
            $decryptSessionKey->getSymmetric()
        );

        $decryptSessionKey = OpenPGP::decryptSessionKey($eskPackets, [
            OpenPGP::readPrivateKey(self::$alicePrivateKey)
        ]);
        $this->assertSame(
            $sessionKey->getEncryptionKey(),
            $decryptSessionKey->getEncryptionKey()
        );
        $this->assertSame(
            $sessionKey->getSymmetric(),
            $decryptSessionKey->getSymmetric()
        );

        $decryptSessionKey = OpenPGP::decryptSessionKey($eskPackets, [], [
            self::PASSPHRASE
        ]);
        $this->assertSame(
            $sessionKey->getEncryptionKey(),
            $decryptSessionKey->getEncryptionKey()
        );
        $this->assertSame(
            $sessionKey->getSymmetric(),
            $decryptSessionKey->getSymmetric()
        );
    }
}
