<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Enum\SignatureType;
use OpenPGP\Packet\PublicKey;
use OpenPGP\Packet\SecretKey;
use OpenPGP\Packet\Signature;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the MPIs written by signing.
 */
class CanonicalMpiSigningTest extends OpenPGPTestCase
{
    const PASSPHRASE = "password";

    // The keys of SigningTest.
    private static $rsaPublicKeyData = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAE=
EOT;

    private static $rsaSecretKeyData = <<<EOT
BGRUrD4BCACe8iv48dGvqnbOuPv1DnnrasH/NZ5bbpGHW0gSOXb4p2d7VcfA6hfoyq1yEuZ2VDzJ
WpkhVnKMF1Ytj7d8mtnGsTQ6NfGrV9jRhGIxAYIgiDjzuhIejzMrTR/RAh9aARPTuEayRXoShTEg
cQfZxIQKwwU5hE4PDZFhq0h/T83eImWidUZwt3zw6jWq29nDtmtR96x+xznG0utZrHsbkxNtuLpX
YlrMl9Lcz9vbntpK45aq35P3cfg5UEjCLj1TAq6LPFnfiwbQcNkbsTRsxPqWpX4J6v5ZabJIFGyd
K14eiohYTbp7Uvr/e3yRhTirWYz4KnJwuFOsemuSjSAGi3C5ABEBAAH+BwMCLQGcMzPKel7/nlml
LznQdMJ5SimdfqT4NvlNkb5QN+IqXfqOg01EF0cbWsT510j8iAox1auK9lJstyeqKK1ttqdF/2wf
dymZ0UQn+BqqvYqACMQmBhXvi/jr4m+4AJC3PLwIapLZaQS/HT+sqqU2WheSCUD2v4pA069B0jGL
nQ8t+j1dJrentK/hr6S/q06G/gOehcRKPYnTjM2lDv8TUA7Yg45dYwRKRg3IneQor2Yh2d0tvL78
U4Dq1YMFfgvsO4szknklq4sQGKLH4DRv+Cv+sALZOFTNv0h851tLP+22RnwfKUbQ9F9uw0MG9Rav
7Wy+ililDQXcU1kYMMIU8vBbGmwjwRrP7QM1NbmGrOEpdDZKgAUWnyv+EtMPxfytbFcj8rF2yAf5
xd3lrQdQcR8ePxE8dbbV/c1KwkbKDfXAQOSoEFJpFNqXEAK9he59oKICH+4yMqXxIXYDaMognhtP
hH/tZCgYRzLavt9dR6BJ9VGhgzNgtWsvn+5L4oBfDBF2XjB3mKLMdjvO9wH1SLLRaAtIx2xGdT1c
ediMVFo5uNdDC97CQwAx4QDlX5RbQHe7lq0T7t2WQ8LagjciTeDOtKEf5WN69a1kGSzgJn6rm1GL
fCc93clNyiYygS+GaVFnhr/hEdq8pRiIUs7FlpK9lPNMv9Ecs03fGE0ZzA3gWyb1KZLpwFLXk2XR
BM8cDkFsIy9Mn9e9p85IcXZ3WDuJms/gkYRb1CsVTsvVSft1+xYi/Ve6JmIeRkE1weRLuOMkqvFJ
QdjujszGY2uSv1iTik/46DAEf0yJ7/7Fwt9gSgTLEbh0NIGE21Z11BKY+ovITfgrmJOhP9kQ6oIX
RfZglUaCOkOPtqPMQNOpZiV3VY6IOay+r7y9Rx2xT03WrnSowNZQXSCksonthXUZAXoGSeFO
EOT;

    private static $eddsaCurve25519PublicKeyData = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM
EOT;

    private static $eddsaCurve25519SecretKeyData = <<<EOT
BGRYXQUWCSsGAQQB2kcPAQEHQLvR0VoiVSt3+xzxSSQrR7/yrMzQG8OXueMhIkQb0UPM/gcDAg3L
LOtx/PSU/9E+PgO1Rd79U+hHRifxAcg+kLq3aoLBbA7RmrVdDTeQvoFl3C+WCC1WleUW21FsUpce
31nuheiWbgVEXVXQUOcXaVbGVGY=
EOT;

    /**
     * Read one MPI at an offset: bit length, value, and the next offset.
     */
    private static function readMpi(string $bytes, int $offset): array
    {
        $bits = unpack("n", substr($bytes, $offset, 2))[1];
        $value = substr($bytes, $offset + 2, ($bits + 7) >> 3);
        return [$bits, $value, $offset + 2 + strlen($value)];
    }

    /**
     * An MPI is canonical when its value has no leading zero octet and its
     * bit length counts from the most significant set bit (RFC 9580, 3.2).
     */
    private function assertCanonical(int $bits, string $value): void
    {
        $this->assertNotSame("\0", $value[0] ?? "", "MPI value has a leading zero octet.");
        $expected = strlen($value) === 0
            ? 0
            : (strlen($value) - 1) * 8 + strlen(decbin(ord($value[0])));
        $this->assertSame($expected, $bits, "MPI bit length is not canonical.");
    }

    public function testRsaSignatureIsCanonicalMpi()
    {
        $secretKey = SecretKey::fromBytes(
            base64_decode(self::$rsaSecretKeyData)
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(
            base64_decode(self::$rsaPublicKeyData)
        );
        $material = $secretKey->getKeyMaterial();
        $modulusLength = ($publicKey->getKeyStrength() + 7) >> 3;

        // RSA PKCS#1 v1.5 signatures are deterministic. About one in 256
        // has a leading zero octet; search until one is found.
        for ($i = 0; $i < 4096; $i++) {
            $message = "message " . $i;
            [$bits, $value] = self::readMpi(
                $material->sign(HashAlgorithm::Sha256, $message),
                0
            );
            if (strlen($value) < $modulusLength || $value[0] === "\0") {
                $this->assertCanonical($bits, $value);
                $signature = Signature::createSignature(
                    $secretKey,
                    SignatureType::Standalone,
                    $message
                );
                $this->assertTrue($signature->verify($publicKey, $message));
                return;
            }
            $this->assertCanonical($bits, $value);
        }
        $this->fail("No RSA signature with a leading zero octet was found.");
    }

    public function testEdDsaLegacySignatureIsCanonicalMpi()
    {
        $secretKey = SecretKey::fromBytes(
            base64_decode(self::$eddsaCurve25519SecretKeyData)
        )->decrypt(self::PASSPHRASE);
        $publicKey = PublicKey::fromBytes(
            base64_decode(self::$eddsaCurve25519PublicKeyData)
        );
        $material = $secretKey->getKeyMaterial();

        // Ed25519 signatures are deterministic. About one in 128 has a
        // leading zero octet in R or S; search until one is found.
        for ($i = 0; $i < 4096; $i++) {
            $message = "message " . $i;
            $bytes = $material->sign(HashAlgorithm::Sha256, $message);
            [$rBits, $r, $offset] = self::readMpi($bytes, 0);
            [$sBits, $s] = self::readMpi($bytes, $offset);
            $this->assertCanonical($rBits, $r);
            $this->assertCanonical($sBits, $s);
            if (strlen($r) < 32 || strlen($s) < 32) {
                $signature = Signature::createSignature(
                    $secretKey,
                    SignatureType::Standalone,
                    $message
                );
                $this->assertTrue($signature->verify($publicKey, $message));
                return;
            }
        }
        $this->fail("No EdDSA signature with a leading zero octet was found.");
    }
}
