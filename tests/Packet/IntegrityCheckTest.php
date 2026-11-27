<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use OpenPGP\Cryptor\Aead\EAX;
use OpenPGP\Enum\{KekSize, KeyType};
use OpenPGP\OpenPGP;
use OpenPGP\Packet\Key\AesKeyWrapper;
use OpenPGP\Packet\SecretKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the integrity checks that compare a received value
 * with a computed one: a right value is accepted, a wrong one rejected.
 */
class IntegrityCheckTest extends OpenPGPTestCase
{
    /**
     * Runs $read on $bytes and on $bytes with one bit flipped at $position.
     * Returns the error message of the changed input.
     */
    private function flipped(callable $read, string $bytes, int $position): string
    {
        $read($bytes);
        $bytes[$position] = chr(ord($bytes[$position]) ^ 0x01);
        try {
            $read($bytes);
        } catch (\RuntimeException $e) {
            return $e->getMessage();
        }
        return "";
    }

    public function testEaxTag()
    {
        $eax = new EAX(str_repeat("k", 16));
        $nonce = str_repeat("n", 16);
        $cipherText = $eax->encrypt("Hello", $nonce, "data");
        $this->assertSame("Hello", $eax->decrypt($cipherText, $nonce, "data"));
        $this->assertSame(
            "Authentication tag mismatch!",
            $this->flipped(
                fn($bytes) => $eax->decrypt($bytes, $nonce, "data"),
                $cipherText,
                strlen($cipherText) - 1
            )
        );
    }

    public function testModificationDetectionCode()
    {
        // A message protected by SEIPD version 1 with its MDC.
        $bytes = OpenPGP::encrypt(
            OpenPGP::createLiteralMessage("Hello"),
            passwords: ["password"]
        )->getPacketList()->encode();
        $read = static fn($bytes) => OpenPGP::decryptMessage(
            $bytes,
            passwords: ["password"],
            armored: false
        );
        $this->assertSame("Hello", $read($bytes)->getLiteralData()->getData());
        $this->assertSame(
            "Modification detected.",
            $this->flipped($read, $bytes, strlen($bytes) - 1)
        );
    }

    public function testKeyWrapIntegrityCheck()
    {
        $aes = new AesKeyWrapper(KekSize::Normal);
        $kek = str_repeat("k", 16);
        $key = str_repeat("s", 16);
        $wrapped = $aes->wrap($kek, $key);
        $this->assertSame($key, $aes->unwrap($kek, $wrapped));
        $this->assertSame(
            "Integrity check failed.",
            $this->flipped(
                fn($bytes) => $aes->unwrap($kek, $bytes),
                $wrapped,
                0
            )
        );
    }

    public function testSecretKeyChecksum()
    {
        // An unencrypted version 4 secret key ends with a two-octet checksum.
        $packet = OpenPGP::generateKey(
            ["Alice <alice@example.org>"],
            "password",
            KeyType::Ecc
        )->getSecretKeyPacket();
        $bytes = (new SecretKey(
            $packet->getPublicKey(),
            $packet->getKeyMaterial()->toBytes(),
            $packet->getKeyMaterial()
        ))->toBytes();
        $this->assertSame(
            "Key checksum mismatch!",
            $this->flipped(
                static fn($bytes) => SecretKey::fromBytes($bytes),
                $bytes,
                strlen($bytes) - 1
            )
        );
    }

    public function testSecretKeyHash()
    {
        // An encrypted version 4 secret key carries a SHA-1 hash of its
        // key material; a wrong passphrase decrypts to material that does
        // not match it.
        $packet = SecretKey::fromBytes(
            OpenPGP::generateKey(
                ["Alice <alice@example.org>"],
                "password",
                KeyType::Ecc
            )
                ->getSecretKeyPacket()
                ->toBytes()
        );
        $this->assertTrue($packet->decrypt("password")->isDecrypted());
        $error = "";
        try {
            $packet->decrypt("wrong password");
        } catch (\RuntimeException $e) {
            $error = $e->getMessage();
        }
        $this->assertSame("Incorrect key passphrase.", $error);
    }
}
