<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\OCB;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OCB through OpenSSL.
 * The result must be the same as the PHP code, in both directions.
 */
class OCBOpenSSLTest extends OpenPGPTestCase
{
    private static function phpCrypt(
        OCB $ocb,
        bool $encrypt,
        string $text,
        string $nonce,
        string $aData,
    ): string {
        $crypt = function (
            bool $encrypt,
            string $text,
            string $nonce,
            string $aData,
        ): string {
            return $this->crypt(
                $encrypt ? $this->encipher : $this->decipher,
                $text,
                $nonce,
                $aData,
            );
        };
        return \Closure::bind($crypt, $ocb, OCB::class)(
            $encrypt,
            $text,
            $nonce,
            $aData,
        );
    }

    private static function usesOpenSSL(OCB $ocb): bool
    {
        return (new \ReflectionProperty(OCB::class, "openssl"))->getValue(
            $ocb,
        ) !== null;
    }

    public function testSameAsPhpInBothDirections()
    {
        $offered = array_map("strtolower", openssl_get_cipher_methods());
        if (!in_array("aes-128-ocb", $offered, true)) {
            $this->markTestSkipped("OpenSSL does not offer OCB.");
        }
        $count = 0;
        foreach (
            [
                SymmetricAlgorithm::Aes128,
                SymmetricAlgorithm::Aes192,
                SymmetricAlgorithm::Aes256,
            ]
            as $symmetric
        ) {
            $key = random_bytes($symmetric->keySizeInByte());
            $ocb = new OCB($key, $symmetric);
            $this->assertTrue(self::usesOpenSSL($ocb), $symmetric->name);
            foreach ([0, 1, 15, 16, 17, 31, 32, 33, 1000, 65537] as $length) {
                foreach (["", "a", random_bytes(17)] as $aData) {
                    foreach ([15, 12] as $nonceLength) {
                        $plainText = $length > 0 ? random_bytes($length) : "";
                        $nonce = random_bytes($nonceLength);
                        $case = "{$symmetric->name} {$length} {$nonceLength}";

                        $cipherText = $ocb->encrypt($plainText, $nonce, $aData);
                        $this->assertSame(
                            bin2hex(
                                self::phpCrypt(
                                    $ocb,
                                    true,
                                    $plainText,
                                    $nonce,
                                    $aData,
                                ),
                            ),
                            bin2hex($cipherText),
                            $case,
                        );

                        // PHP reads what OpenSSL wrote
                        $crypted = self::phpCrypt(
                            $ocb,
                            false,
                            substr($cipherText, 0, -16),
                            $nonce,
                            $aData,
                        );
                        $this->assertSame(
                            bin2hex($plainText . substr($cipherText, -16)),
                            bin2hex($crypted),
                            $case,
                        );

                        // OpenSSL reads what PHP wrote
                        $this->assertSame(
                            bin2hex($plainText),
                            bin2hex(
                                $ocb->decrypt(
                                    self::phpCrypt(
                                        $ocb,
                                        true,
                                        $plainText,
                                        $nonce,
                                        $aData,
                                    ),
                                    $nonce,
                                    $aData,
                                ),
                            ),
                            $case,
                        );
                        $count++;
                    }
                }
            }
        }
        $this->assertSame(180, $count);
    }

    public function testChangedInputThrows()
    {
        $ocb = new OCB(str_repeat("k", 16), SymmetricAlgorithm::Aes128);
        $nonce = str_repeat("n", 15);
        $cipherText = $ocb->encrypt(str_repeat("x", 100), $nonce, "data");
        $tag = $cipherText;
        $tag[115] = chr(ord($tag[115]) ^ 0x01);
        $text = $cipherText;
        $text[0] = chr(ord($text[0]) ^ 0x01);
        foreach (
            [
                "tag" => [$tag, $nonce, "data"],
                "cipher text" => [$text, $nonce, "data"],
                "associated data" => [$cipherText, $nonce, "datA"],
                "nonce" => [$cipherText, str_repeat("m", 15), "data"],
            ]
            as $case => [$changed, $n, $aData]
        ) {
            $error = "";
            try {
                $ocb->decrypt($changed, $n, $aData);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
            $this->assertSame("Authentication tag mismatch!", $error, $case);
        }
    }

    public function testOtherCipherStaysInPhp()
    {
        $ocb = new OCB(
            str_repeat("k", 16),
            SymmetricAlgorithm::Camellia128,
        );
        $this->assertFalse(self::usesOpenSSL($ocb));
        $nonce = str_repeat("n", 15);
        $cipherText = $ocb->encrypt("Hello", $nonce);
        $this->assertSame("Hello", $ocb->decrypt($cipherText, $nonce));
    }
}
