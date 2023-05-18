<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use phpseclib3\Crypt\Random;
use OpenPGP\Cryptor\Symmetric\Camellia;
use OpenPGP\Cryptor\Symmetric\CamelliaLight;
use OpenPGP\Cryptor\Symmetric\CAST5;
use OpenPGP\Cryptor\Symmetric\IDEA;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for symmetric cipher.
 */
class SymmetricTest extends OpenPGPTestCase
{
    public function testCamelliaCipher()
    {
        $cipher = new Camellia('ecb');
        $cipher->disablePadding();

        // 128 bit
        $cipher->setKey(hex2bin('00000000000000000000000000000000'));
        $encrypted = $cipher->encrypt(hex2bin('80000000000000000000000000000000'));
        $this->assertSame('07923a39eb0a817d1c4d87bdb82d1f1c', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('07923a39eb0a817d1c4d87bdb82d1f1c'));
        $this->assertSame('80000000000000000000000000000000', bin2hex($decrypted));

        $cipher->setKey(hex2bin('80000000000000000000000000000000'));
        $encrypted = $cipher->encrypt(hex2bin('00000000000000000000000000000000'));
        $this->assertSame('6c227f749319a3aa7da235a9bba05a2c', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('6c227f749319a3aa7da235a9bba05a2c'));
        $this->assertSame('00000000000000000000000000000000', bin2hex($decrypted));

        $cipher->setKey(hex2bin('0123456789abcdeffedcba9876543210'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdeffedcba9876543210'));
        $this->assertSame('67673138549669730857065648eabe43', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('67673138549669730857065648eabe43'));
        $this->assertSame('0123456789abcdeffedcba9876543210', bin2hex($decrypted));

        // 192 bit
        $cipher->setKey(hex2bin('0123456789abcdeffedcba98765432100011223344556677'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdeffedcba9876543210'));
        $this->assertSame('b4993401b3e996f84ee5cee7d79b09b9', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('b4993401b3e996f84ee5cee7d79b09b9'));
        $this->assertSame('0123456789abcdeffedcba9876543210', bin2hex($decrypted));

        $cipher->setKey(hex2bin('000000000000000000000000000000000000000000000000'));
        $encrypted = $cipher->encrypt(hex2bin('00040000000000000000000000000000'));
        $this->assertSame('9bca6c88b928c1b0f57f99866583a9bc', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('9bca6c88b928c1b0f57f99866583a9bc'));
        $this->assertSame('00040000000000000000000000000000', bin2hex($decrypted));

        $cipher->setKey(hex2bin('949494949494949494949494949494949494949494949494'));
        $encrypted = $cipher->encrypt(hex2bin('636eb22d84b006381235641bcf0308d2'));
        $this->assertSame('94949494949494949494949494949494', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('94949494949494949494949494949494'));
        $this->assertSame('636eb22d84b006381235641bcf0308d2', bin2hex($decrypted));

        // 256 bit
        $cipher->setKey(hex2bin('0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdeffedcba9876543210'));
        $this->assertSame('9acc237dff16d76c20ef7c919e3a7509', bin2hex($encrypted));

        $cipher->setKey(hex2bin('4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a'));
        $encrypted = $cipher->encrypt(hex2bin('057764fe3a500edbd988c5c3b56cba9a'));
        $this->assertSame('4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a', bin2hex($encrypted));

        $cipher->setKey(hex2bin('0303030303030303030303030303030303030303030303030303030303030303'));
        $encrypted = $cipher->encrypt(hex2bin('7968b08aba92193f2295121ef8d75c8a'));
        $this->assertSame('03030303030303030303030303030303', bin2hex($encrypted));
    }

    public function testCamelliaLightCipher()
    {
        $cipher = new CamelliaLight('ecb');
        $cipher->disablePadding();
        $this->assertTrue(true);
    }

    public function testCAST5Cipher()
    {
        $cipher = new CAST5('ecb');
        $cipher->disablePadding();

        $cipher->setKey(hex2bin('0123456712345678234567893456789a'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdef'));
        $this->assertSame('238b4fe5847e44b2', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('238b4fe5847e44b2'));
        $this->assertSame('0123456789abcdef', bin2hex($decrypted));

        $cipher->setKey(hex2bin('01234567123456782345'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdef'));
        $this->assertSame('eb6a711a2c02271b', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('eb6a711a2c02271b'));
        $this->assertSame('0123456789abcdef', bin2hex($decrypted));

        $cipher->setKey(hex2bin('0123456712'));
        $encrypted = $cipher->encrypt(hex2bin('0123456789abcdef'));
        $this->assertSame('7ac816d16e9b302e', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('7ac816d16e9b302e'));
        $this->assertSame('0123456789abcdef', bin2hex($decrypted));
    }

    public function testIDEACipher()
    {
        $cipher = new IDEA('ecb');
        $cipher->disablePadding();
        $cipher->setKey(hex2bin('00112233445566778899aabbccddeeff'));

        $encrypted = $cipher->encrypt(hex2bin('000102030405060708090a0b0c0d0e0f'));
        $this->assertSame('ed732271a7b39f475b4b2b6719f194bf', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('ed732271a7b39f475b4b2b6719f194bf'));
        $this->assertSame('000102030405060708090a0b0c0d0e0f', bin2hex($decrypted));

        $encrypted = $cipher->encrypt(hex2bin('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'));
        $this->assertSame('b8bc6ed5c899265d2bcfad1fc6d4287d', bin2hex($encrypted));
        $decrypted = $cipher->decrypt(hex2bin('b8bc6ed5c899265d2bcfad1fc6d4287d'));
        $this->assertSame('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff', bin2hex($decrypted));
    }
}
