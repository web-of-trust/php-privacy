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
        $this->assertTrue(true);
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
