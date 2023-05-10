<?php declare(strict_types=1);

namespace OpenPGP\Tests\Packet;

use phpseclib3\Crypt\Random;
use OpenPGP\Enum\KekSize;
use OpenPGP\Packet\Key\AesKeyWrapper;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for compression packet.
 */
class KeyWrapperTest extends OpenPGPTestCase
{
    private $key128 = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf";
    private $key192 = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\x10\x11\x12\x13\x14\x15\x16\x17";
    private $key256 = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    private $keyData128 = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
    private $keyData192 = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x01\x02\x03\x04\x05\x06\x07";
    private $keyData256 = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

    public function testAes128()
    {
        $aes = new AesKeyWrapper(KekSize::S16);
        $wrappedKey128128 = "\x1f\xa6\x8b\x0a\x81\x12\xb4\x47\xae\xf3\x4b\xd8\xfb\x5a\x7b\x82\x9d\x3e\x86\x23\x71\xd2\xcf\xe5";

        $wrappedKey128 = $aes->wrap($this->key128, $this->keyData128);
        $unwrappedKey128 = $aes->unwrap($this->key128, $wrappedKey128);
        $this->assertSame($wrappedKey128, $wrappedKey128128);
        $this->assertSame($unwrappedKey128, $this->keyData128);

        $key = Random::string(16);
        $keyData = Random::string(32);
        $wrappedKey = $aes->wrap($key, $keyData);
        $unwrappedKey = $aes->unwrap($key, $wrappedKey);
        $this->assertSame($unwrappedKey, $keyData);
    }

    public function testAes196()
    {
        $aes = new AesKeyWrapper(KekSize::S24);
        $wrappedKey128192 = "\x96\x77\x8b\x25\xae\x6c\xa4\x35\xf9\x2b\x5b\x97\xc0\x50\xae\xd2\x46\x8a\xb8\xa1\x7a\xd8\x4e\x5d";
        $wrappedKey192192 = "\x03\x1d\x33\x26\x4e\x15\xd3\x32\x68\xf2\x4e\xc2\x60\x74\x3e\xdc\xe1\xc6\xc7\xdd\xee\x72\x5a\x93\x6b\xa8\x14\x91\x5c\x67\x62\xd2";

        $wrappedKey128 = $aes->wrap($this->key192, $this->keyData128);
        $unwrappedKey128 = $aes->unwrap($this->key192, $wrappedKey128);
        $this->assertSame($wrappedKey128, $wrappedKey128192);
        $this->assertSame($unwrappedKey128, $this->keyData128);

        $wrappedKey192 = $aes->wrap($this->key192, $this->keyData192);
        $unwrappedKey192 = $aes->unwrap($this->key192, $wrappedKey192);
        $this->assertSame($wrappedKey192, $wrappedKey192192);
        $this->assertSame($unwrappedKey192, $this->keyData192);

        $key = Random::string(24);
        $keyData = Random::string(32);
        $wrappedKey = $aes->wrap($key, $keyData);
        $unwrappedKey = $aes->unwrap($key, $wrappedKey);
        $this->assertSame($unwrappedKey, $keyData);
    }

    public function testAes256()
    {
        $aes = new AesKeyWrapper(KekSize::S32);
        $wrappedKey128256 = "\x64\xe8\xc3\xf9\xce\x0f\x5b\xa2\x63\xe9\x77\x79\x05\x81\x8a\x2a\x93\xc8\x19\x1e\x7d\x6e\x8a\xe7";
        $wrappedKey192256 = "\xa8\xf9\xbc\x16\x12\xc6\x8b\x3f\xf6\xe6\xf4\xfb\xe3\x0e\x71\xe4\x76\x9c\x8b\x80\xa3\x2c\xb8\x95\x8c\xd5\xd1\x7d\x6b\x25\x4d\xa1";
        $wrappedKey256256 = "\x28\xc9\xf4\x04\xc4\xb8\x10\xf4\xcb\xcc\xb3\x5c\xfb\x87\xf8\x26\x3f\x57\x86\xe2\xd8\x0e\xd3\x26\xcb\xc7\xf0\xe7\x1a\x99\xf4\x3b\xfb\x98\x8b\x9b\x7a\x02\xdd\x21";

        $wrappedKey128 = $aes->wrap($this->key256, $this->keyData128);
        $unwrappedKey128 = $aes->unwrap($this->key256, $wrappedKey128);
        $this->assertSame($wrappedKey128, $wrappedKey128256);
        $this->assertSame($unwrappedKey128, $this->keyData128);

        $wrappedKey192 = $aes->wrap($this->key256, $this->keyData192);
        $unwrappedKey192 = $aes->unwrap($this->key256, $wrappedKey192);
        $this->assertSame($wrappedKey192, $wrappedKey192256);
        $this->assertSame($unwrappedKey192, $this->keyData192);

        $wrappedKey256 = $aes->wrap($this->key256, $this->keyData256);
        $unwrappedKey256 = $aes->unwrap($this->key256, $wrappedKey256);
        $this->assertSame($wrappedKey256, $wrappedKey256256);
        $this->assertSame($unwrappedKey256, $this->keyData256);

        $key = Random::string(32);
        $keyData = Random::string(32);
        $wrappedKey = $aes->wrap($key, $keyData);
        $unwrappedKey = $aes->unwrap($key, $wrappedKey);
        $this->assertSame($unwrappedKey, $keyData);
    }
}
