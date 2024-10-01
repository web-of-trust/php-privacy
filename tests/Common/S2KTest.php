<?php declare(strict_types=1);

namespace OpenPGP\Tests\Common;

use OpenPGP\Common\Argon2S2K;
use OpenPGP\Common\GenericS2K;
use OpenPGP\Enum\HashAlgorithm;
use OpenPGP\Enum\S2kType;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Packet\SymmetricKeyEncryptedSessionKey;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for S2K.
 */
class S2KTest extends OpenPGPTestCase
{
    public function testMode0Password1234()
    {
        $data = 'BAkAAg==';
        $passphrase = '1234';
        $salt = '';

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertSame(S2kType::Simple, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), '7110eda4d09e062aa5e4a390b0a572ac0d2c0220f352b0d292b65164c2a67301');
    }

    public function testMode1Password123456()
    {
        $data = 'BAkBAqhCp6lZ+kIq';
        $passphrase = '123456';
        $salt = "\xa8\x42\xa7\xa9\x59\xfa\x42\x2a";

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertSame(S2kType::Salted, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), '8b79077ca448f6fb3d3ad2a264d3b938d357c9fb3e41219fd962df960a9afa08');
    }

    public function testMode1PasswordFoobar()
    {
        $data = 'BAkBAryVWEWBPHw3';
        $passphrase = 'foobar';
        $salt = "\xbc\x95\x58\x45\x81\x3c\x7c\x37";

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertSame(S2kType::Salted, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), 'b7d48aae9b943b22a4d390083e8460b5edfa118fe1688bf0c473b8094d1a8d10');
    }

    public function testMode3PasswordQwerty()
    {
        $data = 'BAkDAnhF8FtV97Se8Q==';
        $passphrase = 'qwerty';
        $salt = "\x78\x45\xf0\x5b\x55\xf7\xb4\x9e";
        $itCount = 241;

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertSame(S2kType::Iterated, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());
        $this->assertSame($itCount, $s2k->getItCount());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm(), $s2k->getItCount());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), '575ad156187a3f8cec11108309236eb499f1e682f0d1afadfac4ecf97613108a');
    }

    public function testMode3Password9876()
    {
        $data = 'BAkDArln6pZT22rIKw==';
        $passphrase = '9876';
        $salt = "\xb9\x67\xea\x96\x53\xdb\x6a\xc8";
        $itCount = 43;

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes256, $skesk->getSymmetric());
        $this->assertSame(S2kType::Iterated, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());
        $this->assertSame($itCount, $s2k->getItCount());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm(), $s2k->getItCount());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), '736c226b8c64e4e6d0325c6c552ef7c0738f98f48fed65fd8c93265103efa23a');
    }

    public function testMode3Aes192Password123()
    {
        $data = 'BAgDAo+BdMXZYcd57g==';
        $passphrase = '123';
        $salt = "\x8f\x81\x74\xc5\xd9\x61\xc7\x79";
        $itCount = 238;

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes192, $skesk->getSymmetric());
        $this->assertSame(S2kType::Iterated, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());
        $this->assertSame($itCount, $s2k->getItCount());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm(), $s2k->getItCount());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), '915e96fc694e7f90a6850b740125ea005199c725f3bd27e3');
    }

    public function testMode3TwofishPassword13Iterations0123456789()
    {
        $data = 'BAoDAlHt/BVFQGWs7g==';
        $passphrase = '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789';
        $salt = "\x51\xed\xfc\x15\x45\x40\x65\xac";
        $itCount = 238;

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Twofish, $skesk->getSymmetric());
        $this->assertSame(S2kType::Iterated, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());
        $this->assertSame($itCount, $s2k->getItCount());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm(), $s2k->getItCount());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), 'ea264fada5a859c40d88a159b344ecf1f51ff327fdb3c558b0a7dc299777173e');
    }

    public function testMode3Aes128Password13Iterations0123456789()
    {
        $data = 'BAcDAgbkYVykSPnd7g==';
        $passphrase = '0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789';
        $salt = "\x06\xe4\x61\x5c\xa4\x48\xf9\xdd";
        $itCount = 238;

        $skesk = SymmetricKeyEncryptedSessionKey::fromBytes(base64_decode($data));
        $s2k = $skesk->getS2K();

        $this->assertSame(SymmetricAlgorithm::Aes128, $skesk->getSymmetric());
        $this->assertSame(S2kType::Iterated, $s2k->getType());
        $this->assertSame(HashAlgorithm::Sha1, $s2k->getHashAlgorithm());
        $this->assertSame($salt, $s2k->getSalt());
        $this->assertSame($itCount, $s2k->getItCount());

        $s2k = new GenericS2K($salt, $s2k->getType(), $s2k->getHashAlgorithm(), $s2k->getItCount());
        $key = $s2k->produceKey($passphrase, $skesk->getSymmetric()->keySizeInByte());
        $this->assertSame(bin2hex($key), 'f3d0ce52ed6143637443e3399437fd0f');
    }

    public function test4Iterations1MB16KeyLengthArgon2S2K()
    {
        $password = 'password';
        $salt = 'dH3Z8hGL7bBUyp1i';
        $hash = 'eaf0095c8412e432cb9ff172957fef91';

        $s2k = new Argon2S2K($salt, 4, 1, 10);
        $this->assertSame(bin2hex($s2k->produceKey($password, 16)), $hash);
    }

    public function test4Iterations64MB16KeyLengthArgon2S2K()
    {
        $password = 'password';
        $salt = 'IeCBTBvkzbmxT87I';
        $hash = '050ebb7bcb8c1165502af049a664f2db';

        $s2k = new Argon2S2K($salt, 4, 1, 16);
        $this->assertSame(bin2hex($s2k->produceKey($password, 16)), $hash);
    }

    public function test4Iterations10MB32KeyLengthArgon2S2K()
    {
        $password = 'password';
        $salt = 'KtPeAgudgN7xrgUK';
        $hash = '66b3d1c15f544eae5810c29381ad477167d5a1d5360c9b97340bd5b8b06c589b';

        $s2k = new Argon2S2K($salt, 4, 1, 10);
        $this->assertSame(bin2hex($s2k->produceKey($password, 32)), $hash);
    }

    public function test4Iterations64MB32KeyLengthArgon2S2K()
    {
        $password = 'password';
        $salt = 'D85Euo8RwvlkUxb5';
        $hash = 'cb1f8f04ec5ecb681e4ffb2665af6e4ad6aed540b5e62f625f48c834e8b88fa6';

        $s2k = new Argon2S2K($salt, 4, 1, 16);
        $this->assertSame(bin2hex($s2k->produceKey($password, 32)), $hash);
    }
}
