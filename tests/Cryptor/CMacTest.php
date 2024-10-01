<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\CMac;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for CMac.
 */
class CMacTest extends OpenPGPTestCase
{
    public function testAesCMac()
    {
        $input0 = "";
        $input16 = hex2bin("6bc1bee22e409f96e93d7e117393172a");
        $input40 = hex2bin(
            "6bc1bee22e409f96e93d7e117393172a" .
                "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"
        );
        $input64 = hex2bin(
            "6bc1bee22e409f96e93d7e117393172a" .
                "ae2d8a571e03ac9c9eb76fac45af8e51" .
                "30c81c46a35ce411e5fbc1191a0a52ef" .
                "f69f2445df4f9b17ad2b417be66c3710"
        );

        $key128 = hex2bin("2b7e151628aed2a6abf7158809cf4f3c");
        $key192 = hex2bin("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        $key256 = hex2bin(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
        );

        $cmac = new CMac(SymmetricAlgorithm::Aes128);

        /// 128 bits test
        $output = $cmac->generate($input0, $key128);
        $this->assertSame("bb1d6929e95937287fa37d129b756746", bin2hex($output));

        $output = $cmac->generate($input16, $key128);
        $this->assertSame("070a16b46b4d4144f79bdd9dd04a287c", bin2hex($output));

        $output = $cmac->generate($input40, $key128);
        $this->assertSame("dfa66747de9ae63030ca32611497c827", bin2hex($output));

        $output = $cmac->generate($input64, $key128);
        $this->assertSame("51f0bebf7e3b9d92fc49741779363cfe", bin2hex($output));

        /// 192 bits test
        $output = $cmac->generate($input0, $key192);
        $this->assertSame("d17ddf46adaacde531cac483de7a9367", bin2hex($output));

        $output = $cmac->generate($input16, $key192);
        $this->assertSame("9e99a7bf31e710900662f65e617c5184", bin2hex($output));

        $output = $cmac->generate($input40, $key192);
        $this->assertSame("8a1de5be2eb31aad089a82e6ee908b0e", bin2hex($output));

        $output = $cmac->generate($input64, $key192);
        $this->assertSame("a1d5df0eed790f794d77589659f39a11", bin2hex($output));

        /// 256 bits test
        $output = $cmac->generate($input0, $key256);
        $this->assertSame("028962f61b7bf89efc6b551f4667d983", bin2hex($output));

        $output = $cmac->generate($input16, $key256);
        $this->assertSame("28a7023f452e8f82bd4bf28d8c37c35c", bin2hex($output));

        $output = $cmac->generate($input40, $key256);
        $this->assertSame("aaf3d8f1de5640c232f5b169b9c911e6", bin2hex($output));

        $output = $cmac->generate($input64, $key256);
        $this->assertSame("e1992190549f6ed5696a2c056c315410", bin2hex($output));
    }
}
