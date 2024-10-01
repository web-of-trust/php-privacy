<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\EAX;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for EAX.
 */
class EAXTest extends OpenPGPTestCase
{
    /**
     * Test vectors
     *
     * From http://www.cs.ucdavis.edu/~rogaway/papers/eax.pdf
     */
    private static array $testVectors = [
        [
            "msg" => "",
            "key" => "233952dee4d5ed5f9b9c6d6ff80ff478",
            "nonce" => "62ec67f9c3a4a407fcb2a8c49031a8b3",
            "header" => "6bfb914fd07eae6b",
            "cipher" => "e037830e8389f27b025a2d6527e79d01",
        ],
        [
            "msg" => "f7fb",
            "key" => "91945d3f4dcbee0bf45ef52255f095a4",
            "nonce" => "becaf043b0a23d843194ba972c66debd",
            "header" => "fa3bfd4806eb53fa",
            "cipher" => "19dd5c4c9331049d0bdab0277408f67967e5",
        ],
        [
            "msg" => "1a47cb4933",
            "key" => "01f74ad64077f2e704c0f60ada3dd523",
            "nonce" => "70c3db4f0d26368400a10ed05d2bff5e",
            "header" => "234a3463c1264ac6",
            "cipher" => "d851d5bae03a59f238a23e39199dc9266626c40f80",
        ],
        [
            "msg" => "481c9e39b1",
            "key" => "d07cf6cbb7f313bdde66b727afd3c5e8",
            "nonce" => "8408dfff3c1a2b1292dc199e46b7d617",
            "header" => "33cce2eabff5a79d",
            "cipher" => "632a9d131ad4c168a4225d8e1ff755939974a7bede",
        ],
        [
            "msg" => "40d0c07da5e4",
            "key" => "35b6d0580005bbc12b0587124557d2c2",
            "nonce" => "fdb6b06676eedc5c61d74276e1f8e816",
            "header" => "aeb96eaebe2970e9",
            "cipher" => "071dfe16c675cb0677e536f73afe6a14b74ee49844dd",
        ],
        [
            "msg" => "4de3b35c3fc039245bd1fb7d",
            "key" => "bd8e6e11475e60b268784c38c62feb22",
            "nonce" => "6eac5c93072d8e8513f750935e46da1b",
            "header" => "d4482d1ca78dce0f",
            "cipher" =>
                "835bb4f15d743e350e728414abb8644fd6ccb86947c5e10590210a4f",
        ],
        [
            "msg" => "8b0a79306c9ce7ed99dae4f87f8dd61636",
            "key" => "7c77d6e813bed5ac98baa417477a2e7d",
            "nonce" => "1a8c98dcd73d38393b2bf1569deefc19",
            "header" => "65d2017990d62528",
            "cipher" =>
                "02083e3979da014812f59f11d52630da30137327d10649b0aa6e1c181db617d7f2",
        ],
        [
            "msg" => "1bda122bce8a8dbaf1877d962b8592dd2d56",
            "key" => "5fff20cafab119ca2fc73549e20f5b0d",
            "nonce" => "dde59b97d722156d4d9aff2bc7559826",
            "header" => "54b9f04e6a09189a",
            "cipher" =>
                "2ec47b2c4954a489afc7ba4897edcdae8cc33b60450599bd02c96382902aef7f832a",
        ],
        [
            "msg" => "6cf36720872b8513f6eab1a8a44438d5ef11",
            "key" => "a4a4782bcffd3ec5e7ef6d8c34a56123",
            "nonce" => "b781fcf2f75fa5a8de97a9ca48e522ec",
            "header" => "899a175897561d7e",
            "cipher" =>
                "0de18fd0fdd91e7af19f1d8ee8733938b1e8e7f6d2231618102fdb7fe55ff1991700",
        ],
        [
            "msg" => "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
            "key" => "8395fcf1e95bebd697bd010bc766aac3",
            "nonce" => "22e7add93cfc6393c57ec0b3c17d6b44",
            "header" => "126735fcc320d25a",
            "cipher" =>
                "cb8920f87a6c75cff39627b56e3ed197c552d295a7cfc46afc253b4652b1af3795b124ab6e",
        ],
    ];

    public function testAesEax()
    {
        foreach (self::$testVectors as $vector) {
            $msg = hex2bin($vector["msg"]);
            $key = hex2bin($vector["key"]);
            $nonce = hex2bin($vector["nonce"]);
            $header = hex2bin($vector["header"]);
            $cipher = hex2bin($vector["cipher"]);

            $eax = new EAX($key);

            // encryption test
            $ct = $eax->encrypt($msg, $nonce, $header);
            $this->assertSame(bin2hex($ct), bin2hex($cipher));

            // decryption test with verification
            $pt = $eax->decrypt($cipher, $nonce, $header);
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // testing without additional data
            $ct = $eax->encrypt($msg, $nonce);
            $pt = $eax->decrypt($ct, $nonce);
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // testing with multiple additional data
            $ct = $eax->encrypt(
                $msg,
                $nonce,
                implode([$header, $header, $header])
            );
            $pt = $eax->decrypt(
                $ct,
                $nonce,
                implode([$header, $header, $header])
            );
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // tampering detection test
            $ct = $eax->encrypt($msg, $nonce, $header);
            $ct[2] = $ct[2] ^ "\x8";
            $this->expectException(\RuntimeException::class);
            $eax->decrypt($ct, $nonce, $header);
        }
    }
}
