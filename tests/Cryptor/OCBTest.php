<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\OCB;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for OCB.
 */
class OCBTest extends OpenPGPTestCase
{
    private static string $key = '000102030405060708090a0b0c0d0e0f';

    /**
     * Test vectors
     * 
     * From https://tools.ietf.org/html/rfc7253#appendix-A
     */
    private static array $testVectors = [
        [
            'N' => 'bbaa99887766554433221100',
            'A' => '',
            'P' => '',
            'C' => '785407bfffc8ad9edcc5520ac9111ee6',
        ],
        [
            'N' => 'bbaa99887766554433221101',
            'A' => '0001020304050607',
            'P' => '0001020304050607',
            'C' => '6820b3657b6f615a5725bda0d3b4eb3a257c9af1f8f03009',
        ],
        [
            'N' => 'bbaa99887766554433221102',
            'A' => '0001020304050607',
            'P' => '',
            'C' => '81017f8203f081277152fade694a0a00',
        ],
        [
            'N' => 'bbaa99887766554433221103',
            'A' => '',
            'P' => '0001020304050607',
            'C' => '45dd69f8f5aae72414054cd1f35d82760b2cd00d2f99bfa9',
        ],
        [
            'N' => 'bbaa99887766554433221104',
            'A' => '000102030405060708090a0b0c0d0e0f',
            'P' => '000102030405060708090a0b0c0d0e0f',
            'C' => '571d535b60b277188be5147170a9a22c3ad7a4ff3835b8c5701c1ccec8fc3358',
        ],
        [
            'N' => 'bbaa99887766554433221105',
            'A' => '000102030405060708090a0b0c0d0e0f',
            'P' => '',
            'C' => '8cf761b6902ef764462ad86498ca6b97',
        ],
        [
            'N' => 'bbaa99887766554433221106',
            'A' => '',
            'P' => '000102030405060708090a0b0c0d0e0f',
            'C' => '5ce88ec2e0692706a915c00aeb8b2396f40e1c743f52436bdf06d8fa1eca343d',
        ],
        [
            'N' => 'bbaa99887766554433221107',
            'A' => '000102030405060708090a0b0c0d0e0f1011121314151617',
            'P' => '000102030405060708090a0b0c0d0e0f1011121314151617',
            'C' => '1ca2207308c87c010756104d8840ce1952f09673a448a122c92c62241051f57356d7f3c90bb0e07f',
        ],
        [
            'N' => 'bbaa99887766554433221108',
            'A' => '000102030405060708090a0b0c0d0e0f1011121314151617',
            'P' => '',
            'C' => '6dc225a071fc1b9f7c69f93b0f1e10de',
        ],
        [
            'N' => 'bbaa99887766554433221109',
            'A' => '',
            'P' => '000102030405060708090a0b0c0d0e0f1011121314151617',
            'C' => '221bd0de7fa6fe993eccd769460a0af2d6cded0c395b1c3ce725f32494b9f914d85c0b1eb38357ff',
        ],
        [
            'N' => 'bbaa9988776655443322110a',
            'A' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'P' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'C' => 'bd6f6c496201c69296c11efd138a467abd3c707924b964deaffc40319af5a48540fbba186c5553c68ad9f592a79a4240',
        ],
        [
            'N' => 'bbaa9988776655443322110b',
            'A' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'P' => '',
            'C' => 'fe80690bee8a485d11f32965bc9d2a32',
        ],
        [
            'N' => 'bbaa9988776655443322110c',
            'A' => '',
            'P' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
            'C' => '2942bfc773bda23cabc6acfd9bfd5835bd300f0973792ef46040c53f1432bcdfb5e1dde3bc18a5f840b52e653444d5df',
        ],
        [
            'N' => 'bbaa9988776655443322110d',
            'A' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
            'P' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
            'C' => 'd5ca91748410c1751ff8a2f618255b68a0a12e093ff454606e59f9c1d0ddc54b65e8628e568bad7aed07ba06a4a69483a7035490c5769e60',
        ],
        [
            'N' => 'bbaa9988776655443322110e',
            'A' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
            'P' => '',
            'C' => 'c5cd9d1850c141e358649994ee701b68',
        ],
        [
            'N' => 'bbaa9988776655443322110f',
            'A' => '',
            'P' => '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252627',
            'C' => '4412923493c57d5de0d700f753cce0d1d2d95060122e9f15a5ddbfc5787e50b5cc55ee507bcb084e479ad363ac366b95a98ca5f3000b1479',
        ],
    ];

    public function testAesOcb()
    {
        $key = hex2bin(self::$key);
        $ocb = new OCB($key);

        foreach (self::$testVectors as $vector) {
            $msg = hex2bin($vector['P']);
            $nonce = hex2bin($vector['N']);
            $header = hex2bin($vector['A']);
            $cipher = hex2bin($vector['C']);

            // encryption test
            $ct = $ocb->encrypt($msg, $nonce, $header);
            $this->assertSame(bin2hex($ct), bin2hex($cipher));

            // decryption test with verification
            $pt = $ocb->decrypt($cipher, $nonce, $header);
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // testing without additional data
            $ct = $ocb->encrypt($msg, $nonce);
            $pt = $ocb->decrypt($ct, $nonce);
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // testing with multiple additional data
            $ct = $ocb->encrypt($msg, $nonce, implode([$header, $header, $header]));
            $pt = $ocb->decrypt($ct, $nonce, implode([$header, $header, $header]));
            $this->assertSame(bin2hex($pt), bin2hex($msg));

            // tampering detection test
            $ct = $ocb->encrypt($msg, $nonce, $header);
            $ct[2] = $ct[2] & "\x8";
            $this->expectException(\RuntimeException::class);
            $ocb->decrypt($ct, $nonce, $header);
        }
    }
}
