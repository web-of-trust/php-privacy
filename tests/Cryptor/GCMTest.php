<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\GCM;
use OpenPGP\Tests\OpenPGPTestCase;
use phpseclib3\Crypt\Random;

/**
 * Testcase class for GCM.
 */
class GCMTest extends OpenPGPTestCase
{
    public function testAesGcm()
    {
        $plaintext = Random::string(40);
        $nonce = Random::string(12);
        $adata = Random::string(10);

        $gcm = new GCM(Random::string(16));
        $ct = $gcm->encrypt(
            $plaintext,
            $nonce,
            $adata
        );
        $pt = $gcm->encrypt(
            $ct,
            $nonce,
            $adata
        );
        $this->assertSame(bin2hex($pt), bin2hex($plaintext));
    }
}
