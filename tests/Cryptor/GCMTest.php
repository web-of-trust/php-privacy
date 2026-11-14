<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\GCM;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for GCM.
 */
class GCMTest extends OpenPGPTestCase
{
    public function testAesGcm()
    {
        $plaintext = random_bytes(40);
        $nonce = random_bytes(12);
        $adata = random_bytes(10);

        $gcm = new GCM(random_bytes(16));
        $ct = $gcm->encrypt($plaintext, $nonce, $adata);
        $pt = $gcm->decrypt($ct, $nonce, $adata);
        $this->assertSame(bin2hex($pt), bin2hex($plaintext));
    }
}
