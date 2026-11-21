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
        $ct = $gcm->encrypt($plaintext, $nonce, $adata);
        $pt = $gcm->decrypt($ct, $nonce, $adata);
        $this->assertSame(bin2hex($pt), bin2hex($plaintext));
    }

    public function testAesGcmRejectsModifiedInput()
    {
        $plaintext = Random::string(40);
        $nonce = Random::string(12);
        $adata = Random::string(10);

        $gcm = new GCM(Random::string(16));
        $ct = $gcm->encrypt($plaintext, $nonce, $adata);

        $cases = [
            "Modified cipher text was accepted." => [
                substr_replace($ct, chr(ord($ct[0]) ^ 1), 0, 1),
                $adata,
            ],
            "Modified tag was accepted." => [
                substr_replace($ct, chr(ord($ct[-1]) ^ 1), -1),
                $adata,
            ],
            "Modified associated data was accepted." => [$ct, $adata . "x"],
        ];
        foreach ($cases as $message => [$modified, $aData]) {
            $error = null;
            try {
                $gcm->decrypt($modified, $nonce, $aData);
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
            $this->assertSame("Authentication tag mismatch!", $error, $message);
        }
    }
}
