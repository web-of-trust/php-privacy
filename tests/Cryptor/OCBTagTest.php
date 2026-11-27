<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\OCB;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the authentication tag of OCB.
 */
class OCBTagTest extends OpenPGPTestCase
{
    public function testTagIsChecked()
    {
        $ocb = new OCB(str_repeat("k", 32));
        $nonce = str_repeat("n", 15);
        $cipherText = $ocb->encrypt("Hello", $nonce, "data");
        $this->assertSame("Hello", $ocb->decrypt($cipherText, $nonce, "data"));

        $last = strlen($cipherText) - 1;
        foreach (
            [
                "last octet of the tag" => $last,
                "first octet of the tag" => $last - 15,
                "first octet of the cipher text" => 0,
            ]
            as $case => $position
        ) {
            $changed = $cipherText;
            $changed[$position] = chr(ord($changed[$position]) ^ 0x01);
            $error = "";
            try {
                $ocb->decrypt($changed, $nonce, "data");
            } catch (\RuntimeException $e) {
                $error = $e->getMessage();
            }
            $this->assertSame("Authentication tag mismatch!", $error, $case);
        }
    }
}
