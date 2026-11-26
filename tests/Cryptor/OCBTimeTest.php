<?php declare(strict_types=1);

namespace OpenPGP\Tests\Cryptor;

use OpenPGP\Cryptor\Aead\OCB;
use OpenPGP\Tests\OpenPGPTestCase;

/**
 * Testcase class for the time OCB takes on long input.
 */
class OCBTimeTest extends OpenPGPTestCase
{
    public function testDecryptTimeGrowsLinearly()
    {
        $ocb = new OCB(str_repeat("k", 32));
        $nonce = str_repeat("n", 15);
        $time = static function (int $length) use ($ocb, $nonce): float {
            $plainText = str_repeat("0123456789abcdef", $length >> 4);
            $cipherText = $ocb->encrypt($plainText, $nonce);
            $start = hrtime(true);
            $decrypted = $ocb->decrypt($cipherText, $nonce);
            $time = (hrtime(true) - $start) / 1e9;
            if ($decrypted !== $plainText) {
                throw new \RuntimeException("Round trip failed.");
            }
            return $time;
        };
        $time(4096);
        $small = $time(131072);
        $large = $time(524288);
        // Four times the input; linear time gives a factor of about 4.
        $this->assertLessThan(
            8.0,
            $large / $small,
            sprintf("%.3f s for 128 KiB, %.3f s for 512 KiB.", $small, $large)
        );
    }
}
