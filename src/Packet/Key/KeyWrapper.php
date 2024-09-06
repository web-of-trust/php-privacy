<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet\Key;

use OpenPGP\Enum\KekSize;
use phpseclib3\Crypt\Common\BlockCipher;

/**
 * KeyWrapper class
 * 
 * An implementation of the key wrapper based on RFC 3394.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
abstract class KeyWrapper
{
    const IV = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";

    /**
     * Constructor
     *
     * @param BlockCipher $cipher
     * @param KekSize $kekSize
     * @return self
     */
    protected function __construct(
        private readonly BlockCipher $cipher,
        private readonly KekSize $kekSize
    )
    {
        $this->cipher->disablePadding();
    }

    /**
     * Wrap the key
     *
     * @param string $kek
     * @param string $key
     * @return string
     */
    public function wrap(string $kek, string $key): string
    {
        $this->validateKeySize($kek, $key);
        $this->cipher->setKey($kek);

        $a = self::IV;
        $r = $key;
        $n = intval(strlen($key) / 8);
        for ($j = 0; $j <= 5; $j++) {
            for ($i = 1; $i <= $n; $i++) { 
                $buffer = implode([
                    $a,
                    substr($r, ($i - 1) * 8, 8),
                ]);
                $buffer = $this->cipher->encrypt($buffer);

                $a = substr($buffer, 0, 8);
                $a[7] = chr(ord($a[7]) ^ ($n * $j + $i) & 0xff);

                $r = substr_replace(
                    $r, substr($buffer, 8, 8), ($i - 1) * 8, 8
                );
            }
        }
        return implode([$a, $r]);
    }

    /**
     * Unwrap the key
     *
     * @param string $kek
     * @param string $wrappedKey
     * @return string
     */
    public function unwrap(string $kek, string $wrappedKey): string
    {
        $this->validateKeySize($kek, $wrappedKey);
        $this->cipher->setKey($kek);

        $a = substr($wrappedKey, 0, 8);
        $r = substr($wrappedKey, 8);
        $n = intval(strlen($wrappedKey) / 8) - 1;
        for ($j = 5; $j >= 0; $j--) {
            for ($i = $n; $i >= 1; $i--) {
                $a[7] = chr(ord($a[7]) ^ ($n * $j + $i) & 0xff);
                $buffer = implode([
                    $a,
                    substr($r, ($i - 1) * 8, 8),
                ]);
                $buffer = $this->cipher->decrypt($buffer);

                $a = substr($buffer, 0, 8);
                $r = substr_replace(
                    $r, substr($buffer, 8, 8), ($i - 1) * 8, 8
                );
            }
        }

        if (strcmp(self::IV, $a) !== 0) {
            throw new \UnexpectedValueException(
                'Integrity check failed.'
            );
        }

        return $r;
    }

    private function validateKeySize(string $kek, string $key): void
    {
        if (strlen($kek) !== $this->kekSize->value) {
            throw new \LengthException(
                "Key encryption key size must be {$this->kekSize->value} bytes."
            );
        }
        if (strlen($key) < KekSize::Normal->value) {
            throw new \LengthException(
                'Key length must be at least ' . KekSize::Normal->value . ' octets.'
            );
        }
        if (strlen($key) % 8 !== 0) {
            throw new \LengthException(
                'Key length must be a multiple of 64 bits.'
            );
        }
    }
}
