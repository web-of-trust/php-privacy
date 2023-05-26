<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Symmetric;

use phpseclib3\Crypt\Common\BlockCipher;
use phpseclib3\Exception\BadModeException;
use OpenPGP\Common\Helper;

/**
 * IDEA class
 * 
 * A class that provides a basic International Data Encryption Algorithm (IDEA) engine.
 * 
 * This implementation is based on the "HOWTO: INTERNATIONAL DATA ENCRYPTION ALGORITHM"
 * implementation summary by Fauzan Mirza (F.U.Mirza@sheffield.ac.uk). (barring 1 typo at the
 * end of the MulInv function!).
 * 
 * It can be found at ftp://ftp.funet.fi/pub/crypt/cryptography/symmetric/idea/
 * Note: This algorithm was patented in the USA, Japan and Europe. These patents expired in 2011/2012.
 *
 * @package    OpenPGP
 * @category   Cryptor
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
class IDEA extends BlockCipher
{
    const MASK = 0xffff;
    const BASE = 0x10001;

    const BLOCK_SIZE = 8;
    const KEY_SIZE   = 52;

    /**
     * Constructor
     *
     * @param string $mode
     * @return self
     */
    public function __construct(string $mode)
    {
        parent::__construct($mode);
        if ($this->mode == self::MODE_STREAM) {
            throw new BadModeException('Block ciphers cannot be ran in stream mode');
        }
        $this->block_size = self::BLOCK_SIZE;
    }

    /**
     * {@inheritdoc}
     */
    protected function encryptBlock($input)
    {
        return self::ideaFunc(
            self::generateWorkingKey(true, $this->key), $input
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function decryptBlock($input)
    {
        return self::ideaFunc(
            self::generateWorkingKey(false, $this->key), $input
        );
    }

    /**
     * {@inheritdoc}
     */
    protected function setupKey()
    {
    }

    private static function wordToBytes(int $word, string $bytes, int $offset = 0): string
    {
        $replace = pack('n', $word);
        return substr_replace($bytes, $replace, $offset, strlen($replace));
    }

    private static function mul(int $x, int $y)
    {
        if ($x == 0) {
            $x = (self::BASE - $y);
        }
        elseif ($y == 0) {
            $x = (self::BASE - $x);
        }
        else {
            $p = $x * $y;
            $y = $p & self::MASK;
            $x = $p >> 16;
            $x = $y - $x + (($y < $x) ? 1 : 0);
        }
        return $x & self::MASK;
    }

    private static function ideaFunc(
        array $workingKey, string $input
    ): string
    {
        $keyOff = 0;
        $x0 = Helper::bytesToShort($input, 0);
        $x1 = Helper::bytesToShort($input, 2);
        $x2 = Helper::bytesToShort($input, 4);
        $x3 = Helper::bytesToShort($input, 6);

        for ($round = 0; $round < 8; $round++) {
            $x0 = self::mul($x0, $workingKey[$keyOff++]);
            $x1 += $workingKey[$keyOff++];
            $x1 &= self::MASK;
            $x2 += $workingKey[$keyOff++];
            $x2 &= self::MASK;
            $x3 = self::mul($x3, $workingKey[$keyOff++]);
            $t0 = $x1;
            $t1 = $x2;
            $x2 ^= $x0;
            $x1 ^= $x3;
            $x2 = self::mul($x2, $workingKey[$keyOff++]);
            $x1 += $x2;
            $x1 &= self::MASK;
            $x1 = self::mul($x1, $workingKey[$keyOff++]);
            $x2 += $x1;
            $x2 &= self::MASK;
            $x0 ^= $x1;
            $x3 ^= $x2;
            $x1 ^= $t1;
            $x2 ^= $t0;
        }

        $output = str_repeat("\x00", self::BLOCK_SIZE);
        $output = self::wordToBytes(self::mul($x0, $workingKey[$keyOff++]), $output, 0);
        $output = self::wordToBytes($x2 + $workingKey[$keyOff++], $output, 2);
        $output = self::wordToBytes($x1 + $workingKey[$keyOff++], $output, 4);
        $output = self::wordToBytes(self::mul($x3, $workingKey[$keyOff]), $output, 6);

        return $output;
    }

    /**
     * The following function is used to expand the user key to the encryption
     * subkey. The first 16 bytes are the user key, and the rest of the subkey
     * is calculated by rotating the previous 16 bytes by 25 bits to the left,
     * and so on until the subkey is completed.
     *
     * @param string $inKey
     * @return array
     */
    private static function expandKey(string $inKey): array
    {
        $key = array_fill(0, self::KEY_SIZE, 0);
        if (strlen($inKey) < 16) {
            $tmp = str_repeat("\x00", 16);
            $inKey = substr_replace($tmp, $inKey, 0, strlen($inKey));
        }

        for ($i = 0; $i < 8; $i++) {
            $key[$i] = Helper::bytesToShort($inKey, $i * 2);
        }

        for ($i = 8; $i < self::KEY_SIZE; $i++) {
            if (($i & 7) < 6) {
                $key[$i] = (($key[$i - 7] & 127) << 9 | $key[$i - 6] >> 7) & self::MASK;
            }
            elseif (($i & 7) == 6) {
                $key[$i] = (($key[$i - 7] & 127) << 9 | $key[$i - 14] >> 7) & self::MASK;
            }
            else {
                $key[$i] = (($key[$i - 15] & 127) << 9 | $key[$i - 14] >> 7) & self::MASK;
            }
        }
        return $key;
    }

    /**
     * This function computes multiplicative inverse using Euclid's Greatest
     * Common Divisor algorithm. Zero and one are self inverse.
     * i.e. x * mulInv(x) == 1 (modulo BASE)
     *
     * @param int $x
     * @return int
     */
    private static function mulInv(int $x): int
    {
        if ($x < 2) {
            return $x;
        }
        $t0 = 1;
        $t1 = intval(self::BASE / $x);
        $y  = intval(self::BASE % $x);
        while ($y != 1) {
            $q = intval($x / $y);
            $x = intval($x % $y);
            $t0 = ($t0 + ($t1 * $q)) & self::MASK;
            if ($x == 1) {
                return $t0;
            }
            $q = intval($y / $x);
            $y = intval($y % $x);
            $t1 = ($t1 + ($t0 * $q)) & self::MASK;
        }
        return (1 - $t1) & self::MASK;
    }

    /**
     * Return the additive inverse of x.
     * i.e. x + addInv(x) == 0
     *
     * @param int $x
     * @return int
     */
    private static function addInv(int $x): int
    {
        return (0 - $x) & self::MASK;
    }

    /**
     * The function to invert the encryption subkey to the decryption subkey.
     * It also involves the multiplicative inverse and the additive inverse functions.
     *
     * @param array $inKey
     * @return array
     */
    private static function invertKey(array $inKey): array
    {
        $p = self::KEY_SIZE;
        $key = array_fill(0, self::KEY_SIZE, 0);
        $offset = 0;

        $t1 = self::mulInv($inKey[$offset++]);
        $t2 = self::addInv($inKey[$offset++]);
        $t3 = self::addInv($inKey[$offset++]);
        $t4 = self::mulInv($inKey[$offset++]);
        $key[--$p] = $t4;
        $key[--$p] = $t3;
        $key[--$p] = $t2;
        $key[--$p] = $t1;

        for ($round = 1; $round < 8; $round++) {
            $t1 = $inKey[$offset++];
            $t2 = $inKey[$offset++];
            $key[--$p] = $t2;
            $key[--$p] = $t1;

            $t1 = self::mulInv($inKey[$offset++]);
            $t2 = self::addInv($inKey[$offset++]);
            $t3 = self::addInv($inKey[$offset++]);
            $t4 = self::mulInv($inKey[$offset++]);
            $key[--$p] = $t4;
            $key[--$p] = $t2;
            $key[--$p] = $t3;
            $key[--$p] = $t1;
        }
        $t1 = $inKey[$offset++];
        $t2 = $inKey[$offset++];
        $key[--$p] = $t2;
        $key[--$p] = $t1;

        $t1 = self::mulInv($inKey[$offset++]);
        $t2 = self::addInv($inKey[$offset++]);
        $t3 = self::addInv($inKey[$offset++]);
        $t4 = self::mulInv($inKey[$offset]);
        $key[--$p] = $t4;
        $key[--$p] = $t3;
        $key[--$p] = $t2;
        $key[--$p] = $t1;

        return $key;
    }

    private static function generateWorkingKey(bool $forEncryption, string $key): array
    {
        if ($forEncryption) {
            return self::expandKey($key);
        }
        else {
            return self::invertKey(self::expandKey($key));
        }
    }
}
