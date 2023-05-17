<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Cryptor\Asymmetric;

use phpseclib3\Crypt\Common\BlockCipher;

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

    private string $workingKey = '';

    private bool $forEncryption = true;

    /**
     * Constructor
     *
     * @return self
     */
    public function __construct()
    {
    }

    public function Init(bool $forEncryption, string $key): self
    {
        $this->forEncryption = $forEncryption;
        return $this->setKey($key);
    }

    public function setKey(string $key): self
    {
        $this->workingKey = self::generateWorkingKey($this->forEncryption, $key);
        return $this;
    }

    private static function bytesToWord(string $bytes, int $offset): int
    {
        return ((ord($bytes[$offset]) << 8) & 0xff00) + (ord($bytes[$offset + 1]) & 0xff);
    }

    private static function wordToBytes(int $word, string $bytes, int $offset): string
    {
        $bytes[$offset] = chr(($word >> 8) & 0xff);
        $bytes[$offset + 1] = chr($word & 0xff);
        return $bytes;
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
        string $workingKey, string $input, int $inOff, string $output, int $outOff
    ): string
    {
        $keyOff = 0;
        $x0 = self::bytesToWord($input, $inOff);
        $x1 = self::bytesToWord($input, $inOff + 2);
        $x2 = self::bytesToWord($input, $inOff + 4);
        $x3 = self::bytesToWord($input, $inOff + 6);

        for ($round = 0; $round < 8; $round++) {
            $x0 = self::mul($x0, ord($workingKey[$keyOff++]));
            $x1 += $workingKey[$keyOff++];
            $x1 &= self::MASK;
            $x2 += $workingKey[$keyOff++];
            $x2 &= self::MASK;
            $x3 = self::mul($x3, ord($workingKey[$keyOff++]));
            $t0 = $x1;
            $t1 = $x2;
            $x2 ^= $x0;
            $x1 ^= $x3;
            $x2 = self::mul($x2, ord($workingKey[$keyOff++]));
            $x1 += $x2;
            $x1 &= self::MASK;
            $x1 = self::mul($x1, ord($workingKey[$keyOff++]));
            $x2 += $x1;
            $x2 &= self::MASK;
            $x0 ^= $x1;
            $x3 ^= $x2;
            $x1 ^= $t1;
            $x2 ^= $t0;
        }

        $output = self::wordToBytes(self::mul($x0, ord($workingKey[$keyOff++])), $output, $outOff);
        $output = self::wordToBytes($x2 + ord($workingKey[$keyOff++]), $output, $outOff + 2);
        $output = self::wordToBytes($x1 + ord($workingKey[$keyOff++]), $output, $outOff + 4);
        $output = self::wordToBytes(self::mul($x3, ord($workingKey[$keyOff])), $output, $outOff + 6);

        return $output;
    }

    /**
     * The following function is used to expand the user key to the encryption
     * subkey. The first 16 bytes are the user key, and the rest of the subkey
     * is calculated by rotating the previous 16 bytes by 25 bits to the left,
     * and so on until the subkey is completed.
     *
     * @param string $uKey
     * @return string
     */
    private static function expandKey(string $uKey): string
    {
        $key = str_repeat("\x00", self::KEY_SIZE);
        if (strlen($uKey) < 16) {
            $tmp = str_repeat("\x00", 16);
            $uKey = substr_replace($tmp, $uKey, 0, strlen($uKey));
        }

        for ($i = 0; $i < 8; $i++) {
            $key[$i] = self::bytesToWord($uKey, $i * 2);
        }

        for ($i = 8; $i < self::KEY_SIZE; $i++) {
            if (($i & 7) < 6) {
                $key[$i] = chr(((ord($key[$i - 7]) & 127) << 9 | ord($key[$i - 6]) >> 7) & self::MASK);
            }
            elseif (($i & 7) == 6) {
                $key[$i] = chr(((ord($key[$i - 7]) & 127) << 9 | ord($key[$i - 14]) >> 7) & self::MASK);
            }
            else {
                $key[$i] = chr(((ord($key[$i - 15]) & 127) << 9 | ord($key[$i - 14]) >> 7) & self::MASK);
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
            $q = intval($y /$ $x);
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
     * @param string $inKey
     * @return string
     */
    private static function invertKey(string $inKey): string
    {
        $p = self::KEY_SIZE;
        $key = str_repeat("\x00", self::KEY_SIZE);
        $inOff = 0;

        $t1 = self::mulInv(ord($inKey[$inOff++]));
        $t2 = self::addInv(ord($inKey[$inOff++]));
        $t3 = self::addInv(ord($inKey[$inOff++]));
        $t4 = self::mulInv(ord($inKey[$inOff++]));
        $key[--$p] = chr($t4);
        $key[--$p] = chr($t3);
        $key[--$p] = chr($t2);
        $key[--$p] = chr($t1);

        for ($round = 1; $round < 8; $round++) {
            $t1 = $inKey[$inOff++];
            $t2 = $inKey[$inOff++];
            $key[--$p] = $t2;
            $key[--$p] = $t1;

            $t1 = self::mulInv(ord($inKey[$inOff++]));
            $t2 = self::addInv(ord($inKey[$inOff++]));
            $t3 = self::addInv(ord($inKey[$inOff++]));
            $t4 = self::mulInv(ord($inKey[$inOff++]));
            $key[--$p] = chr($t4);
            $key[--$p] = chr($t2);
            $key[--$p] = chr($t3);
            $key[--$p] = chr($t1);
        }
        $t1 = $inKey[$inOff++];
        $t2 = $inKey[$inOff++];
        $key[--$p] = $t2;
        $key[--$p] = $t1;

        $t1 = self::mulInv(ord($inKey[$inOff++]));
        $t2 = self::addInv(ord($inKey[$inOff++]));
        $t3 = self::addInv(ord($inKey[$inOff++]));
        $t4 = self::mulInv(ord($inKey[$inOff]));
        $key[--$p] = $t4;
        $key[--$p] = $t3;
        $key[--$p] = $t2;
        $key[--$p] = $t1;

        return $key;
    }

    private static function generateWorkingKey(bool $forEncryption, string $userKey): string
    {
        if ($forEncryption) {
            return self::expandKey($userKey);
        }
        else {
            return self::invertKey(self::expandKey($userKey));
        }
    }
}
