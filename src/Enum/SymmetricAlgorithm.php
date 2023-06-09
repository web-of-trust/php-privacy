<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib3\Crypt\Common\BlockCipher;

/**
 * Symmetric algorithm enum
 * See https://tools.ietf.org/html/rfc4880#section-9.2
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum SymmetricAlgorithm: int
{
    case Plaintext = 0;

    case Idea = 1;

    case TripleDes = 2;

    case Cast5 = 3;

    case Blowfish = 4;

    case Aes128 = 7;

    case Aes192 = 8;

    case Aes256 = 9;

    case Twofish = 10;

    case Camellia128 = 11;

    case Camellia192 = 12;

    case Camellia256 = 13;

    /**
     * Gets key size
     *
     * @return int
     */
    public function keySize(): int
    {
        return match($this) {
            self::Plaintext => 0,
            self::Aes128,
            self::Blowfish,
            self::Camellia128,
            self::Cast5,
            self::Idea
                => 128,
            self::Aes192,
            self::Camellia192,
            self::TripleDes
                => 192,
            self::Aes256,
            self::Camellia256,
            self::Twofish
                => 256,
        };
    }

    /**
     * Gets key size in byte
     *
     * @return int
     */
    public function keySizeInByte(): int
    {
        return ($this->keySize() + 7) >> 3;
    }

    /**
     * Gets block size
     *
     * @return int
     */
    public function blockSize(): int
    {
        return match($this) {
            self::Plaintext => 0,
            self::Idea,
            self::TripleDes,
            self::Cast5
                => 8,
            self::Blowfish,
            self::Aes128,
            self::Aes192,
            self::Aes256,
            self::Twofish,
            self::Camellia128,
            self::Camellia192,
            self::Camellia256
                => 16,
        };
    }

    /**
     * Gets block cipher engine
     *
     * @return BlockCipher
     */
    public function cipherEngine(): BlockCipher
    {
        return match($this) {
            self::Plaintext => throw new \RuntimeException(
                'Symmetric algorithm "Plaintext" is unsupported.'
            ),
            self::Idea => new \OpenPGP\Cryptor\Symmetric\IDEA('cfb'),
            self::TripleDes => new \phpseclib3\Crypt\TripleDES('cfb'),
            self::Cast5 => new \OpenPGP\Cryptor\Symmetric\CAST5('cfb'),
            self::Blowfish => new \phpseclib3\Crypt\Blowfish('cfb'),
            self::Aes128, self::Aes192, self::Aes256
                => new \phpseclib3\Crypt\AES('cfb'),
            self::Twofish => new \phpseclib3\Crypt\Twofish('cfb'),
            self::Camellia128, self::Camellia192, self::Camellia256
                => new \OpenPGP\Cryptor\Symmetric\Camellia('cfb'),
        };
    }
}
