<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use OpenPGP\Cryptor\Symmetric\EcbCipherTrait;
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
    /**
     * Plaintext or unencrypted data
     */
    case Plaintext = 0;

    /**
     * IDEA
     */
    case Idea = 1;

    /**
     * TripleDES (or DES-EDE) with 168-bit key derived from 192
     */
    case TripleDes = 2;

    /**
     * CAST5 with 128-bit key
     */
    case Cast5 = 3;

    /**
     * Blowfish with 128-bit key, 16 rounds
     */
    case Blowfish = 4;

    /**
     * AES with 256-bit key
     */
    case Aes128 = 7;

    /**
     * AES with 256-bit key
     */
    case Aes192 = 8;

    /**
     * AES with 256-bit key
     */
    case Aes256 = 9;

    /**
     * Twofish with 256-bit key
     */
    case Twofish = 10;

    /**
     * Camellia with 128-bit key
     */
    case Camellia128 = 11;

    /**
     * Camellia with 192-bit key
     */
    case Camellia192 = 12;

    /**
     * Camellia with 256-bit key
     */
    case Camellia256 = 13;

    /**
     * Get key size
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
     * Get key size in byte
     *
     * @return int
     */
    public function keySizeInByte(): int
    {
        return ($this->keySize() + 7) >> 3;
    }

    /**
     * Get block size
     *
     * @return int
     */
    public function blockSize(): int
    {
        return match($this) {
            self::Plaintext => 0,
            self::Blowfish,
            self::Idea,
            self::TripleDes,
            self::Cast5
                => 8,
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
     * Get block cipher engine
     *
     * @param string $mode - The cipher mode
     * @return BlockCipher
     */
    public function cipherEngine(string $mode = 'cfb'): BlockCipher
    {
        return match($this) {
            self::Plaintext => throw new \RuntimeException(
                'Symmetric algorithm "Plaintext" is unsupported.'
            ),
            self::Idea => new \OpenPGP\Cryptor\Symmetric\IDEA($mode),
            self::TripleDes => new \phpseclib3\Crypt\TripleDES($mode),
            self::Cast5 => new \OpenPGP\Cryptor\Symmetric\CAST5($mode),
            self::Blowfish => new \phpseclib3\Crypt\Blowfish($mode),
            self::Aes128, self::Aes192, self::Aes256
                => new \phpseclib3\Crypt\AES($mode),
            self::Twofish => new \phpseclib3\Crypt\Twofish($mode),
            self::Camellia128, self::Camellia192, self::Camellia256
                => new \OpenPGP\Cryptor\Symmetric\Camellia($mode),
        };
    }

    /**
     * Get ecb block cipher engine
     *
     * @return BlockCipher
     */
    public function ecbCipherEngine(): BlockCipher
    {
        return match($this) {
            self::Plaintext => throw new \InvalidArgumentException(
                'Symmetric algorithm "Plaintext" is unsupported.'
            ),
            self::Idea => new class extends \OpenPGP\Cryptor\Symmetric\IDEA {
                use EcbCipherTrait;
            },
            self::TripleDes => new class extends \phpseclib3\Crypt\TripleDES {
                use EcbCipherTrait;
            },
            self::Cast5 => new class extends \OpenPGP\Cryptor\Symmetric\CAST5 {
                use EcbCipherTrait;
            },
            self::Blowfish => new class extends \phpseclib3\Crypt\Blowfish {
                use EcbCipherTrait;
            },
            self::Aes128, self::Aes192, self::Aes256
                => new class extends \phpseclib3\Crypt\AES {
                    use EcbCipherTrait;
                },
            self::Twofish => new class extends \phpseclib3\Crypt\Twofish {
                use EcbCipherTrait;
            },
            self::Camellia128, self::Camellia192, self::Camellia256
                => new class extends \OpenPGP\Cryptor\Symmetric\Camellia {
                    use EcbCipherTrait;
                },
        };
    }
}
