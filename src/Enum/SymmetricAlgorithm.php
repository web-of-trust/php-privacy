<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

use phpseclib3\Crypt\Common\BlockCipher;

/**
 * SymmetricAlgorithm enum
 * See https://tools.ietf.org/html/rfc4880#section-9.2
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
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
            SymmetricAlgorithm::Plaintext => 0,
            SymmetricAlgorithm::Idea => 128,
            SymmetricAlgorithm::TripleDes => 192,
            SymmetricAlgorithm::Cast5 => 128,
            SymmetricAlgorithm::Blowfish => 128,
            SymmetricAlgorithm::Aes128 => 128,
            SymmetricAlgorithm::Aes192 => 192,
            SymmetricAlgorithm::Aes256 => 256,
            SymmetricAlgorithm::Twofish => 256,
            SymmetricAlgorithm::Camellia128 => 128,
            SymmetricAlgorithm::Camellia192 => 192,
            SymmetricAlgorithm::Camellia256 => 256,
        };
    }

    /**
     * Gets key size in byte
     *
     * @return int
     */
    public function keySizeInByte(): int
    {
        return ($this->keySize() + 7) >> 3
    }

    /**
     * Gets block size
     *
     * @return int
     */
    public function blockSize(): int
    {
        return match($this) {
            SymmetricAlgorithm::Plaintext => 0,
            SymmetricAlgorithm::Idea => 8,
            SymmetricAlgorithm::TripleDes => 8,
            SymmetricAlgorithm::Cast5 => 8,
            SymmetricAlgorithm::Blowfish => 16,
            SymmetricAlgorithm::Aes128 => 16,
            SymmetricAlgorithm::Aes192 => 16,
            SymmetricAlgorithm::Aes256 => 16,
            SymmetricAlgorithm::Twofish => 16,
            SymmetricAlgorithm::Camellia128 => 16,
            SymmetricAlgorithm::Camellia192 => 16,
            SymmetricAlgorithm::Camellia256 => 16,
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
            SymmetricAlgorithm::Plaintext => throw new \RuntimeException(
                'Symmetric algorithm "Plaintext" is unsupported.'
            ),
            SymmetricAlgorithm::Idea => throw new \RuntimeException(
                'Symmetric algorithm "Idea" is unsupported'
            ),
            SymmetricAlgorithm::TripleDes => new \phpseclib3\Crypt\TripleDES('cfb'),
            SymmetricAlgorithm::Cast5 => throw new \RuntimeException(
                'Symmetric algorithm "Cast5" is unsupported'
            ),
            SymmetricAlgorithm::Blowfish => new \phpseclib3\Crypt\Blowfish('cfb'),
            SymmetricAlgorithm::Aes128 => new \phpseclib3\Crypt\AES('cfb'),
            SymmetricAlgorithm::Aes192 => new \phpseclib3\Crypt\AES('cfb'),
            SymmetricAlgorithm::Aes256 => new \phpseclib3\Crypt\AES('cfb'),
            SymmetricAlgorithm::Twofish => new \phpseclib3\Crypt\Twofish('cfb'),
            SymmetricAlgorithm::Camellia128 => throw new \RuntimeException(
                'Symmetric algorithm "Camellia" is unsupported'
            ),
            SymmetricAlgorithm::Camellia192 => throw new \RuntimeException(
                'Symmetric algorithm "Camellia" is unsupported'
            ),
            SymmetricAlgorithm::Camellia256 => throw new \RuntimeException(
                'Symmetric algorithm "Camellia" is unsupported'
            ),
        };
    }
}
