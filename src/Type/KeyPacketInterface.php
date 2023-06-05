<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
};

/**
 * Key packet interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface KeyPacketInterface extends ForSigningInterface, PacketInterface
{
    /**
     * Get key version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Get creation time
     * 
     * @return DateTimeInterface
     */
    function getCreationTime(): DateTimeInterface;

    /**
     * Get key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Get fingerprint
     * 
     * @param bool $toHex
     * @return string
     */
    function getFingerprint(bool $toHex = false): string;

    /**
     * Get key ID
     * 
     * @param bool $toHex
     * @return string
     */
    function getKeyID(bool $toHex = false): string;

    /**
     * Get key strength
     * 
     * @return int
     */
    function getKeyStrength(): int;

    /**
     * Return key packete is subkey
     * 
     * @return bool
     */
    function isSubkey(): bool;

    /**
     * Is signing key
     *
     * @return bool
     */
    function isSigningKey(): bool;

    /**
     * Is encryption key
     *
     * @return bool
     */
    function isEncryptionKey(): bool;

    /**
     * Get key material
     * 
     * @return KeyMaterialInterface
     */
    function getKeyMaterial(): ?KeyMaterialInterface;

    /**
     * Get preferred hash algorithm
     * 
     * @param HashAlgorithm $preferredHash
     * @return HashAlgorithm
     */
    function getPreferredHash(
        ?HashAlgorithm $preferredHash = null
    ): HashAlgorithm;
}
