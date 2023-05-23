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

use DateTime;
use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
};

/**
 * Key packet interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface KeyPacketInterface
{
    /**
     * Gets key version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Gets creation time
     * 
     * @return DateTime
     */
    function getCreationTime(): DateTime;

    /**
     * Gets key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Gets key parameters
     * 
     * @return KeyParametersInterface
     */
    function getKeyParameters(): ?KeyParametersInterface;

    /**
     * Gets fingerprint
     * 
     * @param bool $toHex
     * @return string
     */
    function getFingerprint(bool $toHex = false): string;

    /**
     * Gets key ID
     * 
     * @param bool $toHex
     * @return string
     */
    function getKeyID(bool $toHex = false): string;

    /**
     * Gets key Strength
     * 
     * @return int
     */
    function getKeyStrength(): int;

    /**
     * Return key packete is subkey
     * 
     * @return string
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
     * Gets preferred hash algorithm
     * 
     * @param HashAlgorithm $preferredHash
     * @return HashAlgorithm
     */
    function getPreferredHash(
        ?HashAlgorithm $preferredHash = null
    ): HashAlgorithm;
}
