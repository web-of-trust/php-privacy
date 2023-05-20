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
use OpenPGP\Enum\KeyAlgorithm;

/**
 * Key interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface KeyInterface
{
    /**
     * Returns key packet
     *
     * @return KeyPacketInterface
     */
    function getKeyPacket(): KeyPacketInterface;

    /**
     * Returns key as public key
     *
     * @return KeyInterface
     */
    function toPublic(): KeyInterface;

    /**
     * Returns the expiration time of the key or null if key does not expire.
     *
     * @return DateTime
     */
    function getExpirationTime(): ?DateTime;

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
     * Gets key strength
     * 
     * @return int
     */
    function getKeyStrength(): int;

    /**
     * Return key is private
     * 
     * @return bool
     */
    function isPrivate(): bool;

    /**
     * Is revoked key
     *
     * @param SignaturePacketInterface $certificate
     * @param DateTime $time
     * @return bool
     */
    function isRevoked(
        ?SignaturePacketInterface $certificate = null, ?DateTime $time = null
    ): bool;

    /**
     * Verify key.
     * Checks for revocation signatures, expiration time and valid self signature.
     * 
     * @param string $userID
     * @param DateTime $time
     * @return bool
     */
    function verify(string $userID = '', ?DateTime $time = null): bool;
}
