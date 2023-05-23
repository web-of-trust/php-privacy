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
 * Subkey interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SubkeyInterface
{
    /**
     * Returns key packet
     *
     * @return SubkeyPacketInterface
     */
    function getKeyPacket(): SubkeyPacketInterface;

    /**
     * Returns the expiration time of the subkey or null if subkey does not expire.
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
     * @return string
     */
    function getKeyStrength(): int;

    /**
     * Checks if a binding signature of a subkey is revoked
     * 
     * @param KeyPacketInterface $keyPacket
     * @param SignaturePacketInterface $certificate
     * @param DateTime $time
     * @return bool
     */
    function isRevoked(
        ?KeyPacketInterface $keyPacket = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTime $time = null
    ): bool;

    /**
     * Verify subkey.
     * Checks for revocation signatures, expiration time and valid binding signature.
     * 
     * @param DateTime $time
     * @return bool
     */
    function verify(?DateTime $time = null): bool;
}
