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

/**
 * OpenPGP user interface
 * that represents an user ID or attribute packet and the relevant signatures.
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface UserInterface extends PacketContainerInterface
{
    /**
     * Get user ID packet
     * 
     * @return UserIDPacketInterface
     */
    function getUserIDPacket(): UserIDPacketInterface;

    /**
     * Get revocation signatures
     * 
     * @return array
     */
    function getRevocationCertifications(): array;

    /**
     * Get self signatures
     * 
     * @return array
     */
    function getSelfCertifications(): array;

    /**
     * Get other signatures
     * 
     * @return array<SignaturePacketInterface>
     */
    function getOtherCertifications(): array;

    /**
     * Get latest self certification
     * 
     * @return SignaturePacketInterface
     */
    function getLatestSelfCertification(): ?SignaturePacketInterface;

    /**
     * Get user ID
     * 
     * @return string
     */
    function getUserID(): string;

    /**
     * Return user is primary
     * 
     * @return bool
     */
    function isPrimary(): bool;

    /**
     * Check if a given certificate of the user is revoked
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
     * Verify user.
     * Check for existence of self signatures, revocation signatures
     * and validity of self signature.
     * 
     * @param DateTime $time
     * @return bool
     */
    function verify(?DateTime $time = null): bool;

    /**
     * Generate third-party certification over this user and its primary key.
     * Return clone user with new certification.
     * 
     * @param PrivateKeyInterface $signKey
     * @param DateTime $time
     * @return self
     */
    function certifyBy(
        PrivateKeyInterface $signKey, ?DateTime $time = null
    ): self;

    /**
     * Revoke the user & return clone user with new revocation signature
     * 
     * @param PrivateKeyInterface $signKey
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = '',
        ?DateTime $time = null
    ): self;
}
