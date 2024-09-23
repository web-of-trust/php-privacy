<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\RevocationReasonTag;

/**
 * OpenPGP user interface
 * that represents an user ID or attribute packet and the relevant signatures.
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface UserInterface extends PacketContainerInterface
{
    /**
     * Get main key
     *
     * @return KeyInterface
     */
    function getMainKey(): KeyInterface;

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
     * @param KeyInterface $verifyKey
     * @param SignaturePacketInterface $certificate
     * @param DateTimeInterface $time
     * @return bool
     */
    function isRevoked(
        ?KeyInterface $verifyKey = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTimeInterface $time = null,
    ): bool;

    /**
     * Verify user is certified.
     * Check for existence of other signatures, revocation signatures
     * and validity of other signature.
     *
     * @param KeyInterface $verifyKey
     * @param SignaturePacketInterface $certificate
     * @param DateTimeInterface $time
     * @return bool
     */
    function isCertified(
        ?KeyInterface $verifyKey = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTimeInterface $time = null,
    ): bool;

    /**
     * Verify user.
     * Check for existence of self signatures, revocation signatures
     * and validity of self signature.
     *
     * @param DateTimeInterface $time
     * @return bool
     */
    function verify(?DateTimeInterface $time = null): bool;

    /**
     * Generate third-party certification over this user and its primary key.
     * Return clone user with new certification.
     *
     * @param PrivateKeyInterface $signKey
     * @param DateTimeInterface $time
     * @return self
     */
    function certifyBy(
        PrivateKeyInterface $signKey, ?DateTimeInterface $time = null
    ): self;

    /**
     * Revoke the user & return clone user with new revocation signature
     *
     * @param PrivateKeyInterface $signKey
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = '',
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null,
    ): self;
}
