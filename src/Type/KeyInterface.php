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
interface KeyInterface extends ArmorableInterface, PacketContainerInterface
{
    /**
     * Return key packet
     *
     * @return KeyPacketInterface
     */
    function getKeyPacket(): KeyPacketInterface;

    /**
     * Return key as public key
     *
     * @return KeyInterface
     */
    function toPublic(): KeyInterface;

    /**
     * Return the expiration time of the key or null if key does not expire.
     *
     * @return DateTime
     */
    function getExpirationTime(): ?DateTime;

    /**
     * Get creation time
     * 
     * @return DateTime
     */
    function getCreationTime(): DateTime;

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
     * Return last created key packet or key packet by given keyID
     * that is available for signing or verification
     * 
     * @param string $keyID
     * @param DateTime $time
     * @return KeyPacketInterface
     */
    function getSigningKeyPacket(
        string $keyID = '', ?DateTime $time = null
    ): KeyPacketInterface;

    /**
     * Return last created key packet or key packet by given keyID
     * that is available for encryption or decryption
     * 
     * @param string $keyID
     * @param DateTime $time
     * @return KeyPacketInterface
     */
    function getEncryptionKeyPacket(
        string $keyID = '', ?DateTime $time = null
    ): KeyPacketInterface;

    /**
     * Return primary user
     * 
     * @param DateTime $time
     * @return UserInterface
     */
    function getPrimaryUser(?DateTime $time = null): UserInterface;

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

    /**
     * Certify by private key.
     * 
     * @param PrivateKeyInterface $signKey
     * @param DateTime $time
     * @return self
     */
    function certifyBy(
        PrivateKeyInterface $signKey, ?DateTime $time = null
    ): self;

    /**
     * Revoke by private key.
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
