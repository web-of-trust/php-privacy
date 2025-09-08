<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\{KeyAlgorithm, RevocationReasonTag, SymmetricAlgorithm};

/**
 * Key interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
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
     * Return key version
     *
     * @return int
     */
    function getVersion(): int;

    /**
     * Return the expiration time of the key or null if key does not expire.
     *
     * @return DateTimeInterface
     */
    function getExpirationTime(): ?DateTimeInterface;

    /**
     * Get creation time
     *
     * @return DateTimeInterface
     */
    function getCreationTime(): ?DateTimeInterface;

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
     * Get revocation signatures
     *
     * @return array
     */
    function getRevocationSignatures(): array;

    /**
     * Get direct signatures
     *
     * @return array
     */
    function getDirectSignatures(): array;

    /**
     * Get latest direct signature
     *
     * @return SignaturePacketInterface
     */
    function getLatestDirectSignature(): ?SignaturePacketInterface;

    /**
     * Return last created key packet or key packet by given keyID
     * that is available for signing or verification
     *
     * @param string $keyID
     * @param DateTimeInterface $time
     * @return KeyPacketInterface
     */
    function getSigningKeyPacket(
        string $keyID = "",
        ?DateTimeInterface $time = null,
    ): KeyPacketInterface;

    /**
     * Return last created key packet or key packet by given keyID
     * that is available for encryption or decryption
     *
     * @param string $keyID
     * @param DateTimeInterface $time
     * @return KeyPacketInterface
     */
    function getEncryptionKeyPacket(
        string $keyID = "",
        ?DateTimeInterface $time = null,
    ): KeyPacketInterface;

    /**
     * Get users
     *
     * @return array
     */
    function getUsers(): array;

    /**
     * Get subkeys
     *
     * @return array
     */
    function getSubkeys(): array;

    /**
     * Return primary user
     *
     * @param DateTimeInterface $time
     * @return UserInterface
     */
    function getPrimaryUser(?DateTimeInterface $time = null): ?UserInterface;

    /**
     * Return key is private
     *
     * @return bool
     */
    function isPrivate(): bool;

    /**
     * Return preferred symmetrics
     *
     * @return array
     */
    function getPreferredSymmetrics(): array;

    /**
     * Return preferred aeads by given symmetric
     *
     * @param SymmetricAlgorithm $symmetric
     * @return array
     */
    function getPreferredAeads(SymmetricAlgorithm $symmetric): array;

    /**
     * Return AEAD supported
     *
     * @return bool
     */
    function aeadSupported(): bool;

    /**
     * The key is revoked
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
     * The key is certified
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
     * Verify key.
     * Checks for revocation signatures, expiration time and valid self signature.
     *
     * @param string $userID
     * @param DateTimeInterface $time
     * @return bool
     */
    function verify(string $userID = "", ?DateTimeInterface $time = null): bool;

    /**
     * Certify by private key.
     *
     * @param PrivateKeyInterface $signKey
     * @param DateTimeInterface $time
     * @return self
     */
    function certifyBy(
        PrivateKeyInterface $signKey,
        ?DateTimeInterface $time = null,
    ): self;

    /**
     * Revoke by private key.
     *
     * @param PrivateKeyInterface $signKey
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    function revokeBy(
        PrivateKeyInterface $signKey,
        string $revocationReason = "",
        ?RevocationReasonTag $reasonTag = null,
        ?DateTimeInterface $time = null,
    ): self;
}
