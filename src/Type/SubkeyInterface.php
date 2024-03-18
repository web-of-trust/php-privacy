<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\{
    KeyAlgorithm,
    RevocationReasonTag,
};

/**
 * Subkey interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SubkeyInterface extends PacketContainerInterface
{
    /**
     * Get key packet
     *
     * @return SubkeyPacketInterface
     */
    function getKeyPacket(): SubkeyPacketInterface;

    /**
     * Get the expiration time of the subkey or null if subkey does not expire.
     * 
     * @return DateTimeInterface
     */
    function getExpirationTime(): ?DateTimeInterface;

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
     * Get revocation signatures
     * 
     * @return array
     */
    function getRevocationSignatures(): array;

    /**
     * Get binding signatures
     * 
     * @return array
     */
    function getBindingSignatures(): array;

    /**
     * Get latest binding signature
     * 
     * @return SignaturePacketInterface
     */
    function getLatestBindingSignature(): ?SignaturePacketInterface;

    /**
     * Return subkey is signing or verification key
     * 
     * @return bool
     */
    function isSigningKey(): bool;

    /**
     * Return subkey is encryption or decryption key
     * 
     * @return bool
     */
    function isEncryptionKey(): bool;

    /**
     * Check if a binding signature of a subkey is revoked
     * 
     * @param KeyInterface $verifyKey
     * @param SignaturePacketInterface $certificate
     * @param DateTimeInterface $time
     * @return bool
     */
    function isRevoked(
        ?KeyInterface $verifyKey = null,
        ?SignaturePacketInterface $certificate = null,
        ?DateTimeInterface $time = null
    ): bool;

    /**
     * Verify subkey.
     * Checks for revocation signatures, expiration time and valid binding signature.
     * 
     * @param DateTimeInterface $time
     * @return bool
     */
    function verify(?DateTimeInterface $time = null): bool;

    /**
     * Revoke the subkey
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
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): self;
}
