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
    HashAlgorithm,
    KeyAlgorithm,
    SignatureType,
};

/**
 * Signature packet interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SignaturePacketInterface extends PacketInterface
{
    /**
     * Get version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Get signature type
     * 
     * @return SignatureType
     */
    function getSignatureType(): SignatureType;

    /**
     * Get key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Get hash algorithm
     * 
     * @return HashAlgorithm
     */
    function getHashAlgorithm(): HashAlgorithm;

    /**
     * Get hashed subpackets
     *
     * @return array
     */
    function getHashedSubpackets(): array;

    /**
     * Get unhashed subpackets
     *
     * @return array
     */
    function getUnhashedSubpackets(): array;

    /**
     * Get signed hash value
     *
     * @return string
     */
    function getSignedHashValue(): string;

    /**
     * Verify signature expiration date
     * Use the given date for verification instead of the current time
     *
     * @param DateTimeInterface $time
     * @return bool
     */
    function isExpired(?DateTimeInterface $time = null): bool;

    /**
     * Get signature data
     *
     * @return string
     */
    function getSignature(): string;

    /**
     * Verify the signature packet.
     *
     * @param KeyPacketInterface $verifyKey
     * @param string $dataToVerify
     * @param DateTimeInterface $time
     * @return bool
     */
    function verify(
        KeyPacketInterface $verifyKey,
        string $dataToVerify,
        ?DateTimeInterface $time = null,
    ): bool;

    /**
     * Get signature creation time
     *
     * @return DateTimeInterface
     */
    function getSignatureCreationTime(): ?DateTimeInterface;

    /**
     * Get signature expiration time
     *
     * @return DateTimeInterface
     */
    function getSignatureExpirationTime(): ?DateTimeInterface;

    /**
     * Get exportable certification sub packet
     *
     * @return SubpacketInterface
     */
    function getExportableCertification(): ?SubpacketInterface;

    /**
     * Get trust signature sub packet
     *
     * @return SubpacketInterface
     */
    function getTrustSignature(): ?SubpacketInterface;

    /**
     * Get regular expression sub packet
     *
     * @return SubpacketInterface
     */
    function getRegularExpression(): ?SubpacketInterface;

    /**
     * Get revocable sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocable(): ?SubpacketInterface;

    /**
     * Get key expiration time sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyExpirationTime(): ?SubpacketInterface;

    /**
     * Get preferred symmetric algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredSymmetricAlgorithms(): ?SubpacketInterface;

    /**
     * Get revocation key sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocationKey(): ?SubpacketInterface;

    /**
     * Get issuer key ID sub packet
     *
     * @param bool $toHex
     * @return string
     */
    function getIssuerKeyID(bool $toHex = false): string;

    /**
     * Get notation data sub packet
     *
     * @return SubpacketInterface
     */
    function getNotationData(): ?SubpacketInterface;

    /**
     * Get preferred hash algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredHashAlgorithms(): ?SubpacketInterface;

    /**
     * Get preferred compression algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredCompressionAlgorithms(): ?SubpacketInterface;

    /**
     * Get key server preferences sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyServerPreferences(): ?SubpacketInterface;

    /**
     * Get preferred key server sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredKeyServer(): ?SubpacketInterface;

    /**
     * Return is primary user ID
     *
     * @return bool
     */
    function isPrimaryUserID(): bool;

    /**
     * Get policy URI sub packet
     *
     * @return SubpacketInterface
     */
    function getPolicyURI(): ?SubpacketInterface;

    /**
     * Get key flags sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyFlags(): ?SubpacketInterface;

    /**
     * Get signer user ID sub packet
     *
     * @return SubpacketInterface
     */
    function getSignerUserID(): ?SubpacketInterface;

    /**
     * Get revocation reason sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocationReason(): ?SubpacketInterface;

    /**
     * Get features sub packet
     *
     * @return SubpacketInterface
     */
    function getFeatures(): ?SubpacketInterface;

    /**
     * Get signature target packet
     *
     * @return SubpacketInterface
     */
    function getSignatureTarget(): ?SubpacketInterface;

    /**
     * Get embedded signature packet
     *
     * @return SubpacketInterface
     */
    function getEmbeddedSignature(): ?SubpacketInterface;

    /**
     * Get issuer fingerprint sub packet
     *
     * @return SubpacketInterface
     */
    function getIssuerFingerprint(): ?SubpacketInterface;
}
