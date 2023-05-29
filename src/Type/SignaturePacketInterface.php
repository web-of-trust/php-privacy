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
    SignatureType,
};

/**
 * Signature packet interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SignaturePacketInterface extends PacketInterface
{
    /**
     * Gets version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Gets signature type
     * 
     * @return SignatureType
     */
    function getSignatureType(): SignatureType;

    /**
     * Gets key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Gets hash algorithm
     * 
     * @return HashAlgorithm
     */
    function getHashAlgorithm(): HashAlgorithm;

    /**
     * Gets hashed subpackets
     *
     * @return array<SubpacketInterface>
     */
    function getHashedSubpackets(): array;

    /**
     * Gets unhashed subpackets
     *
     * @return array<SubpacketInterface>
     */
    function getUnhashedSubpackets(): array;

    /**
     * Gets signed hash value
     *
     * @return string
     */
    function getSignedHashValue(): string;

    /**
     * Verifies signature expiration date
     * Use the given date for verification instead of the current time
     *
     * @param DateTime $time
     * @return bool
     */
    function isExpired(?DateTime $time = null): bool;

    /**
     * Gets signature data
     *
     * @return string
     */
    function getSignature(): string;

    /**
     * Verifies the signature packet.
     *
     * @param KeyPacketInterface $verifyKey
     * @param string $dataToVerify
     * @param DateTime $time
     * @return bool
     */
    function verify(
        KeyPacketInterface $verifyKey,
        string $dataToVerify,
        ?DateTime $time = null
    ): bool;

    /**
     * Gets signature creation time
     *
     * @return DateTime
     */
    function getSignatureCreationTime(): ?DateTime;

    /**
     * Gets signature expiration time
     *
     * @return DateTime
     */
    function getSignatureExpirationTime(): ?DateTime;

    /**
     * Gets exportable certification sub packet
     *
     * @return SubpacketInterface
     */
    function getExportableCertification(): ?SubpacketInterface;

    /**
     * Gets trust signature sub packet
     *
     * @return SubpacketInterface
     */
    function getTrustSignature(): ?SubpacketInterface;

    /**
     * Gets regular expression sub packet
     *
     * @return SubpacketInterface
     */
    function getRegularExpression(): ?SubpacketInterface;

    /**
     * Gets revocable sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocable(): ?SubpacketInterface;

    /**
     * Gets key expiration time sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyExpirationTime(): ?SubpacketInterface;

    /**
     * Gets preferred symmetric algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredSymmetricAlgorithms(): ?SubpacketInterface;

    /**
     * Gets revocation key sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocationKey(): ?SubpacketInterface;

    /**
     * Gets issuer key ID sub packet
     *
     * @return SubpacketInterface
     */
    function getIssuerKeyID(): SubpacketInterface;

    /**
     * Gets notation data sub packet
     *
     * @return SubpacketInterface
     */
    function getNotationData(): ?SubpacketInterface;

    /**
     * Gets preferred hash algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredHashAlgorithms(): ?SubpacketInterface;

    /**
     * Gets preferred compression algorithms sub packet
     *
     * @return SubpacketInterface
     */
    function getPreferredCompressionAlgorithms(): ?SubpacketInterface;

    /**
     * Gets key server preferences sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyServerPreferences(): ?SubpacketInterface;

    /**
     * Gets preferred key server sub packet
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
     * Gets policy URI sub packet
     *
     * @return SubpacketInterface
     */
    function getPolicyURI(): ?SubpacketInterface;

    /**
     * Gets key flags sub packet
     *
     * @return SubpacketInterface
     */
    function getKeyFlags(): ?SubpacketInterface;

    /**
     * Gets signer user ID sub packet
     *
     * @return SubpacketInterface
     */
    function getSignerUserID(): ?SubpacketInterface;

    /**
     * Gets revocation reason sub packet
     *
     * @return SubpacketInterface
     */
    function getRevocationReason(): ?SubpacketInterface;

    /**
     * Gets features sub packet
     *
     * @return SubpacketInterface
     */
    function getFeatures(): ?SubpacketInterface;

    /**
     * Gets signature target packet
     *
     * @return SubpacketInterface
     */
    function getSignatureTarget(): ?SubpacketInterface;

    /**
     * Gets embedded signature packet
     *
     * @return SubpacketInterface
     */
    function getEmbeddedSignature(): ?SubpacketInterface;

    /**
     * Gets issuer fingerprint sub packet
     *
     * @return SubpacketInterface
     */
    function getIssuerFingerprint(): ?SubpacketInterface;
}
