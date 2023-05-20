<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTime;
use OpenPGP\Common\{Config, Helper};
use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
    KeyFlag,
    PacketTag,
    RevocationReasonTag,
    SignatureSubpacketType,
    SignatureType,
};
use OpenPGP\Type\{
    KeyPacketInterface,
    SignaturePacketInterface,
    SignableParametersInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface,
    VerifiableParametersInterface
};

/**
 * Signature represents a signature.
 * See RFC 4880, section 5.2.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class Signature extends AbstractPacket implements SignaturePacketInterface
{
    const VERSION = 4;

    private string $signatureData;

    private readonly array $hashedSubpackets;

    private readonly array $unhashedSubpackets;

    /**
     * Constructor
     *
     * @param int $version
     * @param SignatureType $signatureType
     * @param KeyAlgorithm $keyAlgorithm
     * @param HashAlgorithm $hashAlgorithm
     * @param string $signedHashValue
     * @param string $signature
     * @param array $hashedSubpackets
     * @param array $unhashedSubpackets
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly SignatureType $signatureType,
        private readonly KeyAlgorithm $keyAlgorithm,
        private readonly HashAlgorithm $hashAlgorithm,
        private readonly string $signedHashValue,
        private readonly string $signature,
        array $hashedSubpackets = [],
        array $unhashedSubpackets = []
    )
    {
        parent::__construct(PacketTag::Signature);
        $this->hashedSubpackets = array_filter(
            $hashedSubpackets,
            static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->unhashedSubpackets = array_filter(
            $unhashedSubpackets,
            static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->signatureData = implode([
            chr($this->version),
            chr($this->signatureType->value),
            chr($this->keyAlgorithm->value),
            chr($this->hashAlgorithm->value),
            self::subpacketsToBytes($this->hashedSubpackets),
        ]);
    }

    /**
     * Reads signature packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;

        // A one-octet version number (3 or 4 or 5).
        $version = ord($bytes[$offset++]);
        if ($version != self::VERSION) {
            throw \UnexpectedValueException(
                "Version $version of the signature packet is unsupported.",
            );
        }

        // One-octet signature type.
        $signatureType = SignatureType::from(ord($bytes[$offset++]));

        // One-octet public-key algorithm.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        // One-octet hash algorithm.
        $hashAlgorithm = HashAlgorithm::from(ord($bytes[$offset++]));

        // Reads hashed subpackets
        $hashedLength = Helper::bytesToShort($bytes, $offset);
        $offset += 2;
        $hashedSubpackets = self::readSubpackets(
            substr($bytes, $offset, $hashedLength)
        );
        $offset += $hashedLength;

        // read unhashed subpackets
        $unhashedLength = Helper::bytesToShort($bytes, $offset);
        $offset += 2;
        $unhashedSubpackets = self::readSubpackets(
            substr($bytes, $offset, $unhashedLength)
        );
        $offset += $unhashedLength;

        // Two-octet field holding left 16 bits of signed hash value.
        $signedHashValue = substr($bytes, $offset, 2);
        $signature = substr($bytes, $offset + 2);

        return new self(
            $version,
            $signatureType,
            $keyAlgorithm,
            $hashAlgorithm,
            $signedHashValue,
            $signature,
            $hashedSubpackets,
            $unhashedSubpackets,
        );
    }

    /**
     * Creates signature
     *
     * @param SecretKey $signKey
     * @param SignatureType $signatureType
     * @param string $dataToSign
     * @param HashAlgorithm $hashAlgorithm
     * @param array $subpackets
     * @param DateTime $creationTime
     * @return self
     */
    public static function createSignature(
        SecretKey $signKey,
        SignatureType $signatureType,
        string $dataToSign,
        HashAlgorithm $hashAlgorithm = HashAlgorithm::Sha256,
        array $subpackets = [],
        ?DateTime $creationTime = null
    ): self
    {
        $version = $signKey->getVersion();
        $keyAlgorithm = $signKey->getKeyAlgorithm();
        $hashAlgorithm = $signKey->getPreferredHash($hashAlgorithm);

        $hashedSubpackets = [
            Signature\SignatureCreationTime::fromTime(
                $creationTime ?? new DateTime()
            ),
            Signature\IssuerFingerprint::fromKeyPacket($signKey),
            Signature\IssuerKeyID::fromKeyID($signKey->getKeyID()),
            ...$subpackets,
        ];

        $signatureData = implode([
            chr($version),
            chr($signatureType->value),
            chr($keyAlgorithm->value),
            chr($hashAlgorithm->value),
            self::subpacketsToBytes($hashedSubpackets),
        ]);

        $message = implode([
            $dataToSign,
            $signatureData,
            self::calculateTrailer(
                $version,
                strlen($signatureData),
            ),
        ]);

        return new self(
            $version,
            $signatureType,
            $keyAlgorithm,
            $hashAlgorithm,
            substr(hash(
                strtolower($hashAlgorithm->name), $message, true
            ), 0, 2),
            self::signMessage($signKey, $hashAlgorithm, $message),
            $hashedSubpackets,
        );
    }

    /**
     * Creates cert generic signature
     *
     * @param SecretKey $signKey
     * @param UserIDPacketInterface $userID
     * @param DateTime $creationTime
     * @return self
     */
    public static function createCertGeneric(
        SecretKey $signKey,
        UserIDPacketInterface $userID,
        ?DateTime $creationTime = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::CertGeneric,
            implode([
                $signKey->getSignBytes(),
                $userID->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            [
                Signature\KeyFlags::fromFlags(
                    KeyFlag::CertifyKeys->value | KeyFlag::SignData->value
                ),
            ],
            $creationTime
        );
    }

    /**
     * Creates cert revocation signature
     *
     * @param SecretKey $signKey
     * @param UserIDPacketInterface $userID
     * @param string $revocationReason
     * @param DateTime $creationTime
     * @return self
     */
    public static function createCertRevocation(
        SecretKey $signKey,
        UserIDPacketInterface $userID,
        string $revocationReason = '',
        ?DateTime $creationTime = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::CertRevocation,
            implode([
                $signKey->getSignBytes(),
                $userID->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            [
                Signature\RevocationReason::fromRevocation(
                    RevocationReasonTag::NoReason, $revocationReason
                )
            ],
            $creationTime
        );
    }

    /**
     * Creates subkey binding signature
     *
     * @param SecretKey $signKey
     * @param SubkeyPacketInterface $subkey
     * @param DateTime $creationTime
     * @return self
     */
    public static function createSubkeyBinding(
        SecretKey $signKey,
        SubkeyPacketInterface $subkey,
        ?DateTime $creationTime = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::SubkeyBinding,
            implode([
                $signKey->getSignBytes(),
                $subkey->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            $creationTime
        );
    }

    /**
     * Creates subkey revocation signature
     *
     * @param SecretKey $signKey
     * @param SubkeyPacketInterface $subkey
     * @param string $revocationReason
     * @param DateTime $creationTime
     * @return self
     */
    public static function createSubkeyRevocation(
        SecretKey $signKey,
        SubkeyPacketInterface $subkey,
        string $revocationReason = '',
        ?DateTime $creationTime = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::SubkeyRevocation,
            implode([
                $signKey->getSignBytes(),
                $subkey->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            [
                Signature\RevocationReason::fromRevocation(
                    RevocationReasonTag::NoReason, $revocationReason
                )
            ],
            $creationTime
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->signatureData,
            self::subpacketsToBytes($this->unhashedSubpackets),
            $this->signedHashValue,
            $this->signature,
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        KeyPacketInterface $verifyKey,
        string $dataToVerify,
        ?DateTime $time = null
    ): bool
    {
        if ($this->getIssuerKeyID()->getKeyID() !== $verifyKey->getKeyID()) {
            $this->getLogger()->debug(
                'Signature was not issued by the given public key.'
            );
            return false;
        }
        if ($this->keyAlgorithm !== $verifyKey->getKeyAlgorithm()) {
            $this->getLogger()->debug(
                'Public key algorithm used to sign signature does not match issuer key algorithm.'
            );
            return false;
        }

        $expirationTime = $this->getSignatureExpirationTime();
        if ($expirationTime instanceof DateTime) {
            $time = $time ?? new DateTime();
            if ($expirationTime < $time) {
                $this->getLogger()->debug(
                    'Signature is expired at {expirationTime}.',
                    [
                        'expirationTime' => $expirationTime->format(DateTime::RFC3339_EXTENDED),
                    ]
                );
                return false;
            }
        }

        $message = implode([
            $dataToVerify,
            $this->signatureData,
            self::calculateTrailer(
                $this->version,
                strlen($this->signatureData)
            ),
        ]);
        $hash = hash(
            strtolower($this->hashAlgorithm->name), $message, true
        );
        if ($this->signedHashValue !== substr($hash, 0, 2)) {
            $this->getLogger()->debug(
                'Signed digest did not match.'
            );
            return false;
        }

        $keyParams = $verifyKey->getKeyParameters();
        if ($keyParams instanceof VerifiableParametersInterface) {
            return $keyParams->verify(
                $this->hashAlgorithm, $message, $this->signature
            );
        }
        else {
            $this->getLogger()->debug(
                'Verify key parameters is not verifiable.'
            );
            return false;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureType(): SignatureType
    {
        return $this->signatureType;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getHashAlgorithm(): HashAlgorithm
    {
        return $this->hashAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function getHashedSubpackets(): array
    {
        return $this->hashedSubpackets;
    }

    /**
     * {@inheritdoc}
     */
    public function getUnhashedSubpackets(): array
    {
        return $this->unhashedSubpackets;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignedHashValue(): string
    {
        return $this->signedHashValue;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignature(): string
    {
        return $this->signature;
    }

    /**
     * Gets signature creation time
     *
     * @return DateTime
     */
    public function getSignatureCreationTime(): ?DateTime
    {
        $subpacket = self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignatureCreationTime
        );
        return $subpacket ? $subpacket->getCreationTime() : null;
    }

    /**
     * Gets signature expiration time
     *
     * @return DateTime
     */
    public function getSignatureExpirationTime(): ?DateTime
    {
        $subpacket = self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignatureExpirationTime
        );
        return $subpacket ? $subpacket->getExpirationTime() : null;
    }

    /**
     * Gets exportable certification sub packet
     *
     * @return Signature\ExportableCertification
     */
    public function getExportableCertification(): ?Signature\ExportableCertification
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::ExportableCertification
        );
    }

    /**
     * Gets trust signature sub packet
     *
     * @return Signature\TrustSignature
     */
    public function getTrustSignature(): ?Signature\TrustSignature
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::TrustSignature
        );
    }

    /**
     * Gets regular expression sub packet
     *
     * @return Signature\RegularExpression
     */
    public function getRegularExpression(): ?Signature\RegularExpression
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RegularExpression
        );
    }

    /**
     * Gets revocable sub packet
     *
     * @return Signature\Revocable
     */
    public function getRevocable(): ?Signature\Revocable
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Revocable
        );
    }

    /**
     * Gets key expiration time sub packet
     *
     * @return Signature\KeyExpirationTime
     */
    public function getKeyExpirationTime(): ?Signature\KeyExpirationTime
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyExpirationTime
        );
    }

    /**
     * Gets preferred symmetric algorithms sub packet
     *
     * @return Signature\PreferredSymmetricAlgorithms
     */
    public function getPreferredSymmetricAlgorithms(): ?Signature\PreferredSymmetricAlgorithms
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredSymmetricAlgorithms
        );
    }

    /**
     * Gets revocation key sub packet
     *
     * @return Signature\RevocationKey
     */
    public function getRevocationKey(): ?Signature\RevocationKey
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RevocationKey
        );
    }

    /**
     * Gets issuer key ID sub packet
     *
     * @return Signature\IssuerKeyID
     */
    public function getIssuerKeyID(): Signature\IssuerKeyID
    {
        $type = SignatureSubpacketType::IssuerKeyID;
        $issuerKeyID = self::getSubpacket($this->hashedSubpackets, $type) ??
                       self::getSubpacket($this->unhashedSubpackets, $type);
        if ($issuerKeyID instanceof Signature\IssuerKeyID) {
            return $issuerKeyID;
        }
        else {
            $issuerFingerprint = $this->getIssuerFingerprint();
            if ($issuerFingerprint instanceof Signature\IssuerFingerprint) {
                return Signature\IssuerKeyID(
                    substr($issuerFingerprint->getKeyFingerprint(), 12, 20)
                );
            }
            else {
                return Signature\IssuerKeyID::wildcard();
            }
        }
    }

    /**
     * Gets notation data sub packet
     *
     * @return Signature\NotationData
     */
    public function getNotationData(): ?Signature\NotationData
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::NotationData
        );
    }

    /**
     * Gets preferred hash algorithms sub packet
     *
     * @return Signature\PreferredHashAlgorithms
     */
    public function getPreferredHashAlgorithms(): ?Signature\PreferredHashAlgorithms
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredHashAlgorithms
        );
    }

    /**
     * Gets preferred compression algorithms sub packet
     *
     * @return Signature\PreferredCompressionAlgorithms
     */
    public function getPreferredCompressionAlgorithms(): ?Signature\PreferredCompressionAlgorithms
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredCompressionAlgorithms
        );
    }

    /**
     * Gets key server preferences sub packet
     *
     * @return Signature\KeyServerPreferences
     */
    public function getKeyServerPreferences(): ?Signature\KeyServerPreferences
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyServerPreferences
        );
    }

    /**
     * Gets preferred key server sub packet
     *
     * @return Signature\PreferredKeyServer
     */
    public function getPreferredKeyServer(): ?Signature\PreferredKeyServer
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredKeyServer
        );
    }

    /**
     * Gets primary user ID sub packet
     *
     * @return Signature\PrimaryUserID
     */
    public function getPrimaryUserID(): ?Signature\PrimaryUserID
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PrimaryUserID
        );
    }

    /**
     * Gets policy URI sub packet
     *
     * @return Signature\PolicyURI
     */
    public function getPolicyURI(): ?Signature\PolicyURI
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PolicyURI
        );
    }

    /**
     * Gets key flags sub packet
     *
     * @return Signature\KeyFlags
     */
    public function getKeyFlags(): ?Signature\KeyFlags
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyFlags
        );
    }

    /**
     * Gets signer user ID sub packet
     *
     * @return Signature\SignerUserID
     */
    public function getSignerUserID(): ?Signature\SignerUserID
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignerUserID
        );
    }

    /**
     * Gets revocation reason sub packet
     *
     * @return Signature\RevocationReason
     */
    public function getRevocationReason(): ?Signature\RevocationReason
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RevocationReason
        );
    }

    /**
     * Gets features sub packet
     *
     * @return Signature\Features
     */
    public function getFeatures(): ?Signature\Features
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Features
        );
    }

    /**
     * Gets signature target packet
     *
     * @return Signature\SignatureTarget
     */
    public function getSignatureTarget(): ?Signature\SignatureTarget
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignatureTarget
        );
    }

    /**
     * Gets embedded signature packet
     *
     * @return Signature\EmbeddedSignature
     */
    public function getEmbeddedSignature(): ?Signature\EmbeddedSignature
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::EmbeddedSignature
        );
    }

    /**
     * Gets issuer fingerprint sub packet
     *
     * @return Signature\IssuerFingerprint
     */
    public function getIssuerFingerprint(): ?Signature\IssuerFingerprint
    {
        $type = SignatureSubpacketType::IssuerFingerprint;
        return self::getSubpacket($this->hashedSubpackets, $type) ??
               self::getSubpacket($this->unhashedSubpackets, $type);
    }

    private static function readSubpackets(string $bytes): array
    {
        return SubpacketReader::readSignatureSubpackets($bytes);
    }

    private static function signMessage(
        KeyPacketInterface $signKey,
        HashAlgorithm $hash,
        string $message
    ): string
    {
        switch ($signKey->getKeyAlgorithm()) {
            case KeyAlgorithm::RsaEncryptSign:
            case KeyAlgorithm::RsaSign:
            case KeyAlgorithm::Dsa:
            case KeyAlgorithm::EcDsa:
            case KeyAlgorithm::EdDsa:
                $keyParams = $signKey->getKeyParameters();
                if ($keyParams instanceof SignableParametersInterface) {
                    return $keyParams->sign($hash, $message);
                }
                else {
                    throw \UnexpectedValueException(
                        'Invalid key parameters for signing.',
                    );
                }
            default:
                throw \UnexpectedValueException(
                    'Unsupported public key algorithm for signing.',
                );
        }
    }

    private static function calculateTrailer(
        int $version, int $dataLength
    ): string
    {
        return chr($version) . "\xff" . pack('N', $dataLength);
    }

    private static function subpacketsToBytes(array $subpackets): string
    {
        $bytes = implode(
            array_map(static fn ($subpacket) => $subpacket->toBytes(), $subpackets)
        );
        return pack('n', strlen($bytes)) . $bytes;
    }

    private static function getSubpacket(
        array $subpackets, SignatureSubpacketType $type
    ): ?SignatureSubpacket
    {
        $subpackets = array_filter(
            $subpackets,
            static fn ($subpacket) => $subpacket->getType() === $type->value
        );
        $subpacket = reset($subpackets);
        return $subpacket ? $subpacket : null;
    }
}
