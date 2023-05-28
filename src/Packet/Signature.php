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
use OpenPGP\Common\{
    Config,
    Helper,
};
use OpenPGP\Enum\{
    CompressionAlgorithm,
    HashAlgorithm,
    KeyAlgorithm,
    KeyFlag,
    LiteralFormat,
    PacketTag,
    RevocationReasonTag,
    SignatureSubpacketType,
    SignatureType,
    SupportFeature,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    KeyPacketInterface,
    SignaturePacketInterface,
    SignableParametersInterface,
    SecretKeyPacketInterface,
    SubkeyPacketInterface,
    UserIDPacketInterface,
    VerifiableParametersInterface,
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

    /**
     * @var array<SignatureSubpacket>
     */
    private readonly array $hashedSubpackets;

    /**
     * @var array<SignatureSubpacket>
     */
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
     * @param array<SignatureSubpacket> $hashedSubpackets
     * @param array<SignatureSubpacket> $unhashedSubpackets
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
            throw new \UnexpectedValueException(
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
     * @param SecretKeyPacketInterface $signKey
     * @param SignatureType $signatureType
     * @param string $dataToSign
     * @param HashAlgorithm $hashAlgorithm
     * @param array<SignatureSubpacket> $subpackets
     * @param DateTime $time
     * @return self
     */
    public static function createSignature(
        SecretKeyPacketInterface $signKey,
        SignatureType $signatureType,
        string $dataToSign,
        HashAlgorithm $hashAlgorithm = HashAlgorithm::Sha256,
        array $subpackets = [],
        ?DateTime $time = null
    ): self
    {
        $version = $signKey->getVersion();
        $keyAlgorithm = $signKey->getKeyAlgorithm();
        $hashAlgorithm = $signKey->getPreferredHash($hashAlgorithm);

        $hashedSubpackets = [
            Signature\SignatureCreationTime::fromTime(
                $time ?? new DateTime()
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
     * Creates self signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param UserIDPacketInterface $userID
     * @param bool $isPrimaryUser
     * @param int $keyExpiry
     * @param DateTime $time
     * @return self
     */
    public static function createSelfCertificate(
        SecretKeyPacketInterface $signKey,
        UserIDPacketInterface $userID,
        bool $isPrimaryUser = false,
        int $keyExpiry = 0,
        ?DateTime $time = null
    )
    {
        $subpackets = [
            Signature\KeyFlags::fromFlags(
                KeyFlag::CertifyKeys->value | KeyFlag::SignData->value
            ),
            new Signature\PreferredSymmetricAlgorithms(
                implode([
                    chr(SymmetricAlgorithm::Aes128->value),
                    chr(SymmetricAlgorithm::Aes192->value),
                    chr(SymmetricAlgorithm::Aes256->value),
                ])
            ),
            new Signature\PreferredHashAlgorithms(
                implode([
                    chr(HashAlgorithm::Sha256->value),
                    chr(HashAlgorithm::Sha512->value),
                ])
            ),
            new Signature\PreferredCompressionAlgorithms(
                implode([
                    chr(CompressionAlgorithm::Uncompressed->value),
                    chr(CompressionAlgorithm::Zip->value),
                    chr(CompressionAlgorithm::Zlib->value),
                    chr(CompressionAlgorithm::BZip2->value),
                ])
            ),
            new Signature\Features(
                chr(SupportFeature::ModificationDetection->value)
            ),
        ];
        if ($isPrimaryUser) {
            $subpackets[] = new Signature\PrimaryUserID("\x01");
        }
        if ($keyExpiry > 0) {
            $subpackets[] = Signature\KeyExpirationTime::fromTime($keyExpiry);
        }
        return self::createSignature(
            $signKey,
            SignatureType::CertGeneric,
            implode([
                $signKey->getSignBytes(),
                $userID->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            $subpackets,
            $time
        );
    }

    /**
     * Creates cert generic signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param UserIDPacketInterface $userID
     * @param DateTime $time
     * @return self
     */
    public static function createCertGeneric(
        SecretKeyPacketInterface $signKey,
        UserIDPacketInterface $userID,
        ?DateTime $time = null
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
            $time
        );
    }

    /**
     * Creates cert revocation signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param UserIDPacketInterface $userID
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    public static function createCertRevocation(
        SecretKeyPacketInterface $signKey,
        UserIDPacketInterface $userID,
        string $revocationReason = '',
        ?DateTime $time = null
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
            $time
        );
    }

    /**
     * Creates subkey binding signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param SubkeyPacketInterface $subkey
     * @param int $keyExpiry
     * @param bool $subkeySign
     * @param DateTime $time
     * @return self
     */
    public static function createSubkeyBinding(
        SecretKeyPacketInterface $signKey,
        SubkeyPacketInterface $subkey,
        int $keyExpiry = 0,
        bool $subkeySign = false,
        ?DateTime $time = null
    ): self
    {
        $subpackets = [];
        if ($keyExpiry > 0) {
            $subpackets[] = Signature\KeyExpirationTime::fromTime($keyExpiry);
        }
        if ($subkeySign && $subkey instanceof SecretKeyPacketInterface) {
            $subpackets[] = Signature\KeyFlags::fromFlags(
                KeyFlag::SignData->value
            );
            $subpackets[] = Signature\EmbeddedSignature::fromSignature(
                self::createSignature(
                    $subkey,
                    SignatureType::KeyBinding,
                    implode([
                        $signKey->getSignBytes(),
                        $subkey->getSignBytes(),
                    ]),
                    Config::getPreferredHash(),
                    [],
                    $time
                )
            );
        }
        else {
            $subpackets[] = Signature\KeyFlags::fromFlags(
                KeyFlag::EncryptCommunication->value | KeyFlag::EncryptStorage->value
            );
        }
        return self::createSignature(
            $signKey,
            SignatureType::SubkeyBinding,
            implode([
                $signKey->getSignBytes(),
                $subkey->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            $subpackets,
            $time
        );
    }

    /**
     * Creates subkey revocation signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param SubkeyPacketInterface $subkey
     * @param string $revocationReason
     * @param DateTime $time
     * @return self
     */
    public static function createSubkeyRevocation(
        SecretKeyPacketInterface $signKey,
        SubkeyPacketInterface $subkey,
        string $revocationReason = '',
        ?DateTime $time = null
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
            $time
        );
    }

    /**
     * Creates literal data signature
     *
     * @param SecretKeyPacketInterface $signKey
     * @param LiteralData $literalData
     * @param DateTime $time
     * @return self
     */
    public static function createLiteralData(
        SecretKeyPacketInterface $signKey,
        LiteralData $literalData,
        ?DateTime $time = null
    )
    {
        $signatureType = SignatureType::Binary;
        $format = $literalData->getFormat();
        if ($format === LiteralFormat::Text || $format === LiteralFormat::Utf8) {
            $signatureType = SignatureType::Text;
        }
        return self::createSignature(
            $signKey,
            $signatureType,
            $literalData->getSignBytes(),
            Config::getPreferredHash(),
            time: $time
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
                        'expirationTime' => $expirationTime->format(
                            DateTime::RFC3339_EXTENDED
                        ),
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
     * {@inheritdoc}
     */
    public function isExpired(?DateTime $time = null): bool
    {
        $timestamp = $time?->getTimestamp() ?? time();
        $creationTime = $this->getSignatureCreationTime()?->getTimestamp() ?? 0;
        $expirationTime = $this->getSignatureExpirationTime()?->getTimestamp() ?? time();
        return !($creationTime < $timestamp && $timestamp < $expirationTime);
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
        if ($subpacket instanceof Signature\SignatureCreationTime) {
            return $subpacket->getCreationTime();
        }
        return null;
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
        if ($subpacket instanceof Signature\SignatureExpirationTime) {
            return $subpacket->getExpirationTime();
        }
        return null;
    }

    /**
     * Gets exportable certification sub packet
     *
     * @return SignatureSubpacket
     */
    public function getExportableCertification(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::ExportableCertification
        );
    }

    /**
     * Gets trust signature sub packet
     *
     * @return SignatureSubpacket
     */
    public function getTrustSignature(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::TrustSignature
        );
    }

    /**
     * Gets regular expression sub packet
     *
     * @return SignatureSubpacket
     */
    public function getRegularExpression(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RegularExpression
        );
    }

    /**
     * Gets revocable sub packet
     *
     * @return SignatureSubpacket
     */
    public function getRevocable(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Revocable
        );
    }

    /**
     * Gets key expiration time sub packet
     *
     * @return SignatureSubpacket
     */
    public function getKeyExpirationTime(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyExpirationTime
        );
    }

    /**
     * Gets preferred symmetric algorithms sub packet
     *
     * @return SignatureSubpacket
     */
    public function getPreferredSymmetricAlgorithms(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredSymmetricAlgorithms
        );
    }

    /**
     * Gets revocation key sub packet
     *
     * @return SignatureSubpacket
     */
    public function getRevocationKey(): ?SignatureSubpacket
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
                return new Signature\IssuerKeyID(
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
     * @return SignatureSubpacket
     */
    public function getNotationData(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::NotationData
        );
    }

    /**
     * Gets preferred hash algorithms sub packet
     *
     * @return SignatureSubpacket
     */
    public function getPreferredHashAlgorithms(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredHashAlgorithms
        );
    }

    /**
     * Gets preferred compression algorithms sub packet
     *
     * @return SignatureSubpacket
     */
    public function getPreferredCompressionAlgorithms(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredCompressionAlgorithms
        );
    }

    /**
     * Gets key server preferences sub packet
     *
     * @return SignatureSubpacket
     */
    public function getKeyServerPreferences(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyServerPreferences
        );
    }

    /**
     * Gets preferred key server sub packet
     *
     * @return SignatureSubpacket
     */
    public function getPreferredKeyServer(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredKeyServer
        );
    }

    /**
     * Return is primary user ID
     *
     * @return bool
     */
    public function isPrimaryUserID(): bool
    {
        $subpacket = self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PrimaryUserID
        );
        if ($subpacket instanceof Signature\PrimaryUserID) {
            return $subpacket->isPrimaryUserID();
        }
        return false;
    }

    /**
     * Gets policy URI sub packet
     *
     * @return SignatureSubpacket
     */
    public function getPolicyURI(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PolicyURI
        );
    }

    /**
     * Gets key flags sub packet
     *
     * @return SignatureSubpacket
     */
    public function getKeyFlags(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyFlags
        );
    }

    /**
     * Gets signer user ID sub packet
     *
     * @return SignatureSubpacket
     */
    public function getSignerUserID(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignerUserID
        );
    }

    /**
     * Gets revocation reason sub packet
     *
     * @return SignatureSubpacket
     */
    public function getRevocationReason(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RevocationReason
        );
    }

    /**
     * Gets features sub packet
     *
     * @return SignatureSubpacket
     */
    public function getFeatures(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Features
        );
    }

    /**
     * Gets signature target packet
     *
     * @return SignatureSubpacket
     */
    public function getSignatureTarget(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignatureTarget
        );
    }

    /**
     * Gets embedded signature packet
     *
     * @return SignatureSubpacket
     */
    public function getEmbeddedSignature(): ?SignatureSubpacket
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::EmbeddedSignature
        );
    }

    /**
     * Gets issuer fingerprint sub packet
     *
     * @return SignatureSubpacket
     */
    public function getIssuerFingerprint(): ?SignatureSubpacket
    {
        $type = SignatureSubpacketType::IssuerFingerprint;
        return self::getSubpacket($this->hashedSubpackets, $type) ??
               self::getSubpacket($this->unhashedSubpackets, $type);
    }

    /**
     * @return array<SignatureSubpacket>
     */
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
                    throw new \UnexpectedValueException(
                        'Invalid key parameters for signing.',
                    );
                }
            default:
                throw new \UnexpectedValueException(
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

    /**
     * @param array<SignatureSubpacket> $subpackets
     * @return string
     */
    private static function subpacketsToBytes(array $subpackets): string
    {
        $bytes = implode(array_map(
            static fn ($subpacket) => $subpacket->toBytes(),
            $subpackets
        ));
        return pack('n', strlen($bytes)) . $bytes;
    }

    /**
     * @param array<SignatureSubpacket> $subpackets
     * @param SignatureSubpacketType $type
     * @return SignatureSubpacket
     */
    private static function getSubpacket(
        array $subpackets, SignatureSubpacketType $type
    ): ?SignatureSubpacket
    {
        $subpackets = array_filter(
            $subpackets,
            static fn ($subpacket) => $subpacket->getType() === $type->value
        );
        return array_pop($subpackets);
    }
}
