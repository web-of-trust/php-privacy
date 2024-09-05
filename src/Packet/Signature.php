<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Common\{
    Config,
    Helper,
};
use OpenPGP\Enum\{
    AeadAlgorithm,
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
    LiteralDataInterface,
    NotationDataInterface,
    SignaturePacketInterface,
    SecretKeyMaterialInterface,
    SubkeyPacketInterface,
    SubpacketInterface,
    UserIDPacketInterface,
    PublicKeyMaterialInterface,
};
use phpseclib3\Crypt\Random;

/**
 * Implementation an OpenPGP signature packet (Tag 2).
 * 
 * See RFC 9580, section 5.2.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Signature extends AbstractPacket implements SignaturePacketInterface
{
    const VERSION_4 = 4;
    const VERSION_6 = 6;

    private readonly string $signatureData;

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
     * @param string $salt
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
        private readonly string $salt,
        private readonly string $signature,
        array $hashedSubpackets = [],
        array $unhashedSubpackets = []
    )
    {
        parent::__construct(PacketTag::Signature);
        if ($version != self::VERSION_4 && $version != self::VERSION_6) {
            throw new \UnexpectedValueException(
                "Version $version of the signature packet is unsupported.",
            );
        }

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
            self::subpacketsToBytes(
                $this->hashedSubpackets,
                $this->version === self::VERSION_6
            ),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;

        // A one-octet version number.
        $version = ord($bytes[$offset++]);
        $isV6 = $version === self::VERSION_6;

        // One-octet signature type.
        $signatureType = SignatureType::from(ord($bytes[$offset++]));

        // One-octet public-key algorithm.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        // One-octet hash algorithm.
        $hashAlgorithm = HashAlgorithm::from(ord($bytes[$offset++]));

        // Read hashed subpackets
        $hashedLength = $isV6 ?
            Helper::bytesToLong($bytes, $offset) :
            Helper::bytesToShort($bytes, $offset);
        $offset += $isV6 ? 4: 2;
        $hashedSubpackets = self::readSubpackets(
            substr($bytes, $offset, $hashedLength)
        );
        $offset += $hashedLength;

        // read unhashed subpackets
        $unhashedLength = $isV6 ?
            Helper::bytesToLong($bytes, $offset) :
            Helper::bytesToShort($bytes, $offset);
        $offset += $isV6 ? 4: 2;
        $unhashedSubpackets = self::readSubpackets(
            substr($bytes, $offset, $unhashedLength)
        );
        $offset += $unhashedLength;

        // Two-octet field holding left 16 bits of signed hash value.
        $signedHashValue = substr($bytes, $offset, 2);
        $offset += 2;

        $salt = '';
        if ($isV6) {
            $saltLength = ord($bytes[$offset++]);
            $salt = substr($bytes, $offset, $saltLength);
            $offset += $saltLength;
        }

        $signature = substr($bytes, $offset);

        return new self(
            $version,
            $signatureType,
            $keyAlgorithm,
            $hashAlgorithm,
            $signedHashValue,
            $salt,
            $signature,
            $hashedSubpackets,
            $unhashedSubpackets,
        );
    }

    /**
     * Create signature
     *
     * @param KeyPacketInterface $signKey
     * @param SignatureType $signatureType
     * @param string $dataToSign
     * @param HashAlgorithm $hashAlgorithm
     * @param array $subpackets
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createSignature(
        KeyPacketInterface $signKey,
        SignatureType $signatureType,
        string $dataToSign,
        HashAlgorithm $hashAlgorithm = HashAlgorithm::Sha256,
        array $subpackets = [],
        ?DateTimeInterface $time = null
    ): self
    {
        $version = $signKey->getVersion();
        $keyAlgorithm = $signKey->getKeyAlgorithm();
        $hashAlgorithm = $signKey->getPreferredHash($hashAlgorithm);

        $hashedSubpackets = [
            Signature\SignatureCreationTime::fromTime(
                $time ?? new \DateTime()
            ),
            Signature\IssuerFingerprint::fromKeyPacket($signKey),
            Signature\IssuerKeyID::fromKeyID($signKey->getKeyID()),
            ...$subpackets,
        ];

        $salt = '';
        $isV6 = $version === self::VERSION_6;
        if ($isV6) {
            $salt = Random::string($hashAlgorithm->saltSize());
        }
        else {
            $hashedSubpackets[] = Signature\NotationData::fromNotation(
                Config::SALT_NOTATION,
                Random::string($hashAlgorithm->saltSize())
            );
        }

        $signatureData = implode([
            chr($version),
            chr($signatureType->value),
            chr($keyAlgorithm->value),
            chr($hashAlgorithm->value),
            self::subpacketsToBytes(
                $hashedSubpackets,
                $isV6
            ),
        ]);
        $message = implode([
            $salt,
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
            substr($hashAlgorithm->hash($message), 0, 2),
            $salt,
            self::signMessage($signKey, $hashAlgorithm, $message),
            $hashedSubpackets,
        );
    }

    /**
     * Create self signature
     *
     * @param KeyPacketInterface $signKey
     * @param UserIDPacketInterface $userID
     * @param bool $isPrimaryUser
     * @param int $keyExpiry
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createSelfCertificate(
        KeyPacketInterface $signKey,
        UserIDPacketInterface $userID,
        bool $isPrimaryUser = false,
        int $keyExpiry = 0,
        ?DateTimeInterface $time = null
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
            Signature\Features::fromFeatures(
                SupportFeature::Version1SEIPD->value |
                SupportFeature::Version2SEIPD->value
            ),
        ];
        if ($isPrimaryUser) {
            $subpackets[] = new Signature\PrimaryUserID("\x01");
        }
        if ($keyExpiry > 0) {
            $subpackets[] = Signature\KeyExpirationTime::fromTime($keyExpiry);
        }
        if ($signKey->getVersion() === self::VERSION_6) {
            $subpackets[] = new Signature\PreferredAeadCiphers(
                implode([
                    chr(SymmetricAlgorithm::Aes128->value),
                    chr(AeadAlgorithm::Gcm->value),
                    chr(SymmetricAlgorithm::Aes192->value),
                    chr(AeadAlgorithm::Gcm->value),
                    chr(SymmetricAlgorithm::Aes256->value),
                    chr(AeadAlgorithm::Gcm->value),
                ])
            );
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
     * Create cert generic signature
     *
     * @param KeyPacketInterface $signKey
     * @param KeyPacketInterface $userKey
     * @param UserIDPacketInterface $userID
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createCertGeneric(
        KeyPacketInterface $signKey,
        KeyPacketInterface $userKey,
        UserIDPacketInterface $userID,
        ?DateTimeInterface $time = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::CertGeneric,
            implode([
                $userKey->getSignBytes(),
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
     * Create cert revocation signature
     *
     * @param KeyPacketInterface $signKey
     * @param KeyPacketInterface $userKey
     * @param UserIDPacketInterface $userID
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createCertRevocation(
        KeyPacketInterface $signKey,
        KeyPacketInterface $userKey,
        UserIDPacketInterface $userID,
        string $revocationReason = '',
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::CertRevocation,
            implode([
                $userKey->getSignBytes(),
                $userID->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            [
                Signature\RevocationReason::fromRevocation(
                    $reasonTag, $revocationReason
                )
            ],
            $time
        );
    }

    /**
     * Create key revocation signature
     *
     * @param KeyPacketInterface $signKey
     * @param KeyPacketInterface $keyPacket
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createKeyRevocation(
        KeyPacketInterface $signKey,
        KeyPacketInterface $keyPacket,
        string $revocationReason = '',
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::KeyRevocation,
            $keyPacket->getSignBytes(),
            Config::getPreferredHash(),
            [
                Signature\RevocationReason::fromRevocation(
                    $reasonTag, $revocationReason
                )
            ],
            $time
        );
    }

    /**
     * Create subkey binding signature
     *
     * @param KeyPacketInterface $signKey
     * @param SubkeyPacketInterface $subkey
     * @param int $keyExpiry
     * @param bool $subkeySign
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createSubkeyBinding(
        KeyPacketInterface $signKey,
        SubkeyPacketInterface $subkey,
        int $keyExpiry = 0,
        bool $subkeySign = false,
        ?DateTimeInterface $time = null
    ): self
    {
        $subpackets = [];
        if ($keyExpiry > 0) {
            $subpackets[] = Signature\KeyExpirationTime::fromTime($keyExpiry);
        }
        if ($subkeySign) {
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
     * Create subkey revocation signature
     *
     * @param KeyPacketInterface $signKey
     * @param KeyPacketInterface $primaryKey
     * @param SubkeyPacketInterface $subkey
     * @param string $revocationReason
     * @param RevocationReasonTag $reasonTag
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createSubkeyRevocation(
        KeyPacketInterface $signKey,
        KeyPacketInterface $primaryKey,
        SubkeyPacketInterface $subkey,
        string $revocationReason = '',
        RevocationReasonTag $reasonTag = RevocationReasonTag::NoReason,
        ?DateTimeInterface $time = null
    ): self
    {
        return self::createSignature(
            $signKey,
            SignatureType::SubkeyRevocation,
            implode([
                $primaryKey->getSignBytes(),
                $subkey->getSignBytes(),
            ]),
            Config::getPreferredHash(),
            [
                Signature\RevocationReason::fromRevocation(
                    $reasonTag, $revocationReason
                )
            ],
            $time
        );
    }

    /**
     * Create literal data signature
     *
     * @param KeyPacketInterface $signKey
     * @param LiteralDataInterface $literalData
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return self
     */
    public static function createLiteralData(
        KeyPacketInterface $signKey,
        LiteralDataInterface $literalData,
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null
    )
    {
        $signatureType = SignatureType::Binary;
        $format = $literalData->getFormat();
        if ($format === LiteralFormat::Text || $format === LiteralFormat::Utf8) {
            $signatureType = SignatureType::Text;
        }
        $subpackets = [];
        if ($notationData instanceof NotationDataInterface) {
            $subpackets[] = Signature\NotationData::fromNotation(
                $notationData->getNotationName(),
                $notationData->getNotationValue(),
                $notationData->isHumanReadable(),
            );
        }

        return self::createSignature(
            $signKey,
            $signatureType,
            $literalData->getSignBytes(),
            Config::getPreferredHash(),
            $subpackets,
            $time,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $data = [
            $this->signatureData,
            self::subpacketsToBytes(
                $this->unhashedSubpackets,
                $this->version === self::VERSION_6
            ),
            $this->signedHashValue,
        ];
        if ($this->version === self::VERSION_6) {
            $data[] = chr(strlen($this->salt));
            $data[] = $this->salt;
        }
        $data[] = $this->signature;
        return implode($data);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(
        KeyPacketInterface $verifyKey,
        string $dataToVerify,
        ?DateTimeInterface $time = null,
    ): bool
    {
        if (strcmp($this->getIssuerKeyID(), $verifyKey->getKeyID()) !== 0) {
            $this->getLogger()->warning(
                'Signature was not issued by the given public key.'
            );
            return false;
        }
        if ($this->keyAlgorithm !== $verifyKey->getKeyAlgorithm()) {
            $this->getLogger()->warning(
                'Public key algorithm used to sign signature does not match issuer key algorithm.'
            );
            return false;
        }

        $expirationTime = $this->getSignatureExpirationTime();
        if ($expirationTime instanceof DateTimeInterface) {
            $time = $time ?? new \DateTime();
            if ($expirationTime < $time) {
                $this->getLogger()->warning(
                    'Signature is expired at {expirationTime}.',
                    [
                        'expirationTime' => $expirationTime->format(
                            DateTimeInterface::RFC3339_EXTENDED
                        ),
                    ]
                );
                return false;
            }
        }

        $message = implode([
            $this->salt,
            $dataToVerify,
            $this->signatureData,
            self::calculateTrailer(
                $this->version,
                strlen($this->signatureData),
            ),
        ]);

        $hash = $this->hashAlgorithm->hash($message);
        if (strcmp($this->signedHashValue, substr($hash, 0, 2)) !== 0) {
            $this->getLogger()->warning(
                'Signed digest mismatch!'
            );
            return false;
        }

        $keyMaterial = $verifyKey->getKeyMaterial();
        if ($keyMaterial instanceof PublicKeyMaterialInterface) {
            return $keyMaterial->verify(
                $this->hashAlgorithm, $message, $this->signature
            );
        }
        else {
            $this->getLogger()->warning(
                'Verify key material is not verifiable.'
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
    public function getSalt(): string
    {
        return $this->salt;
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
    public function isExpired(?DateTimeInterface $time = null): bool
    {
        $timestamp = $time?->getTimestamp() ?? time();
        $creationTime = $this->getSignatureCreationTime()?->getTimestamp() ?? 0;
        $expirationTime = $this->getSignatureExpirationTime()?->getTimestamp() ?? time();
        return !($creationTime < $timestamp && $timestamp < $expirationTime);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureCreationTime(): ?DateTimeInterface
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
     * {@inheritdoc}
     */
    public function getSignatureExpirationTime(): ?DateTimeInterface
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
     * {@inheritdoc}
     */
    public function getExportableCertification(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::ExportableCertification
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getTrustSignature(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::TrustSignature
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRegularExpression(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RegularExpression
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRevocable(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Revocable
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyExpirationTime(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyExpirationTime
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredSymmetricAlgorithms(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredSymmetricAlgorithms
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRevocationKey(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RevocationKey
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getIssuerKeyID(bool $toHex = false): string
    {
        $type = SignatureSubpacketType::IssuerKeyID;
        $issuerKeyID = self::getSubpacket($this->hashedSubpackets, $type) ??
                       self::getSubpacket($this->unhashedSubpackets, $type);
        if (!($issuerKeyID instanceof Signature\IssuerKeyID)) {
            $issuerFingerprint = $this->getIssuerFingerprint();
            $keyID = $this->version === self::VERSION_6 ?
                substr($issuerFingerprint, 0, PublicKey::KEY_ID_SIZE) :
                substr($issuerFingerprint, 12, PublicKey::KEY_ID_SIZE);
            $issuerKeyID = new Signature\IssuerKeyID($keyID);
        }
        return $issuerKeyID->getKeyID($toHex);
    }

    /**
     * {@inheritdoc}
     */
    public function getNotationData(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::NotationData
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredHashAlgorithms(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredHashAlgorithms
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredAeadCiphers(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredAeadCiphers
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredCompressionAlgorithms(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredCompressionAlgorithms
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyServerPreferences(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyServerPreferences
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredKeyServer(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PreferredKeyServer
        );
    }

    /**
     * {@inheritdoc}
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
     * {@inheritdoc}
     */
    public function getPolicyURI(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::PolicyURI
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyFlags(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::KeyFlags
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignerUserID(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignerUserID
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getRevocationReason(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::RevocationReason
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getFeatures(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::Features
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureTarget(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::SignatureTarget
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getEmbeddedSignature(): ?SubpacketInterface
    {
        return self::getSubpacket(
            $this->hashedSubpackets,
            SignatureSubpacketType::EmbeddedSignature
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getIssuerFingerprint(bool $toHex = false): string
    {
        $type = SignatureSubpacketType::IssuerFingerprint;
        $subpacket = self::getSubpacket($this->hashedSubpackets, $type) ??
               self::getSubpacket($this->unhashedSubpackets, $type);
        if ($subpacket instanceof Signature\IssuerFingerprint) {
            return $subpacket->getKeyFingerprint($toHex);
        }
        return Signature\IssuerFingerprint::wildcard()->getKeyFingerprint($toHex);
    }

    /**
     * Read subpackets
     * 
     * @return array
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
            case KeyAlgorithm::EdDsaLegacy:
            case KeyAlgorithm::Ed25519:
            case KeyAlgorithm::Ed448:
                $keyMaterial = $signKey->getKeyMaterial();
                if ($keyMaterial instanceof SecretKeyMaterialInterface) {
                    return $keyMaterial->sign($hash, $message);
                }
                else {
                    throw new \UnexpectedValueException(
                        'Invalid key material for signing.',
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
        return implode([
            chr($version),
            "\xff",
            pack('N', $dataLength),
        ]);
    }

    /**
     * Serialize subpackets to bytes
     * 
     * @param array $subpackets
     * @param bool $isV6
     * @return string
     */
    private static function subpacketsToBytes(
        array $subpackets, bool $isV6 = false
    ): string
    {
        $bytes = implode(array_map(
            static fn ($subpacket): string => $subpacket->toBytes(),
            $subpackets
        ));
        return pack($isV6 ? 'N' : 'n', strlen($bytes)) . $bytes;
    }

    /**
     * Get subpacket by type
     * 
     * @param array $subpackets
     * @param SignatureSubpacketType $type
     * @return SubpacketInterface
     */
    private static function getSubpacket(
        array $subpackets, SignatureSubpacketType $type
    ): ?SubpacketInterface
    {
        $subpackets = array_filter(
            $subpackets,
            static fn ($subpacket) => $subpacket->getType() === $type->value
        );
        return array_pop($subpackets);
    }
}
