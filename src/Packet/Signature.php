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

use OpenPGP\Enum\{
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
    SignatureSubpacketType,
    SignatureType,
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
            $hashedSubpackets, static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->unhashedSubpackets = array_filter(
            $unhashedSubpackets, static fn ($subpacket) => $subpacket instanceof SignatureSubpacket
        );
        $this->signatureData = implode([
            chr($this->version),
            chr($this->signatureType->value),
            chr($this->keyAlgorithm->value),
            chr($this->hashAlgorithm->value),
            self::encodeSubpackets($this->hashedSubpackets),
        ]);
    }

    /**
     * Read signature packet from byte string
     *
     * @param string $bytes
     * @return Signature
     */
    public static function fromBytes(string $bytes): Signature
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
        $unpacked = unpack('n', substr($bytes, $offset, 2));
        $hashedLength = reset($unpacked);
        $offset += 2;
        $hashedSubpackets = self::readSubpackets(substr($bytes, $offset, $hashedLength));
        $offset += $hashedLength;

        // read unhashed subpackets
        $unpacked = unpack('n', substr($bytes, $offset, 2));
        $unhashedLength = reset($unpacked);
        $offset += 2;
        $unhashedSubpackets = self::readSubpackets(substr($bytes, $offset, $unhashedLength));
        $offset += $unhashedLength;

        // Two-octet field holding left 16 bits of signed hash value.
        $signedHashValue = substr($bytes, $offset, 2);
        $offset += 2;
        $signature = substr($bytes, $offset);

        return new Signature(
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

    public static function createSignature(
        SecretKey $signKey,
        SignatureType $signatureType,
        string $dataToSign,
        ?HashAlgorithm $preferredHash = null,
        array $subpackets = [],
        int $keyExpirationTime = 0,
        int $time = 0
    ): Signature
    {
        $version = $signKey->getVersion();
        $keyAlgorithm = $signKey->getKeyAlgorithm();
        $hashAlgorithm = $preferredHash ?? $signKey->getPreferredHash();

        $hashedSubpackets = [
            Signature\SignatureCreationTime::fromTime(empty($time) ? time() : $time),
            Signature\IssuerFingerprint::fromKeyPacket($signKey),
            new Signature\IssuerKeyID($signKey->getKeyID()),
            ...$subpackets,
        ];

        if ($keyExpirationTime > 0) {
            $hashedSubpackets[] = Signature\KeyExpirationTime::fromTime($keyExpirationTime);
        }

        $signatureData = implode([
            chr($version),
            chr($signatureType->value),
            chr($keyAlgorithm->value),
            chr($hashAlgorithm->value),
            self::encodeSubpackets($hashedSubpackets),
        ]);

        $message = implode([
            $dataToSign,
            $signatureData,
            self::calculateTrailer(
                $version,
                strlen($signatureData),
            ),
        ]);

        return Signature(
            $version,
            $signatureType,
            $keyAlgorithm,
            $hashAlgorithm,
            substr(hash($hashAlgorithm->name, $message, true), 0, 2),
            self::signMessage($signKey, $hashAlgorithm, $message),
            $hashedSubpackets,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->signatureData,
            self::encodeSubpackets($this->unhashedSubpackets),
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
        int $time = 0
    ): bool
    {
        if ($this->getIssuerKeyID()->getKeyID() != $verifyKey->getKeyID()) {
            // Signature was not issued by the given public key.
            return false;
        }
        if ($this->keyAlgorithm != $verifyKey->getKeyAlgorithm()) {
            // Public key algorithm used to sign signature does not match issuer key algorithm.
            return false;
        }

        $signatureExpirationTime = $this->getSignatureExpirationTime();
        if ($signatureExpirationTime instanceof Signature\SignatureExpirationTime) {
            $time = empty($time) ? time() : $time;
            if ($signatureExpirationTime->getExpirationTime() < $time) {
                // Signature is expired
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
        $hash = hash(strtolower($this->hashAlgorithm->name), $message, true);
        if ($this->signedHashValue !== substr($hash, 0, 2)) {
            // Signed digest did not match
            return false;
        }

        $keyParams = $verifyKey->getKeyParameters();
        if ($keyParams instanceof Key\VerifiableParametersInterface) {
            return $keyParams->verify(
                $this->hashAlgorithm, $message, $this->signature
            );
        }

        return false;
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
     * Gets signature creation time sub packet
     *
     * @return Signature\SignatureCreationTime
     */
    public function getSignatureCreationTime(): Signature\SignatureCreationTime
    {
        $type = SignatureSubpacketType::IssuerFingerprint->value;
        return self::getSubpacket($this->hashedSubpackets, $type) ??
               Signature\SignatureCreationTime::fromTime(time());
    }

    /**
     * Gets signature expiration time sub packet
     *
     * @return Signature\SignatureExpirationTime
     */
    public function getSignatureExpirationTime(): ?Signature\SignatureExpirationTime
    {
        return self::getSubpacket(
            $this->hashedSubpackets, SignatureSubpacketType::SignatureExpirationTime->value
        );
    }

    /**
     * Gets exportable certification sub packet
     *
     * @return Signature\ExportableCertification
     */
    public function getExportableCertification(): ?Signature\ExportableCertification
    {
        return self::getSubpacket(
            $this->hashedSubpackets, SignatureSubpacketType::ExportableCertification->value
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
            $this->hashedSubpackets, SignatureSubpacketType::TrustSignature->value
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
            $this->hashedSubpackets, SignatureSubpacketType::RegularExpression->value
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
            $this->hashedSubpackets, SignatureSubpacketType::Revocable->value
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
            $this->hashedSubpackets, SignatureSubpacketType::KeyExpirationTime->value
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
            $this->hashedSubpackets, SignatureSubpacketType::PreferredSymmetricAlgorithms->value
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
            $this->hashedSubpackets, SignatureSubpacketType::RevocationKey->value
        );
    }

    /**
     * Gets issuer key ID sub packet
     *
     * @return Signature\IssuerFingerprint
     */
    public function getIssuerKeyID(): Signature\IssuerKeyID
    {
        $type = SignatureSubpacketType::IssuerKeyID->value;
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
            $this->hashedSubpackets, SignatureSubpacketType::NotationData->value
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
            $this->hashedSubpackets, SignatureSubpacketType::PreferredHashAlgorithms->value
        );
    }

    /**
     * Gets preferred compression algorithms sub packet
     *
     * @return Signature\PreferredHashAlgorithms
     */
    public function getPreferredCompressionAlgorithms(): ?Signature\PreferredCompressionAlgorithms
    {
        return self::getSubpacket(
            $this->hashedSubpackets, SignatureSubpacketType::PreferredCompressionAlgorithms->value
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
            $this->hashedSubpackets, SignatureSubpacketType::KeyServerPreferences->value
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
            $this->hashedSubpackets, SignatureSubpacketType::PreferredKeyServer->value
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
            $this->hashedSubpackets, SignatureSubpacketType::PrimaryUserID->value
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
            $this->hashedSubpackets, SignatureSubpacketType::PolicyURI->value
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
            $this->hashedSubpackets, SignatureSubpacketType::KeyFlags->value
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
            $this->hashedSubpackets, SignatureSubpacketType::SignerUserID->value
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
            $this->hashedSubpackets, SignatureSubpacketType::RevocationReason->value
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
            $this->hashedSubpackets, SignatureSubpacketType::Features->value
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
            $this->hashedSubpackets, SignatureSubpacketType::SignatureTarget->value
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
            $this->hashedSubpackets, SignatureSubpacketType::EmbeddedSignature->value
        );
    }

    /**
     * Gets issuer fingerprint sub packet
     *
     * @return Signature\IssuerFingerprint
     */
    public function getIssuerFingerprint(): ?Signature\IssuerFingerprint
    {
        $type = SignatureSubpacketType::IssuerFingerprint->value;
        return self::getSubpacket($this->hashedSubpackets, $type) ??
               self::getSubpacket($this->unhashedSubpackets, $type);
    }

    private static function readSubpackets(string $bytes): array
    {
        $offset = 0;
        $length = strlen($bytes);
        $subpackets = [];
        while ($offset < $length) {
            $reader = SubpacketReader::read($bytes, $offset);
            $offset = $reader->getOffset();
            $data = $reader->getData();
            if (!empty($data)) {
                $critical = (($reader->getType() & 0x80) != 0);
                $type = SignatureSubpacketType::from($reader->getType() & 0x7f);
                switch ($type) {
                    case SignatureSubpacketType::SignatureCreationTime:
                        $subpackets[] = new Signature\SignatureCreationTime(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::SignatureExpirationTime:
                        $subpackets[] = new Signature\SignatureExpirationTime(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::ExportableCertification:
                        $subpackets[] = new Signature\ExportableCertification(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::TrustSignature:
                        $subpackets[] = new Signature\TrustSignature(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::RegularExpression:
                        $subpackets[] = new Signature\RegularExpression(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::Revocable:
                        $subpackets[] = new Signature\Revocable(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::KeyExpirationTime:
                        $subpackets[] = new Signature\KeyExpirationTime(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PreferredSymmetricAlgorithms:
                        $subpackets[] = new Signature\PreferredSymmetricAlgorithms(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::RevocationKey:
                        $subpackets[] = new Signature\RevocationKey(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::IssuerKeyID:
                        $subpackets[] = new Signature\IssuerKeyID(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::NotationData:
                        $subpackets[] = new Signature\NotationData(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PreferredHashAlgorithms:
                        $subpackets[] = new Signature\PreferredHashAlgorithms(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PreferredCompressionAlgorithms:
                        $subpackets[] = new Signature\PreferredCompressionAlgorithms(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::KeyServerPreferences:
                        $subpackets[] = new Signature\KeyServerPreferences(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PreferredKeyServer:
                        $subpackets[] = new Signature\PreferredKeyServer(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PrimaryUserID:
                        $subpackets[] = new Signature\PrimaryUserID(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::PolicyURI:
                        $subpackets[] = new Signature\PolicyURI(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::KeyFlags:
                        $subpackets[] = new Signature\KeyFlags(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::SignerUserID:
                        $subpackets[] = new Signature\SignerUserID(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::RevocationReason:
                        $subpackets[] = new Signature\RevocationReason(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::Features:
                        $subpackets[] = new Signature\Features(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::SignatureTarget:
                        $subpackets[] = new Signature\SignatureTarget(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::EmbeddedSignature:
                        $subpackets[] = new Signature\EmbeddedSignature(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    case SignatureSubpacketType::IssuerFingerprint:
                        $subpackets[] = new Signature\IssuerFingerprint(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                    default:
                        $subpackets[] = new SignatureSubpacket(
                            $data, $critical, $reader->isLong()
                        );
                        break;
                }
            }
        }
        return $subpackets;
    }

    private static function signMessage(
        SecretKey $signKey, HashAlgorithm $hash, string $message
    ): string
    {
        switch ($signKey->getKeyAlgorithm()) {
            case KeyAlgorithm::RsaEncryptSign:
            case KeyAlgorithm::RsaSign:
            case KeyAlgorithm::Dsa:
            case KeyAlgorithm::EcDsa:
            case KeyAlgorithm::EdDsa:
                $keyParams = $signKey->getKeyParameters();
                if ($keyParams instanceof Key\SignableParametersInterface) {
                    return $signKey->getKeyParameters()->sign($hash, $message);
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

    private static function encodeSubpackets(array $subpackets): string
    {
        $bytes = implode(
            array_map(static fn ($subpacket) => $subpacket->encode(), $subpackets)
        );
        return pack('n', strlen($bytes)) . $bytes;
    }

    private static function getSubpacket(array $subpackets, int $type): ?SignatureSubpacket
    {
        $subpackets = array_filter(
            $subpackets,
            static fn ($subpacket) => $subpacket->getType() === $type
        );
        $subpacket = reset($subpackets);
        return $subpacket ? $subpacket : null;
    }
}
