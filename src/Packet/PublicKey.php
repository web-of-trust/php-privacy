<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Common\{Config, Helper};
use OpenPGP\Enum\{
    Ecc,
    EdDSACurve,
    HashAlgorithm,
    KeyAlgorithm,
    KeyVersion,
    MontgomeryCurve,
    PacketTag,
};
use OpenPGP\Type\{
    ECKeyMaterialInterface,
    PublicKeyPacketInterface,
    KeyMaterialInterface,
    SubkeyPacketInterface,
};
use phpseclib3\Common\Functions\Strings;

/**
 * Implementation an OpenPGP public key packet (Tag 6).
 *
 * See RFC 9580, section 5.5.2.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicKey extends AbstractPacket implements PublicKeyPacketInterface
{
    const int KEY_ID_SIZE = 8;

    /**
     * Fingerprint bytes
     */
    private readonly string $fingerprint;

    /**
     * Key ID bytes
     */
    private readonly string $keyID;

    /**
     * Constructor
     *
     * @param int $version
     * @param DateTimeInterface $creationTime
     * @param KeyAlgorithm $keyAlgorithm
     * @param KeyMaterialInterface $keyMaterial
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly DateTimeInterface $creationTime,
        private readonly KeyAlgorithm $keyAlgorithm,
        private readonly KeyMaterialInterface $keyMaterial,
    ) {
        parent::__construct(
            $this instanceof SubkeyPacketInterface
                ? PacketTag::PublicSubkey
                : PacketTag::PublicKey,
        );
        if (
            $version !== KeyVersion::V4->value &&
            $version !== KeyVersion::V6->value
        ) {
            throw new \InvalidArgumentException(
                "Version {$version} of the key packet is unsupported.",
            );
        }
        $isV6 = $version === KeyVersion::V6->value;

        if ($isV6) {
            if ($keyMaterial instanceof Key\ECPublicKeyMaterial) {
                $curve = $keyMaterial->getEcc();
                if ($curve === Ecc::Ed25519 || $curve === Ecc::Curve25519) {
                    throw new \InvalidArgumentException(
                        "Legacy curve {$curve->name} cannot be used with v{$version} key packet.",
                    );
                }
            }
            if (
                $keyAlgorithm === KeyAlgorithm::Dsa ||
                $keyAlgorithm === KeyAlgorithm::ElGamal
            ) {
                throw new \InvalidArgumentException(
                    "Key algorithm {$keyAlgorithm->name} cannot be used with v{$version} key packet.",
                );
            }
        }

        $this->fingerprint = $isV6
            ? hash(KeyVersion::V6->hashAlgo(), $this->getSignBytes(), true)
            : hash(KeyVersion::V4->hashAlgo(), $this->getSignBytes(), true);
        $this->keyID = $isV6
            ? substr($this->fingerprint, 0, self::KEY_ID_SIZE)
            : substr($this->fingerprint, 12, self::KEY_ID_SIZE);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        [$version, $creationTime, $keyAlgorithm, $keyMaterial] = self::decode(
            $bytes,
        );
        return new self($version, $creationTime, $keyAlgorithm, $keyMaterial);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $kmBytes = $this->keyMaterial->toBytes();
        return implode([
            chr($this->version),
            pack("N", $this->creationTime->getTimestamp()),
            chr($this->keyAlgorithm->value),
            $this->version === KeyVersion::V6->value
                ? pack("N", strlen($kmBytes))
                : "",
            $kmBytes,
        ]);
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
    public function getCreationTime(): DateTimeInterface
    {
        return $this->creationTime;
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
    public function getKeyMaterial(): ?KeyMaterialInterface
    {
        return $this->keyMaterial;
    }

    /**
     * {@inheritdoc}
     */
    public function getECKeyMaterial(): ?ECKeyMaterialInterface
    {
        return $this->keyMaterial instanceof ECKeyMaterialInterface
            ? $this->keyMaterial
            : null;
    }

    /**
     * {@inheritdoc}
     */
    public function getFingerprint(bool $toHex = false): string
    {
        return $toHex
            ? Strings::bin2hex($this->fingerprint)
            : $this->fingerprint;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(bool $toHex = false): string
    {
        return $toHex ? Strings::bin2hex($this->keyID) : $this->keyID;
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyStrength(): int
    {
        return $this->keyMaterial->getKeyLength();
    }

    /**
     * {@inheritdoc}
     */
    public function isSubkey(): bool
    {
        return $this instanceof SubkeyPacketInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function isSigningKey(): bool
    {
        return $this->keyAlgorithm->forSigning();
    }

    /**
     * {@inheritdoc}
     */
    public function isEncryptionKey(): bool
    {
        return $this->keyAlgorithm->forEncryption();
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredHash(
        ?HashAlgorithm $preferredHash = null,
    ): HashAlgorithm {
        return match (true) {
            $this->keyMaterial instanceof Key\ECPublicKeyMaterial
                => $this->keyMaterial->getEcc()->hashAlgorithm(),
            $this->keyAlgorithm === KeyAlgorithm::Ed25519
                => EdDSACurve::Ed25519->hashAlgorithm(),
            $this->keyAlgorithm === KeyAlgorithm::Ed448
                => EdDSACurve::Ed448->hashAlgorithm(),
            default => $preferredHash ?? Config::getPreferredHash(),
        };
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        $bytes = $this->toBytes();
        $format = $this->version === KeyVersion::V6->value ? "N" : "n";
        return implode([
            chr(0x95 + $this->version),
            pack($format, strlen($bytes)),
            $bytes,
        ]);
    }

    /**
     * Decode public key packet
     *
     * @param string $bytes
     * @return array
     */
    protected static function decode(string $bytes): array
    {
        $offset = 0;

        // A one-octet version number.
        $version = ord($bytes[$offset++]);

        // A four-octet number denoting the time that the key was created.
        $creationTime = (new \DateTime)->setTimestamp(
            Helper::bytesToLong($bytes, $offset),
        );
        $offset += 4;

        // A one-octet number denoting the public-key algorithm of this key.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        if ($version === KeyVersion::V6->value) {
            // - A four-octet scalar octet count for the following key material.
            $offset += 4;
        }

        // A series of values comprising the key material.
        $keyMaterial = self::readKeyMaterial(
            substr($bytes, $offset),
            $keyAlgorithm,
        );

        return [$version, $creationTime, $keyAlgorithm, $keyMaterial];
    }

    private static function readKeyMaterial(
        string $bytes,
        KeyAlgorithm $keyAlgorithm,
    ): KeyMaterialInterface {
        return match ($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign,
            KeyAlgorithm::RsaEncrypt,
            KeyAlgorithm::RsaSign
                => Key\RSAPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalPublicKeyMaterial::fromBytes(
                $bytes,
            ),
            KeyAlgorithm::Dsa => Key\DSAPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::EcDsa => Key\ECDSAPublicKeyMaterial::fromBytes(
                $bytes,
            ),
            KeyAlgorithm::EdDsaLegacy
                => Key\EdDSALegacyPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::X25519 => Key\MontgomeryPublicKeyMaterial::fromBytes(
                substr($bytes, 0, MontgomeryCurve::Curve25519->payloadSize()),
            ),
            KeyAlgorithm::X448 => Key\MontgomeryPublicKeyMaterial::fromBytes(
                substr($bytes, 0, MontgomeryCurve::Curve448->payloadSize()),
            ),
            KeyAlgorithm::Ed25519 => Key\EdDSAPublicKeyMaterial::fromBytes(
                $bytes,
                EdDSACurve::Ed25519,
            ),
            KeyAlgorithm::Ed448 => Key\EdDSAPublicKeyMaterial::fromBytes(
                $bytes,
                EdDSACurve::Ed448,
            ),
            default => throw new \RuntimeException(
                "Key algorithm {$keyAlgorithm->name} is unsupported.",
            ),
        };
    }
}
