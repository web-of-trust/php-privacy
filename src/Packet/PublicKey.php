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

use DateTimeInterface;
use phpseclib3\Common\Functions\Strings;
use OpenPGP\Common\{
    Config,
    Helper,
};
use OpenPGP\Enum\{
    CurveOid,
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
};
use OpenPGP\Type\{
    PublicKeyPacketInterface,
    KeyMaterialInterface,
    SubkeyPacketInterface,
};

/**
 * Public key packet class
 * 
 * PublicKey represents an OpenPGP public key packet.
 * See RFC 4880, section 5.5.2.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicKey extends AbstractPacket implements PublicKeyPacketInterface
{
	const KEY_VERSION = 4;

    private readonly string $fingerprint;

    private readonly string $keyID;

    /**
     * Constructor
     *
     * @param DateTimeInterface $creationTime
     * @param KeyMaterialInterface $keyMaterial
     * @param KeyAlgorithm $keyAlgorithm
     * @return self
     */
    public function __construct(
        private readonly DateTimeInterface $creationTime,
        private readonly KeyMaterialInterface $keyMaterial,
        private readonly KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
    )
    {
        parent::__construct(
            $this instanceof SubkeyPacketInterface ? PacketTag::PublicSubkey : PacketTag::PublicKey
        );
        $this->fingerprint = hash('sha1', $this->getSignBytes(), true);
        $this->keyID = substr($this->fingerprint, 12, 8);
    }

    /**
     * Read public key packets from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;

        // A one-octet version number (3 or 4 or 5).
        $version = ord($bytes[$offset++]);
        if ($version !== self::KEY_VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the key packet is unsupported.",
            );
        }

        // A four-octet number denoting the time that the key was created.
        $creationTime = (new \DateTime())->setTimestamp(
            Helper::bytesToLong($bytes, $offset)
        );
        $offset += 4;

        // A one-octet number denoting the public-key algorithm of this key.
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        // A series of values comprising the key material.
        // This is algorithm-specific and described in section XXXX.
        $keyMaterial = self::readKeyMaterial(
            substr($bytes, $offset), $keyAlgorithm
        );

        return new self(
            $creationTime,
            $keyMaterial,
            $keyAlgorithm
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::KEY_VERSION),
            pack('N', $this->creationTime->getTimestamp()),
            chr($this->keyAlgorithm->value),
            $this->keyMaterial->toBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return self::KEY_VERSION;
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
    public function getFingerprint(bool $toHex = false): string
    {
        return $toHex ? Strings::bin2hex($this->fingerprint) : $this->fingerprint;
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
        if ($this->keyMaterial instanceof Key\RSAPublicKeyMaterial) {
            return $this->keyMaterial->getModulus()->getLength();
        }
        elseif ($this->keyMaterial instanceof Key\DSAPublicKeyMaterial) {
            return $this->keyMaterial->getPrime()->getLength();
        }
        elseif ($this->keyMaterial instanceof Key\ElGamalPublicKeyMaterial) {
            return $this->keyMaterial->getPrime()->getLength();
        }
        elseif ($this->keyMaterial instanceof Key\ECPublicKeyMaterial) {
            return $this->keyMaterial->getPublicKeyLength();
        };
        return 0;
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
        return match ($this->keyAlgorithm) {
            KeyAlgorithm::RsaEncrypt => false,
            KeyAlgorithm::ElGamal => false,
            KeyAlgorithm::Ecdh => false,
            KeyAlgorithm::DiffieHellman => false,
            KeyAlgorithm::Aedh => false,
            default => true,
        };
    }

    /**
     * {@inheritdoc}
     */
    public function isEncryptionKey(): bool
    {
        return match ($this->keyAlgorithm) {
            KeyAlgorithm::RsaSign => false,
            KeyAlgorithm::Dsa => false,
            KeyAlgorithm::EcDsa => false,
            KeyAlgorithm::EdDsa => false,
            KeyAlgorithm::AeDsa => false,
            default => true,
        };
    }

    /**
     * {@inheritdoc}
     */
    public function getPreferredHash(
        ?HashAlgorithm $preferredHash = null
    ): HashAlgorithm
    {
        if ($this->keyMaterial instanceof Key\ECPublicKeyMaterial) {
            return $this->keyMaterial->getCurveOid()->hashAlgorithm();
        }
        else {
            return $preferredHash ?? Config::getPreferredHash();
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        $bytes = $this->toBytes();
        return implode([
            "\x99",
            pack('n', strlen($bytes)),
            $bytes,
        ]);
    }

    private static function readKeyMaterial(
        string $bytes, KeyAlgorithm $keyAlgorithm
    ): KeyMaterialInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt, KeyAlgorithm::RsaSign
            => Key\RSAPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::Dsa => Key\DSAPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::EcDsa => Key\ECDSAPublicKeyMaterial::fromBytes($bytes),
            KeyAlgorithm::EdDsa => Key\EdDSAPublicKeyMaterial::fromBytes($bytes),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
