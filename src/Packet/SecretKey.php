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
use phpseclib3\Crypt\Random;
use OpenPGP\Common\Config;
use OpenPGP\Enum\{
    CurveOid,
    DHKeySize,
    HashAlgorithm,
    KeyAlgorithm,
    PacketTag,
    RSAKeySize,
    S2kType,
    S2kUsage,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    KeyPacketInterface,
    KeyMaterialInterface,
    PublicKeyPacketInterface,
    SecretKeyPacketInterface,
    SubkeyPacketInterface,
};

/**
 * Secret key packet class
 * 
 * SecretKey represents a possibly encrypted private key.
 * See RFC 4880, section 5.5.3.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SecretKey extends AbstractPacket implements SecretKeyPacketInterface
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param S2kUsage $s2kUsage
     * @param string $keyData
     * @param KeyMaterialInterface $keyMaterial
     * @param SymmetricAlgorithm $symmetric
     * @param Key\S2K $s2k
     * @param string $iv
     * @return self
     */
    public function __construct(
        private readonly PublicKey $publicKey,
        private readonly string $keyData = '',
        private readonly ?KeyMaterialInterface $keyMaterial = null,
        private readonly S2kUsage $s2kUsage = S2kUsage::Sha1,
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private readonly ?Key\S2K $s2k = null,
        private readonly string $iv = ''
    )
    {
        parent::__construct(
            $this instanceof SubkeyPacketInterface ? PacketTag::SecretSubkey : PacketTag::SecretKey
        );
    }

    /**
     * Read secret key packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = PublicKey::fromBytes($bytes);
        $offset = strlen($publicKey->toBytes());

        $s2kUsage = S2kUsage::from(ord($bytes[$offset++]));

        $s2k = null;
        switch ($s2kUsage) {
            case S2kUsage::Checksum:
            case S2kUsage::Sha1:
                $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
                $s2k = Key\S2K::fromBytes(substr($bytes, $offset));
                $offset += $s2k->getLength();
                break;
            default:
                $symmetric = SymmetricAlgorithm::Plaintext;
                break;
        }

        $iv = '';
        if ($s2k instanceof Key\S2K) {
            $iv = substr($bytes, $offset, $symmetric->blockSize());
            $offset += $symmetric->blockSize();
        }

        $keyMaterial = null;
        $keyData = substr($bytes, $offset);
        if ($s2kUsage === S2kUsage::None) {
            $keyMaterial = self::readKeyMaterial($keyData, $publicKey);
        }

        return new self(
            $publicKey,
            $keyData,
            $keyMaterial,
            $s2kUsage,
            $symmetric,
            $s2k,
            $iv
        );
    }

    /**
     * Generate secret key packet
     *
     * @param KeyAlgorithm $keyAlgorithm
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curveOid
     * @param DateTimeInterface $time
     * @return self
     */
    public static function generate(
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curveOid = CurveOid::Secp521r1,
        ?DateTimeInterface $time = null
    ): self
    {
        $keyMaterial = match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt, KeyAlgorithm::RsaSign
            => Key\RSASecretKeyMaterial::generate($rsaKeySize),
            KeyAlgorithm::ElGamal => Key\ElGamalSecretKeyMaterial::generate($dhKeySize),
            KeyAlgorithm::Dsa => Key\DSASecretKeyMaterial::generate($dhKeySize),
            KeyAlgorithm::Ecdh => Key\ECDHSecretKeyMaterial::generate($curveOid),
            KeyAlgorithm::EcDsa => Key\ECDSASecretKeyMaterial::generate($curveOid),
            KeyAlgorithm::EdDsa => Key\EdDSASecretKeyMaterial::generate($curveOid),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
        return new self(
            new PublicKey(
                $time ?? new \DateTime(),
                $keyMaterial->getPublicMaterial(),
                $keyAlgorithm
            ),
            $keyMaterial->toBytes(),
            $keyMaterial
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        if ($this->s2kUsage !== S2kUsage::None && $this->s2k instanceof Key\S2K) {
            return implode([
                $this->publicKey->toBytes(),
                chr($this->s2kUsage->value),
                chr($this->symmetric->value),
                $this->s2k->toBytes(),
                $this->iv,
                $this->keyData,
            ]);
        }
        else {
            return implode([
                $this->publicKey->toBytes(),
                chr(S2kUsage::None->value),
                $this->keyData,
            ]);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function getVersion(): int
    {
        return $this->publicKey->getVersion();
    }

    /**
     * {@inheritdoc}
     */
    public function getCreationTime(): DateTimeInterface
    {
        return $this->publicKey->getCreationTime();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->publicKey->getKeyAlgorithm();
    }

    /**
     * {@inheritdoc}
     */
    public function isSigningKey(): bool
    {
        return $this->publicKey->isSigningKey();
    }

    /**
     * {@inheritdoc}
     */
    public function isEncryptionKey(): bool
    {
        return $this->publicKey->isEncryptionKey();
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
        return $this->publicKey->getFingerprint($toHex);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(bool $toHex = false): string
    {
        return $this->publicKey->getKeyID($toHex);
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyStrength(): int
    {
        return $this->publicKey->getKeyStrength();
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
    public function getPreferredHash(
        ?HashAlgorithm $preferredHash = null
    ): HashAlgorithm
    {
        return $this->publicKey->getPreferredHash($preferredHash);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        return $this->publicKey->getSignBytes();
    }

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): PublicKeyPacketInterface
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function isEncrypted(): bool
    {
        return ($this->s2k instanceof Key\S2K) && ($this->s2kUsage !== S2kUsage::None);
    }

    /**
     * {@inheritdoc}
     */
    public function isDecrypted(): bool
    {
        return $this->keyMaterial instanceof KeyMaterialInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->isDecrypted()) {
            $this->getLogger()->debug(
                'Encrypt secret key material with passphrase.'
            );
            $s2k = new Key\S2K(
                Random::string(Key\S2K::SALT_LENGTH),
                S2kType::Iterated,
                HashAlgorithm::Sha1,
                Config::getS2kItCount()
            );
            $iv = Random::string($symmetric->blockSize());
            $cipher = $symmetric->cipherEngine();
            $cipher->setIV($iv);
            $cipher->setKey($s2k->produceKey(
                $passphrase,
                $symmetric->keySizeInByte()
            ));

            $clearText = $this->keyMaterial?->toBytes() ?? '';
            $encrypted = $cipher->encrypt(implode([
                $clearText,
                hash('sha1', $clearText, true),
            ]));
            return new self(
                $this->publicKey,
                $encrypted,
                $this->keyMaterial,
                S2kUsage::Sha1,
                $symmetric,
                $s2k,
                $iv
            );
        }
        else {
            return $this;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $passphrase): self
    {
        if ($this->isDecrypted() || !$this->isEncrypted()) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt secret key material with passphrase.'
            );
            $cipher = $this->symmetric->cipherEngine();
            $cipher->setIV($this->iv);
            $key = $this->s2k?->produceKey(
                $passphrase,
                $this->symmetric->keySizeInByte()
            ) ?? str_repeat("\x00", $this->symmetric->keySizeInByte());
            $cipher->setKey($key);
            $decrypted = $cipher->decrypt($this->keyData);

            $length = strlen($decrypted) - HashAlgorithm::Sha1->digestSize();
            $clearText = substr($decrypted, 0, $length);
            $hashText = substr($decrypted, $length);
            $hashed = hash('sha1', $clearText, true);
            if ($hashed !== $hashText) {
                throw new \UnexpectedValueException(
                    'Incorrect key passphrase.'
                );
            }

            $keyMaterial = self::readKeyMaterial($clearText, $this->publicKey);

            return new self(
                $this->publicKey,
                $this->keyData,
                $keyMaterial,
                $this->s2kUsage,
                $this->symmetric,
                $this->s2k,
                $this->iv
            );
        }
    }

    /**
     * Get S2k usage
     * 
     * @return S2kUsage
     */
    public function getS2kUsage(): S2kUsage
    {
        return $this->s2kUsage;
    }

    /**
     * Get symmetric algorithm
     * 
     * @return SymmetricAlgorithm
     */
    public function getSymmetric(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * Get string 2 key
     * 
     * @return Key\S2K
     */
    public function getS2K(): ?Key\S2K
    {
        return $this->s2k;
    }

    /**
     * Get initialization vector
     * 
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * Get key data
     * 
     * @return string
     */
    public function getKeyData(): string
    {
        return $this->keyData;
    }

    private static function readKeyMaterial(
        string $bytes, PublicKey $publicKey
    ): KeyMaterialInterface
    {
        $keyAlgorithm = $publicKey->getKeyAlgorithm();
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt, KeyAlgorithm::RsaSign
            => Key\RSASecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            KeyAlgorithm::Dsa => Key\DSASecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            KeyAlgorithm::EcDsa => Key\ECDSASecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            KeyAlgorithm::EdDsa => Key\EdDSASecretKeyMaterial::fromBytes(
                $bytes, $publicKey->getKeyMaterial()
            ),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
