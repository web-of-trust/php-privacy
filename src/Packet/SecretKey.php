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
use phpseclib3\Crypt\Random;
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
    ForSigningInterface,
    KeyPacketInterface,
    KeyParametersInterface,
    SecretKeyPacketInterface,
    SubkeyPacketInterface
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
class SecretKey extends AbstractPacket implements SecretKeyPacketInterface, ForSigningInterface
{
    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param S2kUsage $s2kUsage
     * @param string $keyData
     * @param KeyParametersInterface $keyParameters
     * @param SymmetricAlgorithm $symmetric
     * @param Key\S2K $s2k
     * @param string $iv
     * @param bool $isSubkey
     * @return self
     */
    public function __construct(
        private readonly PublicKey $publicKey,
        private readonly string $keyData = '',
        private readonly ?KeyParametersInterface $keyParameters = null,
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

        $keyParameters = null;
        $keyData = substr($bytes, $offset);
        if ($s2kUsage === S2kUsage::None) {
            $keyParameters = self::readKeyParameters($keyData, $publicKey);
        }

        return new self(
            $publicKey,
            $keyData,
            $keyParameters,
            $s2kUsage,
            $symmetric,
            $s2k,
            $iv
        );
    }

    /**
     * Generate secret key packet
     *
     * @param KeyAlgorithm $algorithm
     * @param RSAKeySize $rsaKeySize
     * @param DHKeySize $dhKeySize
     * @param CurveOid $curveOid
     * @param DateTime $time
     * @return self
     */
    public static function generate(
        KeyAlgorithm $keyAlgorithm = KeyAlgorithm::RsaEncryptSign,
        RSAKeySize $rsaKeySize = RSAKeySize::S2048,
        DHKeySize $dhKeySize = DHKeySize::L2048_N224,
        CurveOid $curveOid = CurveOid::Secp521r1,
        ?DateTime $time = null
    ): self
    {
        $keyParameters = match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASecretParameters::generate($rsaKeySize),
            KeyAlgorithm::RsaEncrypt => Key\RSASecretParameters::generate($rsaKeySize),
            KeyAlgorithm::RsaSign => Key\RSASecretParameters::generate($rsaKeySize),
            KeyAlgorithm::ElGamal => Key\ElGamalSecretParameters::generate($dhKeySize),
            KeyAlgorithm::Dsa => Key\DSASecretParameters::generate($dhKeySize),
            KeyAlgorithm::Ecdh => Key\ECDHSecretParameters::generate($curveOid),
            KeyAlgorithm::EcDsa => Key\ECDSASecretParameters::generate($curveOid),
            KeyAlgorithm::EdDsa => Key\EdDSASecretParameters::generate($curveOid),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
        return new self(
            new PublicKey(
                $time ?? new DateTime(),
                $keyParameters->getPublicParams(),
                $keyAlgorithm
            ),
            $keyParameters->toBytes(),
            $keyParameters
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
    public function getCreationTime(): DateTime
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
    public function getKeyParameters(): ?KeyParametersInterface
    {
        return $this->keyParameters;
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
    public function getPublicKey(): KeyPacketInterface
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
        return $this->keyParameters instanceof KeyParametersInterface;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        string $passphrase,
        S2kUsage $s2kUsage = S2kUsage::Sha1,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        HashAlgorithm $hash = HashAlgorithm::Sha1,
        S2kType $s2kType = S2kType::Iterated
    ): self
    {
        if ($this->keyParameters instanceof KeyParametersInterface) {
            $this->getLogger()->debug(
                'Encrypt secret key with passphrase.'
            );
            $s2k = new Key\S2K(Random::string(Key\S2K::SALT_LENGTH), $s2kType, $hash);
            $iv = Random::string($symmetric->blockSize());
            $cipher = $symmetric->cipherEngine();
            $cipher->setIV($iv);
            $cipher->setKey($s2k->produceKey(
                $passphrase,
                $symmetric->keySizeInByte()
            ));

            $clearText = $this->keyParameters->toBytes();
            $encrypted = $cipher->encrypt(implode([
                $clearText,
                hash('sha1', $clearText, true),
            ]));
            return new self(
                $this->publicKey,
                $encrypted,
                $this->keyParameters,
                $s2kUsage,
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
        if ($this->keyParameters instanceof KeyParametersInterface) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt secret key with passphrase.'
            );
            $cipher = $this->symmetric->cipherEngine();
            $cipher->setIV($this->iv);
            $cipher->setKey($this->s2k->produceKey(
                $passphrase,
                $this->symmetric->keySizeInByte()
            ));
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

            $keyParameters = self::readKeyParameters($clearText, $this->publicKey);

            return new self(
                $this->publicKey,
                $this->keyData,
                $keyParameters,
                $this->s2kUsage,
                $this->symmetric,
                $this->s2k,
                $this->iv
            );
        }
    }

    /**
     * Gets S2k usage
     * 
     * @return S2kUsage
     */
    public function getS2kUsage(): S2kUsage
    {
        return $this->s2kUsage;
    }

    /**
     * Gets symmetric algorithm
     * 
     * @return SymmetricAlgorithm
     */
    public function getSymmetric(): SymmetricAlgorithm
    {
        return $this->symmetric;
    }

    /**
     * Gets string 2 key
     * 
     * @return Key\S2K
     */
    public function getS2K(): ?Key\S2K
    {
        return $this->s2k;
    }

    /**
     * Gets initialization vector
     * 
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * Gets key data
     * 
     * @return string
     */
    public function getKeyData(): string
    {
        return $this->keyData;
    }

    private static function readKeyParameters(
        string $bytes, PublicKey $publicKey
    ): KeyParametersInterface
    {
        $keyAlgorithm = $publicKey->getKeyAlgorithm();
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::RsaEncrypt => Key\RSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::RsaSign => Key\RSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::Dsa => Key\DSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::EcDsa => Key\ECDSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            KeyAlgorithm::EdDsa => Key\EdDSASecretParameters::fromBytes(
                $bytes, $publicKey->getKeyParameters()
            ),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
