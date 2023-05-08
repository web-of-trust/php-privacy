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

use phpseclib3\Crypt\Random;
use OpenPGP\Enum\{
    HashAlgorithm, KeyAlgorithm, PacketTag, S2kType, S2kUsage, SymmetricAlgorithm
};
use OpenPGP\Packet\Key\{
    KeyParametersInterface,
    RSASecretParameters,
    DSASecretParameters,
    ElGamalSecretParameters,
    ECDHSecretParameters,
    ECDSASecretParameters,
    S2K,
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
    private KeyParametersInterface? $keyParameters;

    /**
     * Constructor
     *
     * @param PublicKey $publicKey
     * @param S2kUsage $s2kUsage
     * @param SymmetricAlgorithm $symmetric
     * @param S2K $s2k
     * @param string $iv
     * @param string $keyData
     * @param KeyParametersInterface $keyParameters
     * @return self
     */
    public function __construct(
        private PublicKey $publicKey,
        private S2kUsage $s2kUsage = S2kUsage::Sha1,
        private SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private ?S2K $s2k = null,
        private string $iv = ''
        private string $keyData = '',
        ?KeyParametersInterface $keyParameters = null
    )
    {
        parent::__construct(PacketTag::SecretKey);
        $this->keyParameters = $keyParameters;
    }

    /**
     * Read secret key packets from byte string
     *
     * @param string $bytes
     * @return SecretKey
     */
    public static function fromBytes(string $bytes): SecretKey
    {
        $publicKey = PublicKey::fromBytes($bytes);
        $offset = strlen($publicKey->toBytes());

        $s2kUsage = S2kUsage::from(ord($bytes[$offset++]));

        $s2k = null;
        switch ($s2kUsage) {
            case S2kUsage::Checksum:
            case S2kUsage::Sha1:
                $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));
                $s2k = S2K::fromBytes(substr($bytes, $offset++));
                $offset += $s2k->getLength();
                break;
            default:
                $symmetric = SymmetricAlgorithm::Plaintext;
                break;
        }

        $iv = '';
        if ($s2k instanceof S2K) {
            $iv = substr($bytes, $offset, $symmetric->blockSize());
            $offset += $symmetric->blockSize();
        }

        $keyParameters = null;
        $keyData = substr($bytes, $offset);
        if ($s2kUsage === S2kUsage::None) {
            $keyParameters = self::readKeyParameters($keyData, $publicKey);
        }

        return new SecretKey(
            $publicKey,
            $s2kUsage,
            $symmetric,
            $s2k,
            $iv,
            $keyData,
            $keyParameters,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        if ($this->s2kUsage !== S2kUsage::None && $this->s2k instanceof S2K) {
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
    public function getCreationTime(): int
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
    public function getKeyParameters(): ?KeyParametersInterface
    {
        return $this->keyParameters;
    }

    /**
     * {@inheritdoc}
     */
    public function getFingerprint(): string
    {
        return $this->publicKey->getFingerprint();
    }

    /**
     * {@inheritdoc}
     */
    public function getKeyID(): string
    {
        return $this->publicKey->getKeyID();
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
    public function getPublicKey(): SecretKeyPacketInterface
    {
        return $this->publicKey;
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
    ): SecretKeyPacketInterface
    {
        if ($this->keyParameters instanceof KeyParametersInterface ) {
            $s2k = new S2K(Random::string(S2K::SALT_LENGTH), $s2kType, $hash);
            $iv = Random::string($symmetric->blockSize());
            $key = $s2k->produceKey(
                $passphrase,
                $symmetric->keySizeInByte()
            );
            $cipher = $symmetric->cipherEngine();
            $cipher->setIV($iv)->setKey($key);

            $clearText = $this->keyParameters->toBytes();
            $encrypted = $cipher->encrypt(implode([
                $clearText,
                sha1($clearText, true),
            ]));
            return new SecretKey(
                $this->publicKey,
                $s2kUsage,
                $symmetric,
                $s2k,
                $iv,
                $encrypted,
                $keyParameters,
            );
        }
        else {
            return $this;
        }
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $passphrase): SecretKeyPacketInterface
    {
        if ($this->keyParameters instanceof KeyParametersInterface ) {
            return $this;
        }
        else {
            $key = $this->s2k->produceKey(
                $passphrase,
                $this->symmetric->keySizeInByte()
            );
            $cipher = $this->symmetric->cipherEngine();
            $cipher->setKey($key);
            $decrypted = $cipher->decrypt($this->keyData);
            $clearText = substr($decrypted, 0, HashAlgorithm::Sha1->digestSize());
            $hashText = substr(
                $decrypted, strlen($decrypted) - HashAlgorithm::Sha1->digestSize()
            );
            $hashed = sha1($clearText, true);
            if ($hashed !== $hashText) {
                throw new \InvalidArgumentException('Incorrect key passphrase');
            }
            
            $keyParameters = self::readKeyParameters($clearText, $this->publicKey);

            return new SecretKey(
                $this->publicKey,
                $this->s2kUsage,
                $this->symmetric,
                $this->s2k,
                $this->iv,
                $this->keyData,
                $keyParameters,
            );
        }
    }

    private static function readKeyParameters(
        string $bytes, PublicKey $publicKey
    ): KeyParametersInterface
    {
        $keyAlgorithm = $publicKey->getKeyAlgorithm();
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::RsaEncrypt => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::RsaSign => RSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::ElGamal => ElGamalSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::Dsa => DSASecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::Ecdh => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::EcDsa => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            KeyAlgorithm::EdDsa => ECDHSecretParameters::fromBytes($bytes, $publicKey->getKeyParameters()),
            default => throw new \UnexpectedValueException(
                "Unsupported PGP public key algorithm encountered",
            ),
        };
    }
}
