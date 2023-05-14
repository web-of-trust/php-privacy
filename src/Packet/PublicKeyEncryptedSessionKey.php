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
use OpenPGP\Enum\{KeyAlgorithm, PacketTag, SymmetricAlgorithm};

/**
 * PublicKeyEncryptedSessionKey represents a Public-Key Encrypted Session Key packet.
 * See RFC 4880, section 5.1.
 * 
 * A Public-Key Encrypted Session Key packet holds the session key used to encrypt a message.
 * Zero or more Public-Key Encrypted Session Key packets and/or Symmetric-Key Encrypted Session Key
 * packets may precede a Symmetrically Encrypted Data Packet, which holds an encrypted message.
 * The message is encrypted with the session key, and the session key is itself
 * encrypted and stored in the Encrypted Session Key packet(s).
 * The Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
 * Session Key packet for each OpenPGP key to which the message is encrypted.
 * The recipient of the message finds a session key that is encrypted to their public key,
 * decrypts the session key, and then uses the session key to decrypt the message.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicKeyEncryptedSessionKey extends AbstractPacket
{
    const VERSION = 3;

    /**
     * Constructor
     *
     * @param string $publicKeyID
     * @param KeyAlgorithm $publicKeyAlgorithm
     * @param SessionKeyParametersInterface $sessionKeyParameters
     * @param SessionKey $sessionKey
     * @return self
     */
    public function __construct(
        private readonly string $publicKeyID,
        private readonly KeyAlgorithm $publicKeyAlgorithm,
        private readonly Key\SessionKeyParametersInterface $sessionKeyParameters,
        private readonly ?Key\SessionKey $sessionKey = null
    )
    {
        parent::__construct(PacketTag::PublicKeyEncryptedSessionKey);
    }

    /**
     * Read PKESK packet from byte string
     *
     * @param string $bytes
     * @return PublicKeyEncryptedSessionKey
     */
    public static function fromBytes(string $bytes): PublicKeyEncryptedSessionKey
    {
        $offset = 0;
        $version = ord($bytes[$offset++]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the PKESK packet is unsupported.",
            );
        }

        $keyID = substr($bytes, $offset, 8);
        $offset += 8;
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        return new PublicKeyEncryptedSessionKey(
            $keyID,
            $keyAlgorithm,
            self::readParameters(
                substr($bytes, $offset), $keyAlgorithm
            )
        );
    }

    /**
     * Encrypt session key
     *
     * @param PublicKey $publicKey
     * @param SessionKey $sessionKey
     * @return PublicKeyEncryptedSessionKey
     */
    public static function encryptSessionKey(
        PublicKey $publicKey,
        Key\SessionKey $sessionKey
    ): PublicKeyEncryptedSessionKey
    {
        return new PublicKeyEncryptedSessionKey(
            $publicKey->getKeyID(),
            $publicKey->getKeyAlgorithm(),
            self::produceParameters($sessionKey, $publicKey),
            $sessionKey
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::VERSION),
            $this->publicKeyID,
            chr($this->publicKeyAlgorithm->value),
            $this->sessionKeyParameters->encode(),
        ]);
    }

    /**
     * Gets public key ID
     *
     * @return string
     */
    public function getPublicKeyID(): string
    {
        return $this->publicKeyID;
    }

    /**
     * Gets public key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getPublicKeyAlgorithm(): KeyAlgorithm
    {
        return $this->publicKeyAlgorithm;
    }

    /**
     * Gets session key parameters
     *
     * @return Key\SessionKeyParametersInterface
     */
    public function getSessionKeyParameters(): Key\SessionKeyParametersInterface
    {
        return $this->sessionKeyParameters;
    }

    /**
     * Gets session key
     *
     * @return Key\SessionKey
     */
    public function getSessionKey(): ?Key\SessionKey
    {
        return $this->sessionKey;
    }

    /**
     * Decrypts session key
     *
     * @param SecretKey $secretKey
     * @return PublicKeyEncryptedSessionKey
     */
    public function decrypt(SecretKey $secretKey): PublicKeyEncryptedSessionKey
    {
        if ($this->sessionKey instanceof Key\SessionKey) {
            return $this;
        }
        else {
            return new PublicKeyEncryptedSessionKey(
                $secretKey->getKeyID(),
                $secretKey->getKeyAlgorithm(),
                $this->sessionKeyParameters,
                $this->decryptSessionKey($secretKey)
            );
        }
    }

    private function decryptSessionKey(SecretKey $secretKey): Key\SessionKey
    {
        return match($this->publicKeyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => $this->sessionKeyParameters->decrypt(
                $secretKey->getKeyParameters()->getPrivateKey()
            ),
            KeyAlgorithm::RsaEncrypt => $this->sessionKeyParameters->decrypt(
                $secretKey->getKeyParameters()->getPrivateKey()
            ),
            KeyAlgorithm::ElGamal => $this->sessionKeyParameters->decrypt(
                $secretKey->getKeyParameters()->getPrivateKey()
            ),
            KeyAlgorithm::Ecdh => $this->sessionKeyParameters->decrypt(
                $secretKey->getKeyParameters(), $secretKey->getFingerprint()
            ),
            default => throw new \UnexpectedValueException(
                "Public key algorithm $keyAlgorithm->name of the PKESK packet is unsupported."
            ),
        };
    }

    private static function produceParameters(
        Key\SessionKey $sessionKey, PublicKey $publicKey
    ): Key\SessionKeyParametersInterface
    {
        return match($publicKey->getKeyAlgorithm()) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASessionKeyParameters::produceParameters(
                $sessionKey, $publicKey->getKeyParameters()->getPublicKey()
            ),
            KeyAlgorithm::RsaEncrypt => Key\RSASessionKeyParameters::produceParameters(
                $sessionKey, $publicKey->getKeyParameters()->getPublicKey()
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyParameters::produceParameters(
                $sessionKey, $publicKey->getKeyParameters()->getPublicKey()
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyParameters::produceParameters(
                $sessionKey, $publicKey->getKeyParameters(), $publicKey->getFingerprint()
            ),
            default => throw new \UnexpectedValueException(
                "Public key algorithm $keyAlgorithm->name of the PKESK packet is unsupported."
            ),
        };
    }

    private static function readParameters(
        string $bytes, KeyAlgorithm $keyAlgorithm
    ): Key\SessionKeyParametersInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASessionKeyParameters::fromBytes($bytes),
            KeyAlgorithm::RsaEncrypt => Key\RSASessionKeyParameters::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyParameters::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyParameters::fromBytes($bytes),
            default => throw new \UnexpectedValueException(
                "Public key algorithm $keyAlgorithm->name of the PKESK packet is unsupported."
            ),
        };
    }
}
