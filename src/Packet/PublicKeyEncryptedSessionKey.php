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

use phpseclib3\Common\Functions\Strings;
use phpseclib3\Crypt\Random;
use OpenPGP\Enum\{
    KeyAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    PublicKeyPacketInterface,
    SecretKeyPacketInterface,
    SessionKeyInterface,
    SessionKeyCryptorInterface,
};

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
     * @param SessionKeyCryptorInterface $sessionKeyCryptor
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function __construct(
        private readonly string $publicKeyID,
        private readonly KeyAlgorithm $publicKeyAlgorithm,
        private readonly SessionKeyCryptorInterface $sessionKeyCryptor,
        private readonly ?SessionKeyInterface $sessionKey = null
    )
    {
        parent::__construct(PacketTag::PublicKeyEncryptedSessionKey);
    }

    /**
     * Read PKESK packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
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

        return new self(
            $keyID,
            $keyAlgorithm,
            self::readMaterial(
                substr($bytes, $offset), $keyAlgorithm
            )
        );
    }

    /**
     * Encrypt session key
     *
     * @param PublicKeyPacketInterface $publicKey
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public static function encryptSessionKey(
        PublicKeyPacketInterface $publicKey,
        SessionKeyInterface $sessionKey
    ): self
    {
        return new self(
            $publicKey->getKeyID(),
            $publicKey->getKeyAlgorithm(),
            self::produceSessionKeyCryptor($sessionKey, $publicKey),
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
            $this->sessionKeyCryptor->toBytes(),
        ]);
    }

    /**
     * Gets public key ID
     *
     * @param bool $toHex
     * @return string
     */
    public function getPublicKeyID(bool $toHex = false): string
    {
        return $toHex ? Strings::bin2hex($this->publicKeyID) : $this->publicKeyID;
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
     * Gets session key cryptor
     *
     * @return SessionKeyCryptorInterface
     */
    public function getSessionKeyCryptor(): SessionKeyCryptorInterface
    {
        return $this->sessionKeyCryptor;
    }

    /**
     * Gets session key
     *
     * @return SessionKeyInterface
     */
    public function getSessionKey(): ?SessionKeyInterface
    {
        return $this->sessionKey;
    }

    /**
     * Decrypts session key
     *
     * @param SecretKeyPacketInterface $secretKey
     * @return self
     */
    public function decrypt(SecretKeyPacketInterface $secretKey): self
    {
        if ($this->sessionKey instanceof SessionKeyInterface) {
            return $this;
        }
        else {
            return new self(
                $secretKey->getKeyID(),
                $secretKey->getKeyAlgorithm(),
                $this->sessionKeyCryptor,
                $this->decryptSessionKey($secretKey)
            );
        }
    }

    private function decryptSessionKey(SecretKeyPacketInterface $secretKey): SessionKeyInterface
    {
        $this->getLogger()->debug(
            'Decrypt public key encrypted session key.'
        );
        switch ($this->publicKeyAlgorithm) {
            case KeyAlgorithm::RsaEncryptSign:
            case KeyAlgorithm::RsaEncrypt:
            case KeyAlgorithm::ElGamal:
            case KeyAlgorithm::Ecdh:
                return $this->sessionKeyCryptor->decryptSessionKey(
                    $secretKey
                );
            default:
                throw new \UnexpectedValueException(
                    "Public key algorithm {$this->publicKeyAlgorithm->name} of the PKESK packet is unsupported."
                );
        }
    }

    private static function produceSessionKeyCryptor(
        SessionKeyInterface $sessionKey, PublicKeyPacketInterface $publicKey
    ): SessionKeyCryptorInterface
    {
        return match($publicKey->getKeyAlgorithm()) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASessionKeyCryptor::encryptSessionKey(
                $sessionKey, $publicKey->getKeyMaterial()->getAsymmetricKey()
            ),
            KeyAlgorithm::RsaEncrypt => Key\RSASessionKeyCryptor::encryptSessionKey(
                $sessionKey, $publicKey->getKeyMaterial()->getAsymmetricKey()
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::encryptSessionKey(
                $sessionKey, $publicKey->getKeyMaterial()->getAsymmetricKey()
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::encryptSessionKey(
                $sessionKey, $publicKey->getKeyMaterial(), $publicKey->getFingerprint()
            ),
            default => throw new \UnexpectedValueException(
                "Public key algorithm {$publicKey->getKeyAlgorithm()->name} of the PKESK packet is unsupported."
            ),
        };
    }

    private static function readMaterial(
        string $bytes, KeyAlgorithm $keyAlgorithm
    ): SessionKeyCryptorInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign => Key\RSASessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::RsaEncrypt => Key\RSASessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::fromBytes($bytes),
            default => throw new \UnexpectedValueException(
                "Public key algorithm $keyAlgorithm->name of the PKESK packet is unsupported."
            ),
        };
    }
}
