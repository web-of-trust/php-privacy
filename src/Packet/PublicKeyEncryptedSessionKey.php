<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\{
    KeyAlgorithm,
    MontgomeryCurve,
    PacketTag,
};
use OpenPGP\Type\{
    KeyPacketInterface,
    SecretKeyPacketInterface,
    SessionKeyInterface,
    SessionKeyCryptorInterface,
};
use phpseclib3\Common\Functions\Strings;

/**
 * Implementation Public-Key Encrypted Session Key (PKESK) packet (Tag 1).
 * 
 * See RFC 9580, section 5.1.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicKeyEncryptedSessionKey extends AbstractPacket
{
    const VERSION_3   = 3;
    const VERSION_6   = 6;
    const KEY_ID_SIZE = 8;

    /**
     * Constructor
     *
     * @param string $publicKeyID
     * @param int $publicKeyVersion
     * @param string $publicKeyFingerprint
     * @param KeyAlgorithm $publicKeyAlgorithm
     * @param SessionKeyCryptorInterface $sessionKeyCryptor
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly string $publicKeyID,
        private readonly int $publicKeyVersion,
        private readonly string $publicKeyFingerprint,
        private readonly KeyAlgorithm $publicKeyAlgorithm,
        private readonly SessionKeyCryptorInterface $sessionKeyCryptor,
        private readonly ?SessionKeyInterface $sessionKey = null
    )
    {
        parent::__construct(PacketTag::PublicKeyEncryptedSessionKey);
        if ($version !== self::VERSION_3 && $version !== self::VERSION_6) {
            throw new \UnexpectedValueException(
                "Version $version of the PKESK packet is unsupported.",
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        $version = ord($bytes[$offset++]);

        if ($version === self::VERSION_6) {
            $length = ord($bytes[$offset++]);
            $keyVersion = ord($bytes[$offset++]);
            $keyFingerprint = substr($bytes, $offset, $length - 1);
            $offset += $length - 1;
            $keyV6 = $keyVersion === PublicKey::VERSION_6;
            $keyID = $keyV6 ?
                substr($keyFingerprint, 0, self::KEY_ID_SIZE) :
                substr($keyFingerprint, 12, self::KEY_ID_SIZE);
        }
        else {
            $keyID = substr($bytes, $offset, self::KEY_ID_SIZE);
            $offset += self::KEY_ID_SIZE;
            $keyVersion = 0;
            $keyFingerprint = '';
        }
        $keyAlgorithm = KeyAlgorithm::from(ord($bytes[$offset++]));

        return new self(
            $version,
            $keyID,
            $keyVersion,
            $keyFingerprint,
            $keyAlgorithm,
            self::readMaterial(
                substr($bytes, $offset), $keyAlgorithm
            )
        );
    }

    /**
     * Encrypt session key
     *
     * @param KeyPacketInterface $keyPacket
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public static function encryptSessionKey(
        KeyPacketInterface $keyPacket,
        SessionKeyInterface $sessionKey
    ): self
    {
        $version = $keyPacket->getVersion();
        if ($version !== self::VERSION_6) {
            $version = self::VERSION_3;
        }
        return new self(
            $version,
            $keyPacket->getKeyID(),
            $keyPacket->getVersion(),
            $keyPacket->getFingerprint(),
            $keyPacket->getKeyAlgorithm(),
            self::produceSessionKeyCryptor($sessionKey, $keyPacket),
            $sessionKey,
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $bytes = [
            chr($this->version),
        ];
        if ($this->version === self::VERSION_6) {
            $bytes[] = chr(strlen($this->publicKeyFingerprint) + 1);
            $bytes[] = chr($this->publicKeyVersion);
            $bytes[] = $this->publicKeyFingerprint;
        }
        else {
            $bytes[] = $this->publicKeyID;
        }
        $bytes[] = chr($this->publicKeyAlgorithm->value);
        $bytes[] = $this->sessionKeyCryptor->toBytes();
        return implode($bytes);
    }

    /**
     * Get version
     *
     * @return int
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * Get public key id
     *
     * @param bool $toHex
     * @return string
     */
    public function getPublicKeyID(bool $toHex = false): string
    {
        return $toHex ?
            Strings::bin2hex($this->publicKeyID) :
            $this->publicKeyID;
    }

    /**
     * Get public key version
     *
     * @return int
     */
    public function getPublicKeyVersion(): int
    {
        return $this->publicKeyVersion;
    }

    /**
     * Get public key fingerprint
     *
     * @param bool $toHex
     * @return string
     */
    public function getPublicKeyFingerprint(bool $toHex = false): string
    {
        return $toHex ?
            Strings::bin2hex($this->publicKeyFingerprint) :
            $this->publicKeyFingerprint;
    }

    /**
     * Get public key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getPublicKeyAlgorithm(): KeyAlgorithm
    {
        return $this->publicKeyAlgorithm;
    }

    /**
     * Get session key cryptor
     *
     * @return SessionKeyCryptorInterface
     */
    public function getSessionKeyCryptor(): SessionKeyCryptorInterface
    {
        return $this->sessionKeyCryptor;
    }

    /**
     * Get session key
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
                $this->version,
                $secretKey->getKeyID(),
                $secretKey->getVersion(),
                $secretKey->getFingerprint(),
                $secretKey->getKeyAlgorithm(),
                $this->sessionKeyCryptor,
                $this->decryptSessionKey($secretKey),
            );
        }
    }

    private function decryptSessionKey(
        SecretKeyPacketInterface $secretKey
    ): SessionKeyInterface
    {
        $this->getLogger()->debug(
            'Decrypt public key encrypted session key.'
        );
        switch ($this->publicKeyAlgorithm) {
            case KeyAlgorithm::RsaEncryptSign:
            case KeyAlgorithm::RsaEncrypt:
            case KeyAlgorithm::ElGamal:
            case KeyAlgorithm::Ecdh:
            case KeyAlgorithm::X25519:
            case KeyAlgorithm::X448:
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
        SessionKeyInterface $sessionKey, KeyPacketInterface $keyPacket
    ): SessionKeyCryptorInterface
    {
        return match($keyPacket->getKeyAlgorithm()) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt
            => Key\RSASessionKeyCryptor::encryptSessionKey(
                $sessionKey, $keyPacket->getKeyMaterial()->getAsymmetricKey()
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::encryptSessionKey(
                $sessionKey, $keyPacket->getKeyMaterial()->getAsymmetricKey()
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::encryptSessionKey(
                $sessionKey, $keyPacket
            ),
            KeyAlgorithm::X25519 => Key\MontgomerySessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getKeyMaterial()->getECPublicKey(),
                MontgomeryCurve::Curve25519
            ),
            KeyAlgorithm::X448 => Key\MontgomerySessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getKeyMaterial()->getECPublicKey(),
                MontgomeryCurve::Curve448
            ),
            default => throw new \UnexpectedValueException(
                "Public key algorithm {$keyPacket->getKeyAlgorithm()->name} of the PKESK packet is unsupported."
            ),
        };
    }

    private static function readMaterial(
        string $bytes, KeyAlgorithm $keyAlgorithm
    ): SessionKeyCryptorInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt
            => Key\RSASessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::X25519 => Key\MontgomerySessionKeyCryptor::fromBytes(
                $bytes, MontgomeryCurve::Curve25519
            ),
            KeyAlgorithm::X448 => Key\MontgomerySessionKeyCryptor::fromBytes(
                $bytes, MontgomeryCurve::Curve448
            ),
            default => throw new \UnexpectedValueException(
                "Public key algorithm {$keyAlgorithm->name} of the PKESK packet is unsupported."
            ),
        };
    }
}
