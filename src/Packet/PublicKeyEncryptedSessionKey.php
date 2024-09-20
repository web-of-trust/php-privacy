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
     * @param string $keyID
     * @param int $keyVersion
     * @param string $keyFingerprint
     * @param KeyAlgorithm $keyAlgorithm
     * @param SessionKeyCryptorInterface $sessionKeyCryptor
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly string $keyID,
        private readonly int $keyVersion,
        private readonly string $keyFingerprint,
        private readonly KeyAlgorithm $keyAlgorithm,
        private readonly SessionKeyCryptorInterface $sessionKeyCryptor,
        private readonly ?SessionKeyInterface $sessionKey = null
    )
    {
        parent::__construct(PacketTag::PublicKeyEncryptedSessionKey);
        if ($version !== self::VERSION_3 && $version !== self::VERSION_6) {
            throw new \InvalidArgumentException(
                "Version {$version} of the PKESK packet is unsupported.",
            );
        }
        if ($version === self::VERSION_6 &&
            $keyAlgorithm === KeyAlgorithm::ElGamal
        ) {
            throw new \InvalidArgumentException(
                "Public key {$keyAlgorithm->name} cannot be used with v{$version} PKESK packet.",
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
            $keyID = $keyVersion === PublicKey::VERSION_6 ?
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
                substr($bytes, $offset), $version, $keyAlgorithm
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
        $version = $keyPacket->getVersion() === self::VERSION_6 ?
            self::VERSION_6 : self::VERSION_3;
        return new self(
            $version,
            $keyPacket->getKeyID(),
            $keyPacket->getVersion(),
            $keyPacket->getFingerprint(),
            $keyPacket->getKeyAlgorithm(),
            self::produceSessionKeyCryptor(
                $sessionKey, $keyPacket, $version
            ),
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
            $bytes[] = chr(strlen($this->keyFingerprint) + 1);
            $bytes[] = chr($this->keyVersion);
            $bytes[] = $this->keyFingerprint;
        }
        else {
            $bytes[] = $this->keyID;
        }
        $bytes[] = chr($this->keyAlgorithm->value);
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
    public function getKeyID(bool $toHex = false): string
    {
        return $toHex ?
            Strings::bin2hex($this->keyID) :
            $this->keyID;
    }

    /**
     * Get public key version
     *
     * @return int
     */
    public function getKeyVersion(): int
    {
        return $this->keyVersion;
    }

    /**
     * Get public key fingerprint
     *
     * @param bool $toHex
     * @return string
     */
    public function getKeyFingerprint(bool $toHex = false): string
    {
        return $toHex ?
            Strings::bin2hex($this->keyFingerprint) :
            $this->keyFingerprint;
    }

    /**
     * Get public key algorithm
     *
     * @return KeyAlgorithm
     */
    public function getKeyAlgorithm(): KeyAlgorithm
    {
        return $this->keyAlgorithm;
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
        switch ($this->keyAlgorithm) {
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
                throw new \RuntimeException(
                    "Public key algorithm {$this->keyAlgorithm->name} of the PKESK packet is unsupported."
                );
        }
    }

    private static function produceSessionKeyCryptor(
        SessionKeyInterface $sessionKey,
        KeyPacketInterface $keyPacket,
        int $pkeskVersion,
    ): SessionKeyCryptorInterface
    {
        return match($keyPacket->getKeyAlgorithm()) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt
            => Key\RSASessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getKeyMaterial()->getAsymmetricKey(),
                $pkeskVersion,
            ),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getKeyMaterial()->getAsymmetricKey(),
            ),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::encryptSessionKey(
                $sessionKey, $keyPacket, $pkeskVersion
            ),
            KeyAlgorithm::X25519 => Key\MontgomerySessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getECKeyMaterial()->getECKey(),
                $pkeskVersion,
                MontgomeryCurve::Curve25519,
            ),
            KeyAlgorithm::X448 => Key\MontgomerySessionKeyCryptor::encryptSessionKey(
                $sessionKey,
                $keyPacket->getECKeyMaterial()->getECKey(),
                $pkeskVersion,
                MontgomeryCurve::Curve448,
            ),
            default => throw new \RuntimeException(
                "Public key algorithm {$keyPacket->getKeyAlgorithm()->name} of the PKESK packet is unsupported."
            ),
        };
    }

    private static function readMaterial(
        string $bytes, int $pkeskVersion, KeyAlgorithm $keyAlgorithm
    ): SessionKeyCryptorInterface
    {
        return match($keyAlgorithm) {
            KeyAlgorithm::RsaEncryptSign, KeyAlgorithm::RsaEncrypt
            => Key\RSASessionKeyCryptor::fromBytes($bytes, $pkeskVersion),
            KeyAlgorithm::ElGamal => Key\ElGamalSessionKeyCryptor::fromBytes($bytes),
            KeyAlgorithm::Ecdh => Key\ECDHSessionKeyCryptor::fromBytes($bytes, $pkeskVersion),
            KeyAlgorithm::X25519 => Key\MontgomerySessionKeyCryptor::fromBytes(
                $bytes, $pkeskVersion, MontgomeryCurve::Curve25519
            ),
            KeyAlgorithm::X448 => Key\MontgomerySessionKeyCryptor::fromBytes(
                $bytes, $pkeskVersion, MontgomeryCurve::Curve448
            ),
            default => throw new \RuntimeException(
                "Public key algorithm {$keyAlgorithm->name} of the PKESK packet is unsupported."
            ),
        };
    }
}
