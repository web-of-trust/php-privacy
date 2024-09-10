<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{
    Argon2S2K,
    Config,
    GenericS2K,
    Helper,
};
use OpenPGP\Enum\{
    AeadAlgorithm,
    PacketTag,
    S2kType,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    S2KInterface,
    SessionKeyInterface,
};
use phpseclib3\Crypt\Random;

/**
 * Implementation of the Symmetric-Key Encrypted Session Key packet (Tag 3)
 * 
 * See RFC 9580, section 5.3.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SymEncryptedSessionKey extends AbstractPacket
{
    const VERSION_4 = 4;
    const VERSION_5 = 5;
    const VERSION_6 = 6;
    const ZERO_CHAR = "\x00";

    /**
     * Constructor
     *
     * @param int $version
     * @param S2KInterface $s2k
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @param string $iv
     * @param string $encrypted
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function __construct(
        private readonly int $version,
        private readonly S2KInterface $s2k,
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private readonly ?AeadAlgorithm $aead = null,
        private readonly string $iv = '',
        private readonly string $encrypted = '',
        private readonly ?SessionKeyInterface $sessionKey = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedSessionKey);
        if ($version != self::VERSION_4 &&
            $version != self::VERSION_5 &&
            $version != self::VERSION_6
        ) {
            throw new \UnexpectedValueException(
                "Version $version of the SKESK packet is unsupported."
            );
        }
        if ($version === self::VERSION_6) {
            self::validateSymmetric($symmetric);
        }
        if ($aead instanceof AeadAlgorithm && $version < self::VERSION_5) {
            throw new \UnexpectedValueException(
                "Using AEAD with version {$version} of the SKESK packet is not allowed."
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;

        // A one-octet version number.
        $version = ord($bytes[$offset++]);
        $isV6 = $version === self::VERSION_6;

        if ($isV6) {
            // A one-octet scalar octet count of the following 5 fields.
            $offset++;
        }

        // A one-octet number describing the symmetric algorithm used.
        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));

        $aead = null;
        $ivLength = 0;
        if ($version >= self::VERSION_5) {
            // A one-octet AEAD algorithm identifier.
            $aead = AeadAlgorithm::from(ord($bytes[$offset++]));
            $ivLength = $aead->ivLength();
            if ($isV6) {
                // A one-octet scalar octet count of the following field.
                $offset++;
            }
        }

        // A string-to-key (S2K) specifier, length as defined above.
        $s2kType = S2kType::from(ord($bytes[$offset]));
        $s2k = ($s2kType === S2kType::Argon2) ?
            Argon2S2K::fromBytes(substr($bytes, $offset)) : 
            GenericS2K::fromBytes(substr($bytes, $offset));
        $offset += $s2kType->packetLength();

        // A starting initialization vector of size specified by the AEAD algorithm.
        $iv = substr($bytes, $offset, $ivLength);
        $offset += $ivLength;

        return new self(
            $version,
            $s2k,
            $symmetric,
            $aead,
            $iv,
            substr($bytes, $offset)
        );
    }

    /**
     * Encrypt session key
     *
     * @param string $password
     * @param SessionKeyInterface $sessionKey
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aead
     * @return self
     */
    public static function encryptSessionKey(
        string $password,
        ?SessionKeyInterface $sessionKey = null,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        ?AeadAlgorithm $aead = null,
    ): self
    {
        $aeadProtect = $aead instanceof AeadAlgorithm;
        $version = ($aeadProtect || Config::useV6Key()) ?
            self::VERSION_6 : self::VERSION_4;
        $symmetric = $sessionKey?->getSymmetric() ?? $symmetric;
        self::validateSymmetric($symmetric);

        $s2k = $aeadProtect && Argon2S2K::argon2Supported() ?
            Helper::stringToKey(S2kType::Argon2) :
            Helper::stringToKey(S2kType::Iterated);

        $keySize = $symmetric->keySizeInByte();
        $key = $s2k->produceKey(
            $password, $keySize
        );

        $iv = '';
        $encrypted = '';

        if ($sessionKey instanceof SessionKeyInterface) {
            if ($aeadProtect) {
                $aData = implode([
                    chr(0xc0 | PacketTag::SymEncryptedSessionKey->value),
                    chr($version),
                    chr($symmetric->value),
                    chr($aead->value),
                ]);
                $iv = Random::string($aead->ivLength());
                $encryptionKey = hash_hkdf(
                    Config::HKDF_ALGO, $key, $keySize, $aData
                );
                $cipher = $aead->cipherEngine($encryptionKey, $symmetric);
                $encrypted = $cipher->encrypt(
                    $sessionKey->getEncryptionKey(), $iv, $aData
                );
            }
            else {
                $cipher = $symmetric->cipherEngine(Config::CIPHER_MODE);
                $cipher->setKey($key);
                $cipher->setIV(
                    str_repeat(self::ZERO_CHAR, $symmetric->blockSize())
                );
                $encrypted = $cipher->encrypt($sessionKey->toBytes());
            }
        }
        else {
            $sessionKey = new Key\SessionKey($key, $symmetric);
        }

        return new self(
            $version,
            $s2k,
            $symmetric,
            $aead,
            $iv,
            $encrypted,
            $sessionKey,
        );
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
     * Get string 2 key
     *
     * @return S2KInterface
     */
    public function getS2K(): S2KInterface
    {
        return $this->s2k;
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
     * Get AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    public function getAead(): ?AeadAlgorithm
    {
        return $this->aead;
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
     * Get encrypted data
     *
     * @return string
     */
    public function getEncrypted(): string
    {
        return $this->encrypted;
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
     * Decrypt session key
     *
     * @param string $password
     * @return self
     */
    public function decrypt(string $password): self
    {
        if ($this->sessionKey instanceof SessionKeyInterface) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt symmetric key encrypted session key.'
            );
            $keySize = $this->symmetric->keySizeInByte();
            $key = $this->s2k->produceKey($password, $keySize);
            if (empty($this->encrypted)) {
                $sessionKey = new Key\SessionKey($key, $this->symmetric);
            }
            else {
                if ($this->aead instanceof AeadAlgorithm) {
                    $aData = implode([
                        chr(0xc0 | $this->getTag()->value),
                        chr($this->version),
                        chr($this->symmetric->value),
                        chr($this->aead->value),
                    ]);
                    $encryptionKey = $this->version === self::VERSION_6 ? hash_hkdf(
                        Config::HKDF_ALGO, $key, $keySize, $aData
                    ) : $key;
                    $cipher = $this->aead->cipherEngine(
                        $encryptionKey, $this->symmetric
                    );
                    $decrypted = $cipher->decrypt(
                        $this->encrypted, $this->iv, $aData
                    );
                    $sessionKey = new Key\SessionKey(
                        $decrypted, $this->symmetric
                    );
                }
                else {
                    $cipher = $this->symmetric->cipherEngine(
                        Config::CIPHER_MODE
                    );
                    $cipher->setKey($key);
                    $cipher->setIV(str_repeat(
                        self::ZERO_CHAR, $this->symmetric->blockSize()
                    ));
                    $decrypted = $cipher->decrypt($this->encrypted);
                    $sessionKeySymmetric = SymmetricAlgorithm::from(
                        ord($decrypted[0])
                    );
                    $sessionKey = new Key\SessionKey(
                        substr($decrypted, 1), $sessionKeySymmetric
                    );
                }
            }
            return new self(
                $this->version,
                $this->s2k,
                $this->symmetric,
                $this->aead,
                $this->iv,
                $this->encrypted,
                $sessionKey,
            );
        }
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        switch ($this->version) {
            case self::VERSION_6:
                return implode([
                    chr($this->version),
                    chr(3 + $this->s2k->getLength() + strlen($this->iv)),
                    chr($this->symmetric->value),
                    chr($this->aead->value),
                    chr($this->s2k->getLength()),
                    $this->s2k->toBytes(),
                    $this->iv,
                    $this->encrypted,
                ]);
            case self::VERSION_5:
                return implode([
                    chr($this->version),
                    chr($this->symmetric->value),
                    chr($this->aead->value),
                    $this->s2k->toBytes(),
                    $this->iv,
                    $this->encrypted,
                ]);
            default:
                return implode([
                    chr($this->version),
                    chr($this->symmetric->value),
                    $this->s2k->toBytes(),
                    $this->encrypted,
                ]);
        }
    }
}
