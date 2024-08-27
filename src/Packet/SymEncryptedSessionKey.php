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
    Helper,
    S2K,
};
use OpenPGP\Enum\{
    AeadAlgorithm,
    HashAlgorithm,
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
 * SymEncryptedSessionKey packet class
 * 
 * Implementation of the Symmetric-Key Encrypted Session Key packet (Tag 3)
 * See RFC 4880, section 5.3.
 * 
 * The Symmetric-Key Encrypted Session Key packet holds the
 * symmetric-key encryption of a session key used to encrypt a message.
 * Zero or more Public-Key Encrypted Session Key packets and/or
 * Symmetric-Key Encrypted Session Key packets may precede a
 * Symmetrically Encrypted Data packet that holds an encrypted message.
 * The message is encrypted with a session key, and the session key is
 * itself encrypted and stored in the Encrypted Session Key packet or
 * the Symmetric-Key Encrypted Session Key packet.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SymEncryptedSessionKey extends AbstractPacket
{
    const VERSION_4 = 4;
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
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;

        // A one-octet version number. The only currently defined version is 4.
        $version = ord($bytes[$offset++]);
        if ($version != self::VERSION_4 && $version != self::VERSION_6) {
            throw new \UnexpectedValueException(
                "Version $version of the SKESK packet is unsupported."
            );
        }
        $isV6 = $version === self::VERSION_6;

        if ($isV6) {
            // A one-octet scalar octet count of the following 5 fields.
            $offset++;
        }

        // A one-octet number describing the symmetric algorithm used.
        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));

        $aead = null;
        $ivLength = 0;
        if ($isV6) {
            // A one-octet AEAD algorithm identifier.
            $aead = AeadAlgorithm::from(ord($bytes[$offset++]));
            $ivLength = $aead->ivLength();
        }

        // A string-to-key (S2K) specifier, length as defined above.
        $s2kType = S2kType::from(ord($bytes[$offset]));
        $s2k = ($s2kType === S2kType::Argon2) ?
            Argon2S2K::fromBytes(substr($bytes, $offset)) : 
            S2K::fromBytes(substr($bytes, $offset));
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
        $version = $aeadProtect ? self::VERSION_6 : self::VERSION_4;
        $s2k = $aeadProtect ?
            Helper::stringToKey(S2kType::Argon2) :
            Helper::stringToKey(S2kType::Iterated);

        $keySize = $symmetric->keySizeInByte();
        $key = $s2k->produceKey(
            $password,
            $keySize
        );

        $iv = '';
        $encrypted = '';

        if ($sessionKey instanceof SessionKeyInterface) {
            if ($aeadProtect) {
                $adata = implode([
                    chr(0xc0 | PacketTag::SymEncryptedSessionKey->value),
                    chr($version),
                    chr($symmetric->value),
                    chr($aead->value),
                ]);
                $iv = Random::string($aead->ivLength());
                $encryptionKey = hash_hkdf(
                    Config::HKDF_ALGO, $key, $keySize, $adata
                );
                $cipher = $aead->cipherEngine($encryptionKey, $symmetric);
                $encrypted = $cipher->encrypt($sessionKey->getEncryptionKey(), $iv, $adata);
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
            $sessionKey
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
            $key = $this->s2k->produceKey(
                $password,
                $keySize
            );
            if (empty($this->encrypted)) {
                $sessionKey = new Key\SessionKey($key, $this->symmetric);
            }
            else {
                if (($this->version === self::VERSION_6)) {
                    $adata = implode([
                        chr(0xc0 | $this->getTag()->value),
                        chr($this->version),
                        chr($this->symmetric->value),
                        chr($this->aead->value),
                    ]);
                    $encryptionKey = hash_hkdf(
                        Config::HKDF_ALGO, $key, $keySize, $adata
                    );
                    $cipher = $this->aead->cipherEngine($encryptionKey, $this->symmetric);
                    $decrypted = $cipher->decrypt($this->encrypted, $this->iv, $adata);
                    $sessionKey = new Key\SessionKey(
                        $decrypted, $this->symmetric
                    );
                }
                else {
                    $cipher = $this->symmetric->cipherEngine(Config::CIPHER_MODE);
                    $cipher->setKey($key);
                    $cipher->setIV(
                        str_repeat(self::ZERO_CHAR, $this->symmetric->blockSize())
                    );
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
        return ($this->version === self::VERSION_6) ?
            implode([
                chr($this->version),
                chr($this->symmetric->value),
                chr($this->aead->value),
                $this->s2k->toBytes(),
                $this->iv,
                $this->encrypted,
            ]) : implode([
                chr($this->version),
                chr($this->symmetric->value),
                $this->s2k->toBytes(),
                $this->encrypted,
            ]);
    }
}
