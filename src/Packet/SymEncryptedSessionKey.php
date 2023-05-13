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
use OpenPGP\Enum\{HashAlgorithm, PacketTag, S2kType, SymmetricAlgorithm};
use OpenPGP\Packet\Key\{S2K, SessionKey};

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
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SymEncryptedSessionKey extends AbstractPacket
{
    const VERSION = 4;

    /**
     * Constructor
     *
     * @param S2K $s2k
     * @param SymmetricAlgorithm $symmetric
     * @param string $encrypted
     * @param SessionKey $sessionKey
     * @return self
     */
    public function __construct(
        private readonly S2K $s2k,
        private readonly SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        private readonly string $encrypted = '',
        private readonly ?SessionKey $sessionKey = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedSessionKey);
    }

    /**
     * Reads SKESK packet from byte string
     *
     * @param string $bytes
     * @return SymEncryptedSessionKey
     */
    public static function fromBytes(string $bytes): SymEncryptedSessionKey
    {
        $offset = 0;

        // A one-octet version number. The only currently defined version is 4.
        $version = ord($bytes[$offset++]);
        if ($version != self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the SKESK packet is unsupported."
            );
        }

        // A one-octet number describing the symmetric algorithm used.
        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));

        // A string-to-key (S2K) specifier, length as defined above.
        $s2k = S2K::fromBytes(substr($bytes, $offset));

        return new SymEncryptedSessionKey(
            $s2k,
            $symmetric,
            substr($bytes, $offset + $s2k->getLength())
        );
    }

    /**
     * Encrypt session key
     *
     * @param string $password
     * @param SessionKey $sessionKey
     * @param SymmetricAlgorithm $symmetric
     * @param HashAlgorithm $hash
     * @param S2kType $s2kType
     * @return SymEncryptedSessionKey
     */
    public static function encryptSessionKey(
        string $password,
        ?SessionKey $sessionKey = null,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        HashAlgorithm $hash = HashAlgorithm::Sha1,
        S2kType $s2kType = S2kType::Iterated
    ): SymEncryptedSessionKey
    {
        $s2k = new S2K(Random::string(S2K::SALT_LENGTH), $s2kType, $hash);
        $cipher = $symmetric->cipherEngine();
        $key = $s2k->produceKey(
            $password,
            $symmetric->keySizeInByte()
        );
        if ($sessionKey instanceof SessionKey) {
            $cipher->setKey($key);
            $cipher->setIV(str_repeat("\x0", $symmetric->blockSize()));
            $encrypted = $cipher->encrypt($sessionKey->encode());
        }
        else {
            $encrypted = '';
            $sessionKey = new SessionKey($key, $symmetric);
        }

        return new SymEncryptedSessionKey(
            $s2k,
            $symmetric,
            $encrypted,
            $sessionKey
        );
    }

    /**
     * Gets S2K
     *
     * @return S2K
     */
    public function getS2K(): S2K
    {
        return $this->s2k;
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
     * Gets encrypted data
     *
     * @return string
     */
    public function getEncrypted(): string
    {
        return $this->encrypted;
    }

    /**
     * Gets session key
     *
     * @return SessionKey
     */
    public function getSessionKey(): ?SessionKey
    {
        return $this->sessionKey;
    }

    /**
     * Decrypts session key
     *
     * @param string $password
     * @return SymEncryptedSessionKey
     */
    public function decrypt(string $password): SymEncryptedSessionKey
    {
        if ($this->sessionKey instanceof SessionKey) {
            return $this;
        } else {
            $key = $this->s2k->produceKey(
                $password,
                $this->symmetric->keySizeInByte()
            );
            if (empty($this->encrypted)) {
                $sessionKey = new SessionKey($key, $this->symmetric);
            }
            else {
                $cipher = $this->symmetric->cipherEngine();
                $cipher->setKey($key);
                $cipher->setIV(str_repeat("\x0", $this->symmetric->blockSize()));
                $decrypted = $cipher->decrypt($this->encrypted);
                $sessionKeySymmetric = SymmetricAlgorithm::from(ord($decrypted[0]));
                $sessionKey = new SessionKey(substr($decrypted, 1), $sessionKeySymmetric);
            }
            return new SymEncryptedSessionKey(
                $this->s2k,
                $this->symmetric,
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
        return implode([
            chr(self::VERSION),
            chr($this->symmetric->value),
            $this->s2k->toBytes(),
            $this->encrypted,
        ]);
    }
}
