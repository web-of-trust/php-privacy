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

use OpenPGP\Enum\PacketTag;
use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Packet\Key\S2K;
use OpenPGP\Packet\Key\SessionKey;

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
        private S2K $s2k,
        private SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        private string $encrypted = '',
        private ?SessionKey $sessionKey = null
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
            throw new \InvalidArgumentException(
                "Version $version of the SKESK packet is unsupported."
            );
        }

        // A one-octet number describing the symmetric algorithm used.
        $symmetric = SymmetricAlgorithm::from(ord($bytes[$offset++]));

        // A string-to-key (S2K) specifier, length as defined above.
        $s2k = S2K::fromBytes(substr($bytes, $offset));

        return new SymEncryptedSessionKey(
            $s2k, $symmetric, substr($bytes, $offset + $s2k->getLength())
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
     * @return SymEncryptedSessionKey
     */
    public function decrypt(string $password): SymEncryptedSessionKey
    {
        if (null != $this->sessionKey) {
            return $this;
        } else {
            $key = $this->s2k->produceKey(
                $password,
                $this->symmetric->keySizeInByte()
            );
            $cipher = $this->symmetric->cipherEngine();
            $cipher->setKey($key);
            $decrypted = $cipher->decrypt($this->encrypted);
            $sessionKeySymmetric = SymmetricAlgorithm::from(ord($decrypted[0]));
            return SymEncryptedSessionKey(
                $this->s2k,
                $this->symmetric,
                $this->encrypted,
                new SessionKey(substr($decrypted, 1), $sessionKeySymmetric)
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
