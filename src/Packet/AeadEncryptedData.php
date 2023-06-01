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

use OpenPGP\Enum\{
    AeadAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    SessionKeyInterface,
    PacketListInterface,
};

/**
 * AEAD Protected Data Packet class
 * 
 * Implementation of the Symmetrically Encrypted Authenticated Encryption with
 * Additional Data (AEAD) Protected Data Packet(Tag 20)
 * See https://tools.ietf.org/html/draft-ford-openpgp-format-00#section-2.1
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class AeadEncryptedData extends AbstractPacket implements EncryptedDataPacketInterface
{
    use EncryptedDataTrait;

    const VERSION = 1;

    /**
     * Constructor
     *
     * @param SymmetricAlgorithm $symmetricAlgorithm
     * @param AeadAlgorithm $aeadAlgorithm
     * @param int $chunkSizeByte
     * @param string $iv
     * @param string $encrypted
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly SymmetricAlgorithm $symmetricAlgorithm,
        private readonly AeadAlgorithm $aeadAlgorithm,
        private readonly int $chunkSizeByte,
        private readonly string $iv,
        private readonly string $encrypted,
        private readonly ?PacketListInterface $packetList = null
    )
    {
        parent::__construct(PacketTag::AeadEncryptedData);
    }

    /**
     * Read AEAD Protected Data packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        // A one-octet version number.
        // The only currently defined version is 1.
        $version = ord($bytes[$offset++]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the AEAD-encrypted data packet is not supported.",
          );
        }

        $symmetricAlgorithm = SymmetricAlgorithm::from(ord($bytes[$offset++]));
        $aeadAlgorithm = AeadAlgorithm::from(ord($bytes[$offset++]));
        $chunkSizeByte = ord($bytes[$offset++]);
        $iv = substr($bytes, $offset, $aeadAlgorithm->ivLength());
        $offset += $aeadAlgorithm->ivLength();
        $encrypted = substr($bytes, $offset);

        return new self(
            $symmetricAlgorithm,
            $aeadAlgorithm,
            $chunkSizeByte,
            $iv,
            $encrypted
        );
    }

    /**
     * Encrypts packet list
     *
     * @param string $key
     * @param PacketListInterface $packetList
     * @param SymmetricAlgorithm $symmetric
     * @param AeadAlgorithm $aeadAlgorithm
     * @param int $chunkSizeByte
     * @return self
     */
    public static function encryptPackets(
        string $key,
        PacketListInterface $packetList,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128,
        AeadAlgorithm $aeadAlgorithm = AeadAlgorithm::Eax,
        int $chunkSizeByte = 12
    ): self
    {
        throw new \RuntimeException(
            'AEAD encryption is not supported.'
        );
    }

    /**
     * Encrypts packet list with session key
     *
     * @param SessionKeyInterface $sessionKey
     * @param PacketListInterface $packetList
     * @return self
     */
    public static function encryptPacketsWithSessionKey(
        SessionKeyInterface $sessionKey, PacketListInterface $packetList
    ): self
    {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packetList,
            $sessionKey->getSymmetric()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr(self::VERSION),
            chr($this->symmetricAlgorithm->value),
            chr($this->aeadAlgorithm->value),
            chr($this->chunkSizeByte),
            $this->iv,
            $this->encrypted
        ]);
    }

    /**
     * Gets symmetric algorithm
     *
     * @return SymmetricAlgorithm
     */
    public function getSymmetricAlgorithm(): SymmetricAlgorithm
    {
        return $this->symmetricAlgorithm;
    }

    /**
     * Gets AEAD algorithm
     *
     * @return AeadAlgorithm
     */
    public function getAeadAlgorithm(): AeadAlgorithm
    {
        return $this->aeadAlgorithm;
    }

    /**
     * Gets chunk size byte
     *
     * @return int
     */
    public function getChunkSizeByte(): int
    {
        return $this->chunkSizeByte;
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
     * {@inheritdoc}
     */
    public function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketListInterface) {
            $this->getLogger()->debug(
                'Encrypt the packets contained in AEAD packet.'
            );
            return self::encryptPackets($key, $this->packetList, $symmetric);
        }
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt the encrypted data contained in AEAD packet.'
            );
            throw new \RuntimeException(
                'AEAD decryption is not supported.'
            );
        }
    }
}
