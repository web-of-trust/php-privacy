<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\{
    Config,
    Helper,
};
use OpenPGP\Enum\{
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    EncryptedDataPacketInterface,
    PacketListInterface,
    SessionKeyInterface,
};

/**
 * SymEncryptedData packet (tag 9) represents a Symmetrically Encrypted Data packet.
 * See RFC 4880, sections 5.7 and 5.13.
 * 
 * The encrypted contents will consist of more OpenPGP packets.
 * The Symmetrically Encrypted Data packet contains data encrypted
 * with a symmetric-key algorithm.
 * When it has been decrypted, it contains other packets
 * (usually a literal data packet or compressed data packet,
 * but in theory other Symmetrically Encrypted Data packets
 * or sequences of packets that form whole OpenPGP messages).
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class SymEncryptedData extends AbstractPacket implements EncryptedDataPacketInterface
{
    use EncryptedDataTrait;

    const ZERO_CHAR   = "\x00";
    const CIPHER_MODE = 'cfb';

    /**
     * Constructor
     *
     * @param string $encrypted
     * @param PacketListInterface $packetList
     * @return self
     */
    public function __construct(
        private readonly string $encrypted,
        private readonly ?PacketListInterface $packetList = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedData);
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /**
     * Encrypt packet list
     *
     * @param string $key
     * @param PacketListInterface $packetList
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    public static function encryptPackets(
        string $key,
        PacketListInterface $packetList,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        $cipher = $symmetric->cipherEngine(self::CIPHER_MODE);
        $cipher->setKey($key);
        $cipher->setIV(str_repeat(self::ZERO_CHAR, $symmetric->blockSize()));
        $prefix = $cipher->encrypt(Helper::generatePrefix($symmetric));
        $cipher->setIV(substr($prefix, 2));

        return new self(
            $prefix . $cipher->encrypt($packetList->encode()), $packetList
        );
    }

    /**
     * Encrypt packet list with session key
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
        return $this->encrypted;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if (!Config::allowUnauthenticated()) {
            throw new \UnexpectedValueException(
                'Message is not authenticated.'
            );
        }
        if ($this->packetList instanceof PacketListInterface) {
            return $this;
        }
        else {
            $blockSize = $symmetric->blockSize();
            $cipher = $symmetric->cipherEngine(self::CIPHER_MODE);
            $cipher->setKey($key);
            $cipher->setIV(substr($this->encrypted, 2, $blockSize));

            return new self(
                $this->encrypted,
                PacketList::decode(
                    $cipher->decrypt(substr($this->encrypted, $blockSize + 2))
                )
            );
        }
    }
}
