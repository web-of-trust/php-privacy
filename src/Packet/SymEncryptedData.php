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
use OpenPGP\Common\Helper;
use OpenPGP\Enum\{PacketTag, SymmetricAlgorithm};

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
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SymEncryptedData extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $encrypted
     * @param PacketList $packets
     * @return self
     */
    public function __construct(
        private string $encrypted, private ?PacketList $packets = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedData);
    }

    /**
     * Read encrypted data packet from byte string
     *
     * @param string $bytes
     * @return SymEncryptedData
     */
    public static function fromBytes(string $bytes): SymEncryptedData
    {
        return new SymEncryptedData($bytes);
    }

    /**
     * Encrypts packet list
     *
     * @param string $key
     * @param PacketList $packets
     * @param SymmetricAlgorithm $symmetric
     * @return SymEncryptedData
     */
    public static function encryptPackets(
        string $key,
        PacketList $packets,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): SymEncryptedData
    {
        $cipher = $symmetric->cipherEngine();
        $cipher->setKey($key);
        $cipher->setIV(str_repeat("\0", $symmetric->blockSize()));
        $prefix = $cipher->encrypt(Helper::generatePrefix($symmetric));
        $cipher->setIV(substr($prefix, 2));

        return new SymEncryptedData(
            $prefix . $cipher->encrypt($packets->encode()), $packets
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
     * Gets decrypted packets contained within.
     *
     * @return PacketList
     */
    public function getPackets(): ?PacketList
    {
        return $this->packets;
    }

    /**
     * Encrypts the payload in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return SymEncryptedData
     */
    public function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): SymEncryptedData
    {
        if ($this->packets instanceof PacketList) {
            return self::encryptPackets($key, $this->packets, $symmetric);
        }
        return $this;
    }

    /**
     * Decrypts the encrypted data contained in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @param bool $allowUnauthenticated
     * @return SymEncryptedData
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
        bool $allowUnauthenticated = false
    ): SymEncryptedData
    {
        if (!$allowUnauthenticated) {
          throw new \RuntimeException('Message is not authenticated.');
        }
        $blockSize = $symmetric->blockSize();
        $cipher = $symmetric->cipherEngine();
        $cipher->setKey($key);
        $cipher->setIV(substr($this->encrypted, 2, $blockSize));

        return new SymEncryptedData(
            $this->encrypted,
            PacketList::decode(
                $cipher->decrypt(substr($this->encrypted, $blockSize + 2))
            )
        );
    }
}
