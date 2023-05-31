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

use OpenPGP\Common\Helper;
use OpenPGP\Enum\{
    HashAlgorithm,
    PacketTag,
    SymmetricAlgorithm,
};
use OpenPGP\Type\{
    PacketListInterface,
    SessionKeyInterface,
};

/**
 * Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
 * See RFC 4880, section 5.13.
 * 
 * The Symmetrically Encrypted Integrity Protected Data packet is a variant
 * of the Symmetrically Encrypted Data packet.
 * It is a new feature created for OpenPGP that addresses the problem of
 * detecting a modification to encrypted data.
 * It is used in combination with a Modification Detection Code packet.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class SymEncryptedIntegrityProtectedData extends AbstractPacket
{
    const VERSION = 1;

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
        parent::__construct(PacketTag::SymEncryptedIntegrityProtectedData);
    }

    /**
     * Read SEIP packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        // A one-octet version number.
        // The only currently defined version is 1.
        $version = ord($bytes[0]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the SEIP packet is unsupported.",
          );
        }

        return new self(substr($bytes, 1));
    }

    /**
     * Encrypts packet list
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
        $toHash = implode([
            Helper::generatePrefix($symmetric),
            $packetList->encode(),
            "\xd3\x14",
        ]);
        $plainText = $toHash . hash('sha1', $toHash, true);

        $cipher = $symmetric->cipherEngine();
        $cipher->setKey($key);
        $cipher->setIV(str_repeat("\x00", $symmetric->blockSize()));

        return new self(
            $cipher->encrypt($plainText), $packetList
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
        return chr(self::VERSION) . $this->encrypted;
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
     * Gets decrypted packets contained within.
     *
     * @return PacketListInterface
     */
    public function getPacketList(): ?PacketListInterface
    {
        return $this->packetList;
    }

    /**
     * Encrypts the payload in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    public function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketList) {
            return self::encryptPackets($key, $this->packetList, $symmetric);
        }
        return $this;
    }

    /**
     * Encrypts the payload in the packet with session key.
     *
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function encryptWithSessionKey(
        SessionKeyInterface $sessionKey
    ): self
    {
        return $this->encrypt(
            $sessionKey->getEncryptionKey(),
            $sessionKey->getSymmetric()
        );
    }

    /**
     * Decrypts the encrypted data contained in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): self
    {
        if ($this->packetList instanceof PacketList) {
            return $this;
        }
        else {
            $this->getLogger()->debug(
                'Decrypt the encrypted data contained in the packet.'
            );
            $size = $symmetric->blockSize();
            $cipher = $symmetric->cipherEngine();
            $cipher->setKey($key);
            $cipher->setIV(str_repeat("\x00", $size));

            $decrypted = $cipher->decrypt($this->encrypted);
            $digestSize = strlen($decrypted) - HashAlgorithm::Sha1->digestSize();
            $realHash = substr($decrypted, $digestSize);
            $toHash = substr($decrypted, 0, $digestSize);
            if ($realHash !== hash('sha1', $toHash, true)) {
                throw new \UnexpectedValueException('Modification detected.');
            }

            return new self(
                $this->encrypted,
                PacketList::decode(
                    substr($toHash, $size + 2, strlen($toHash) - $size - 2)
                )
            );
        }
    }

    /**
     * Decrypts the encrypted data contained in the packet with session key.
     *
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    public function decryptWithSessionKey(
        SessionKeyInterface $sessionKey
    ): self
    {
        return $this->decrypt(
            $sessionKey->getEncryptionKey(),
            $sessionKey->getSymmetric()
        );
    }
}
