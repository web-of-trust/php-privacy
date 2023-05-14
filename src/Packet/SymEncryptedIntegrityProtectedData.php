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
use OpenPGP\Enum\{HashAlgorithm, PacketTag, SymmetricAlgorithm};

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
     * @param PacketList $packets
     * @return self
     */
    public function __construct(
        private readonly string $encrypted,
        private readonly ?PacketList $packets = null
    )
    {
        parent::__construct(PacketTag::SymEncryptedIntegrityProtectedData);
    }

    /**
     * Read SEIP packet from byte string
     *
     * @param string $bytes
     * @return SymEncryptedIntegrityProtectedData
     */
    public static function fromBytes(string $bytes): SymEncryptedIntegrityProtectedData
    {
        // A one-octet version number. The only currently defined version is 1.
        $version = ord($bytes[0]);
        if ($version !== self::VERSION) {
            throw new \UnexpectedValueException(
                "Version $version of the SEIP packet is unsupported.",
          );
        }

        return new SymEncryptedIntegrityProtectedData(substr($bytes, 1));
    }

    /**
     * Encrypts packet list
     *
     * @param string $key
     * @param PacketList $packets
     * @param SymmetricAlgorithm $symmetric
     * @return SymEncryptedIntegrityProtectedData
     */
    public static function encryptPackets(
        string $key,
        PacketList $packets,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): SymEncryptedIntegrityProtectedData
    {
        $toHash = implode([
            Helper::generatePrefix($symmetric),
            $packets->encode(),
            "\xd3\x14",
        ]);
        $plainText = $toHash . sha1($toHash, true);

        $cipher = $symmetric->cipherEngine();
        $cipher->setKey($key);
        $cipher->setIV(str_repeat("\0", $symmetric->blockSize()));

        return new SymEncryptedIntegrityProtectedData(
            $cipher->encrypt($plainText), $packets
        );
    }

    /**
     * Encrypts packet list with session key
     *
     * @param Key\SessionKey $sessionKey
     * @param PacketList $packets
     * @return SymEncryptedIntegrityProtectedData
     */
    public static function encryptPacketsWithSessionKey(
        Key\SessionKey $sessionKey, PacketList $packets
    ): SymEncryptedIntegrityProtectedData
    {
        return self::encryptPackets(
            $sessionKey->getEncryptionKey(),
            $packets,
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
     * @return SymEncryptedIntegrityProtectedData
     */
    public function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): SymEncryptedIntegrityProtectedData
    {
        if ($this->packets instanceof PacketList) {
            return self::encryptPackets($key, $this->packets, $symmetric);
        }
        return $this;
    }

    /**
     * Encrypts the payload in the packet with session key.
     *
     * @param Key\SessionKey $sessionKey
     * @return SymEncryptedIntegrityProtectedData
     */
    public function encryptWithSessionKey(
        Key\SessionKey $sessionKey
    ): SymEncryptedIntegrityProtectedData
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
     * @return SymEncryptedIntegrityProtectedData
     */
    public function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes128
    ): SymEncryptedIntegrityProtectedData
    {
        $blockSize = $symmetric->blockSize();
        $cipher = $symmetric->cipherEngine();
        $cipher->setKey($key);
        $cipher->setIV(str_repeat("\x0", $blockSize));

        $decrypted = $cipher->decrypt($this->encrypted);
        $digestSize = strlen($decrypted) - HashAlgorithm::Sha1->digestSize();
        $realHash = substr($decrypted, $digestSize);
        $toHash = substr($decrypted, 0, $digestSize);
        if ($realHash !== sha1($toHash, true)) {
            throw new \UnexpectedValueException('Modification detected.');
        }

        return new SymEncryptedIntegrityProtectedData(
            $this->encrypted,
            PacketList::decode(
                substr($toHash, $blockSize + 2, strlen($toHash) - $blockSize - 2)
            )
        );
    }

    /**
     * Decrypts the encrypted data contained in the packet with session key.
     *
     * @param Key\SessionKey $sessionKey
     * @return SymEncryptedIntegrityProtectedData
     */
    public function decryptWithSessionKey(
        Key\SessionKey $sessionKey
    ): SymEncryptedIntegrityProtectedData
    {
        return $this->decrypt(
            $sessionKey->getEncryptionKey(),
            $sessionKey->getSymmetric()
        );
    }
}
