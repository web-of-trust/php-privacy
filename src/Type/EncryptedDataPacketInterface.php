<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * Encrypted data packet packet interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface EncryptedDataPacketInterface extends PacketInterface
{
    /**
     * Get encrypted data
     *
     * @return string
     */
    function getEncrypted(): string;

    /**
     * Get decrypted packets contained within.
     *
     * @return PacketListInterface
     */
    function getPacketList(): ?PacketListInterface;

    /**
     * Encrypt the payload in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    function encrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): self;

    /**
     * Encrypt the payload in the packet with session key.
     *
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    function encryptWithSessionKey(SessionKeyInterface $sessionKey): self;

    /**
     * Decrypt the encrypted data contained in the packet.
     *
     * @param string $key
     * @param SymmetricAlgorithm $symmetric
     * @return self
     */
    function decrypt(
        string $key,
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256
    ): self;

    /**
     * Decrypt the encrypted data contained in the packet with session key.
     *
     * @param SessionKeyInterface $sessionKey
     * @return self
     */
    function decryptWithSessionKey(SessionKeyInterface $sessionKey): self;
}
