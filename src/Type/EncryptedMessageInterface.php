<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * Encrypted message interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface EncryptedMessageInterface
{
    /**
     * Return encrypted packet.
     *
     * @return EncryptedDataPacketInterface
     */
    function getEncryptedPacket(): EncryptedDataPacketInterface;

    /**
     * Return session key.
     *
     * @return SessionKeyInterface
     */
    function getSessionKey(): ?SessionKeyInterface;

    /**
     * Decrypt the message. One of `decryptionKeys` or `passwords` must be specified.
     * Return new message with decrypted content.
     *
     * @param array $decryptionKeys
     * @param array $passwords
     * @return LiteralMessageInterface
     */
    function decrypt(
        array $decryptionKeys = [],
        array $passwords = []
    ): LiteralMessageInterface;
}
