<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use OpenPGP\Enum\SymmetricAlgorithm;

/**
 * Literal message interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface LiteralMessageInterface extends MessageInterface
{
    /**
     * Gets literal data packet
     *
     * @return LiteralDataPacketInterface
     */
    function getLiteralDataPacket(): LiteralDataPacketInterface;

    /**
     * Encrypt the message either with public keys, passwords, or both at once.
     * Return new message with encrypted content.
     *
     * @param array $encryptionKeys
     * @param array $passwords
     * @param SymmetricAlgorithm $sessionKeySymmetric
     * @param SymmetricAlgorithm $encryptionKeySymmetric
     * @return EncryptedMessageInterface
     */
    function encrypt(
        array $encryptionKeys,
        array $passwords = [],
        SymmetricAlgorithm $sessionKeySymmetric = SymmetricAlgorithm::Aes128,
        SymmetricAlgorithm $encryptionKeySymmetric = SymmetricAlgorithm::Aes128
    ): EncryptedMessageInterface;
}
