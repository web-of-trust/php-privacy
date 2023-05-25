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

use OpenPGP\Enum\{
    CompressionAlgorithm,
    SymmetricAlgorithm,
};

/**
 * Literal message interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface LiteralMessageInterface extends ArmorableInterface, PacketContainerInterface, MessageInterface
{
    /**
     * Gets contained packets
     *
     * @return array
     */
    function getPackets(): array;

    /**
     * Gets literal data
     *
     * @return LiteralDataInterface
     */
    function getLiteralData(): LiteralDataInterface;

    /**
     * Encrypt the message either with public keys, passwords, or both at once.
     * Return new message with encrypted content.
     *
     * @param array $encryptionKeys
     * @param array $passwords
     * @param SymmetricAlgorithm $symmetric
     * @return EncryptedMessageInterface
     */
    function encrypt(
        array $encryptionKeys,
        array $passwords = [],
        ?SymmetricAlgorithm $symmetric = null
    ): EncryptedMessageInterface;

    /**
     * Compress the message (the literal and -if signed- signature data packets of the message)
     * Return new message with compressed content.
     *
     * @param CompressionAlgorithm $algorithm
     * @return self
     */
    function compress(
        CompressionAlgorithm $algorithm = CompressionAlgorithm::Uncompressed
    ): self
}
