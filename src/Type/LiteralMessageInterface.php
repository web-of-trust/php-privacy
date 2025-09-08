<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\{CompressionAlgorithm, SymmetricAlgorithm};

/**
 * Literal message interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface LiteralMessageInterface extends
    ArmorableInterface,
    PacketContainerInterface
{
    /**
     * Get literal data
     *
     * @return LiteralDataInterface
     */
    function getLiteralData(): LiteralDataInterface;

    /**
     * Sign the message
     *
     * @param array $signingKeys
     * @param array $recipients
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return self
     */
    function sign(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): self;

    /**
     * Create a detached signature for the message
     *
     * @param array $signingKeys
     * @param array $recipients
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignatureInterface
     */
    function signDetached(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignatureInterface;

    /**
     * Verify signature
     * Return verification array
     *
     * @param array $verificationKeys
     * @param DateTimeInterface $time
     * @return array
     */
    function verify(
        array $verificationKeys,
        ?DateTimeInterface $time = null,
    ): array;

    /**
     * Verify detached signature
     * Return verification array
     *
     * @param array $verificationKeys
     * @param SignatureInterface $signature
     * @param DateTimeInterface $time
     * @return array
     */
    function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTimeInterface $time = null,
    ): array;

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
        array $encryptionKeys = [],
        array $passwords = [],
        SymmetricAlgorithm $symmetric = SymmetricAlgorithm::Aes256,
    ): EncryptedMessageInterface;

    /**
     * Compress the message (the literal and signature packets of the message)
     * Return new message with compressed content.
     *
     * @param CompressionAlgorithm $algorithm
     * @return self
     */
    function compress(
        CompressionAlgorithm $algorithm = CompressionAlgorithm::Uncompressed,
    ): self;
}
