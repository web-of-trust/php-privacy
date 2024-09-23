<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;

/**
 * Cleartext message interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface CleartextMessageInterface
{
    /**
     * Get cleartext
     *
     * @return string
     */
    function getText(): string;

    /**
     * Get normalized cleartext
     *
     * @return string
     */
    function getNormalizeText(): string;

    /**
     * Sign the message
     *
     * @param array $signingKeys
     * @param array $recipients
     * @param NotationDataInterface $notationData
     * @param DateTimeInterface $time
     * @return SignedMessageInterface
     */
    function sign(
        array $signingKeys,
        array $recipients = [],
        ?NotationDataInterface $notationData = null,
        ?DateTimeInterface $time = null,
    ): SignedMessageInterface;

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
     * Verify detached signature & return verification array
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
}
