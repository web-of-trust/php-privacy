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

use DateTime;

/**
 * Cleartext message interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
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
     * @param NotationDataInterface $notationData
     * @param DateTime $time
     * @return SignedMessageInterface
     */
    function sign(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTime $time = null
    ): SignedMessageInterface;

    /**
     * Create a detached signature for the message
     *
     * @param array $signingKeys
     * @param NotationDataInterface $notationData
     * @param DateTime $time
     * @return SignatureInterface
     */
    function signDetached(
        array $signingKeys,
        ?NotationDataInterface $notationData = null,
        ?DateTime $time = null
    ): SignatureInterface;

    /**
     * Verify detached signature & return verification array
     *
     * @param array $verificationKeys
     * @param SignatureInterface $signature
     * @param DateTime $time
     * @return array
     */
    function verifyDetached(
        array $verificationKeys,
        SignatureInterface $signature,
        ?DateTime $time = null
    ): array;
}
