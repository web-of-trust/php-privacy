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
 * Signature interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SignatureInterface extends
    ArmorableInterface,
    PacketContainerInterface
{
    /**
     * Get signing key IDs
     *
     * @param bool $toHex
     * @return array
     */
    function getSigningKeyIDs(bool $toHex = false): array;

    /**
     * Get verification errors
     *
     * @return array
     */
    function getVerificationErrors(): array;

    /**
     * Verify signature with literal data
     * Return verification array
     *
     * @param array $verificationKeys
     * @param LiteralDataInterface $literalData
     * @param DateTimeInterface $time
     * @return array
     */
    function verify(
        array $verificationKeys,
        LiteralDataInterface $literalData,
        ?DateTimeInterface $time = null,
    ): array;

    /**
     * Verify signature with cleartext
     * Return verification array
     *
     * @param array $verificationKeys
     * @param CleartextMessageInterface $cleartext
     * @param DateTimeInterface $time
     * @return array
     */
    function verifyCleartext(
        array $verificationKeys,
        CleartextMessageInterface $cleartext,
        ?DateTimeInterface $time = null,
    ): array;
}
