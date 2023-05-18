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

use OpenPGP\Enum\{HashAlgorithm, KeyAlgorithm, SignatureType};

/**
 * Signature packet interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SignaturePacketInterface
{
    /**
     * Gets version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Gets signature type
     * 
     * @return SignatureType
     */
    function getSignatureType(): SignatureType;

    /**
     * Gets key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Gets hash algorithm
     * 
     * @return HashAlgorithm
     */
    function getHashAlgorithm(): HashAlgorithm;

    /**
     * Gets hashed subpackets
     *
     * @return array
     */
    function getHashedSubpackets(): array;

    /**
     * Gets unhashed subpackets
     *
     * @return array
     */
    function getUnhashedSubpackets(): array;

    /**
     * Gets signed hash value
     *
     * @return string
     */
    function getSignedHashValue(): string;

    /**
     * Gets signature data
     *
     * @return string
     */
    function getSignature(): string;

    /**
     * Verifies the signature packet.
     *
     * @param KeyPacketInterface $verifyKey
     * @param string $dataToVerify
     * @param int $time
     * @return bool
     */
    function verify(
        KeyPacketInterface $verifyKey,
        string $dataToVerify,
        int $time = 0
    ): bool;
}
