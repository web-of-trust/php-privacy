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

/**
 * Verification interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface VerificationInterface
{
    /**
     * Get verification key ID
     *
     * @param bool $toHex
     * @return string
     */
	function getKeyID(bool $toHex = false): string;

    /**
     * Get signature packet
     *
     * @return SignaturePacketInterface
     */
	function getSignaturePacket(): SignaturePacketInterface;

    /**
     * Is verified
     *
     * @return bool
     */
	function isVerified(): bool;
}
