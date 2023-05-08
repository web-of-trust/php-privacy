<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Packet\Key\KeyParametersInterface;

/**
 * Key packet interface
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface KeyPacketInterface
{
    /**
     * Gets key version
     * 
     * @return int
     */
    function getVersion(): int;

    /**
     * Gets creation time
     * 
     * @return int
     */
    function getCreationTime(): int;

    /**
     * Gets key algorithm
     * 
     * @return KeyAlgorithm
     */
    function getKeyAlgorithm(): KeyAlgorithm;

    /**
     * Gets key parameters
     * 
     * @return KeyParametersInterface
     */
    function getKeyParameters(): ?KeyParametersInterface;

    /**
     * Gets fingerprint
     * 
     * @return string
     */
    function getFingerprint(): string;

    /**
     * Gets key ID
     * 
     * @return string
     */
    function getKeyID(): string;

    /**
     * Gets bytes for sign
     *
     * @return string
     */
    function getSignBytes(): string;
}
