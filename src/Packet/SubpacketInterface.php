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

/**
 * Subpacket interface
 *
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface SubpacketInterface
{
    /**
     * Gets type
     * 
     * @return int
     */
	function getType(): int;

    /**
     * Gets data
     * 
     * @return string
     */
	function getData(): string;

    /**
     * Gets is long
     * 
     * @return bool
     */
	function isLong(): bool;

    /**
     * Serializes subpacket to bytes
     * 
     * @return string
     */
    function toBytes(): string;
}
