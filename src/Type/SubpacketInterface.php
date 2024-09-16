<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * Subpacket interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface SubpacketInterface
{
    /**
     * Get type
     *
     * @return int
     */
    function getType(): int;

    /**
     * Get data
     *
     * @return string
     */
    function getData(): string;

    /**
     * Get is long
     *
     * @return bool
     */
    function isLong(): bool;

    /**
     * Serialize subpacket to bytes
     *
     * @return string
     */
    function toBytes(): string;
}
