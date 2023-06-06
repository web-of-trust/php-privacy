<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * Notation data interface
 * 
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface NotationDataInterface
{
    /**
     * Get notation name
     *
     * @return string
     */
    function getNotationName(): string;

    /**
     * Get notation value
     *
     * @return string
     */
    function getNotationValue(): string;

    /**
     * Is human readable
     *
     * @return bool
     */
    function isHumanReadable(): bool;
}
