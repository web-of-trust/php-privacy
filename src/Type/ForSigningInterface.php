<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

/**
 * For signing interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface ForSigningInterface
{
    /**
     * Get bytes for sign
     *
     * @return string
     */
    function getSignBytes(): string;
}
