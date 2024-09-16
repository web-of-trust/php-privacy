<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Type;

use DateTimeInterface;
use OpenPGP\Enum\LiteralFormat;

/**
 * Literal data interface
 *
 * @package  OpenPGP
 * @category Type
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
interface LiteralDataInterface extends ForSigningInterface
{
    /**
     * Get literal format
     *
     * @return LiteralFormat
     */
    function getFormat(): LiteralFormat;

    /**
     * Get filename
     *
     * @return string
     */
    function getFilename(): string;

    /**
     * Get time
     *
     * @return DateTimeInterface
     */
    function getTime(): DateTimeInterface;

    /**
     * Get data
     *
     * @return string
     */
    function getData(): string;

    /**
     * Get header
     *
     * @return string
     */
    function getHeader(): string;
}
