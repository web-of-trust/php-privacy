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
use OpenPGP\Enum\LiteralFormat;

/**
 * Literal data interface
 * 
 * @package   OpenPGP
 * @category  Type
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
interface LiteralDataInterface
{
    /**
     * Gets literal format
     *
     * @return LiteralFormat
     */
    function getFormat(): LiteralFormat;

    /**
     * Gets filename
     *
     * @return string
     */
    function getFilename(): string;

    /**
     * Gets time
     *
     * @return DateTime
     */
    function getTime(): DateTime;

    /**
     * Gets data
     *
     * @return string
     */
    function getData(): string;
}
