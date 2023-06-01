<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Literal format enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum LiteralFormat: int
{
    /**
     * Binary data 'b'
     */
	case Binary = 98;

    /**
     * Text data 't'
     */
	case Text = 116;

    /**
     * Utf8 data 'u'
     */
	case Utf8 = 117;

    /**
     * MIME message body part 'm'
     */
	case Mime = 109;
}
