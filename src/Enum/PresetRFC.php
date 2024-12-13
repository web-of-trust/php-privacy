<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * OpenPGP preset RFC enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum PresetRFC
{
    /**
     * RFC 4880 & 5581 & 6637
     * https://www.rfc-editor.org/rfc/rfc4880
     * https://www.rfc-editor.org/rfc/rfc5581
     * https://www.rfc-editor.org/rfc/rfc6637
     */
    case RFC4880;

    /**
     * RFC 9580
     * https://www.rfc-editor.org/rfc/rfc9580
     */
    case RFC9580;
}
