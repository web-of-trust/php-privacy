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
 * RSAKeySize enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum RSAKeySize: int
{
    case S2048 = 2048;

    case S2560 = 2560;

    case S3072 = 3072;

    case S3584 = 3584;

    case S4096 = 4096;
}
