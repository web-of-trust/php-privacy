<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * RSA key size enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum RSAKeySize: int
{
    case Normal = 2048;

    case Medium = 2560;

    case High = 3072;

    case VeryHigh = 3584;

    case UltraHigh = 4096;
}
