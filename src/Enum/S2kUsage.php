<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * S2k usage enum
 *
 * S2k usage indicating whether and how the secret key material is protected by a passphrase
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum S2kUsage: int
{
    /// Indicates that the secret key data is not encrypted
    case None = 0;

    /// AEAD protect
    case AeadProtect = 253;

    /// CFB
    case Cfb = 254;

    /// Malleable CFB
    case MalleableCfb = 255;
}
