<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Reason for revocation enum
 * See https://tools.ietf.org/html/rfc4880#section-5.2.3.23
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum RevocationReasonTag: string
{
    /**
     * No reason specified (key revocations or cert revocations)
     */
    case NoReason = "\x00";

    /**
     * Key is superseded (key revocations)
     */
    case KeySuperseded = "\x01";

    /**
     * Key material has been compromised (key revocations)
     */
    case KeyCompromised = "\x02";

    /**
     * Key is retired and no longer used (key revocations)
     */
    case KeyRetired = "\x03";

    /**
     * User ID information is no longer valid (cert revocations)
     */
    case UserIDInvalid = "\x20";
}
