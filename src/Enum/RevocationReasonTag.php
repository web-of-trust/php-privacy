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
enum RevocationReasonTag: int
{
    /**
     * No reason specified (key revocations or cert revocations)
     */
    case NoReason = 0;

    /**
     * Key is superseded (key revocations)
     */
    case KeySuperseded = 1;

    /**
     * Key material has been compromised (key revocations)
     */
    case KeyCompromised = 2;

    /**
     * Key is retired and no longer used (key revocations)
     */
    case KeyRetired = 3;

    /**
     * User ID information is no longer valid (cert revocations)
     */
    case UserIDInvalid = 32;
}
