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
 * Reason for Revocation enum
 * See https://tools.ietf.org/html/rfc4880#section-5.2.3.23
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum RevocationReasonTag: int
{
    /**
     * No reason specified (key revocations or cert revocations)
     */
    case noReason = 0;

    /**
     * Key is superseded (key revocations)
     */
    case keySuperseded = 1;

    /**
     * Key material has been compromised (key revocations)
     */
    case keyCompromised = 2;

    /**
     * Key is retired and no longer used (key revocations)
     */
    case keyRetired = 3;

    /**
     * User ID information is no longer valid (cert revocations)
     */
    case userIDInvalid = 32;
}
