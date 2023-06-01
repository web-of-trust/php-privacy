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
 * Support feature enum
 * See https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.2.3.25
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum SupportFeature: int
{
    case ModificationDetection = 1;

    case AeadEncryptedData = 2;

    case Version5PublicKey = 3;
}
