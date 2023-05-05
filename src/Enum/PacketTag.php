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
 * PacketTag enum
 * A list of packet types and numeric tags associated with them.
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum PacketTag: int
{
    case PublicKeyEncryptedSessionKey = 1;

    case Signature = 2;

    case SymEncryptedSessionKey = 3;

    case OnePassSignature = 4;

    case SecretKey = 5;

    case PublicKey = 6;

    case SecretSubkey = 7;

    case CompressedData = 8;

    case SymEncryptedData = 9;

    case Marker = 10;

    case LiteralData = 11;

    case Trust = 12;

    case UserID = 13;

    case PublicSubkey = 14;

    case UserAttribute = 17;

    case SymEncryptedIntegrityProtectedData = 18;

    case ModificationDetectionCode = 19;

    case AeadEncryptedData = 20;
}
