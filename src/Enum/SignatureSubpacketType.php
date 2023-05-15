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
 * SignatureSubpacketType enum
 *
 * @package    OpenPGP
 * @category   Enum
 * @author     Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright  Copyright © 2023-present by Nguyen Van Nguyen.
 */
enum SignatureSubpacketType: int
{
    case SignatureCreationTime = 2;

    case SignatureExpirationTime = 3;

    case ExportableCertification = 4;

    case TrustSignature = 5;

    case RegularExpression = 6;

    case Revocable = 7;

    case KeyExpirationTime = 9;

    case PlaceholderBackwardCompatibility = 10;

    case PreferredSymmetricAlgorithms = 11;

    case RevocationKey = 12;

    case IssuerKeyID = 16;

    case NotationData = 20;

    case PreferredHashAlgorithms = 21;

    case PreferredCompressionAlgorithms = 22;

    case KeyServerPreferences = 23;

    case PreferredKeyServer = 24;

    case PrimaryUserID = 25;

    case PolicyURI = 26;

    case KeyFlags = 27;

    case SignerUserID = 28;

    case RevocationReason = 29;

    case Features = 30;

    case SignatureTarget = 31;

    case EmbeddedSignature = 32;

    case IssuerFingerprint = 33;

    case PreferredAEADAlgorithms = 34;

    case IntendedRecipientFingerprint = 35;

    case AttestedCertifications = 37;
}
