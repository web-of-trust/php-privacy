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
    case signatureCreationTime = 2;

    case signatureExpirationTime = 3;

    case exportableCertification = 4;

    case trustSignature = 5;

    case regularExpression = 6;

    case revocable = 7;

    case keyExpirationTime = 9;

    case placeholderBackwardCompatibility = 10;

    case preferredSymmetricAlgorithms = 11;

    case revocationKey = 12;

    case issuerKeyID = 13;

    case notationData = 20;

    case preferredHashAlgorithms = 21;

    case preferredCompressionAlgorithms = 22;

    case keyServerPreferences = 23;

    case preferredKeyServer = 24;

    case primaryUserID = 25;

    case policyURI = 26;

    case keyFlags = 27;

    case signerUserID = 28;

    case revocationReason = 29;

    case features = 30;

    case signatureTarget = 31;

    case embeddedSignature = 32;

    case issuerFingerprint = 33;

    case preferredAEADAlgorithms = 34;

    case intendedRecipientFingerprint = 35;

    case attestedCertifications = 37;
}
