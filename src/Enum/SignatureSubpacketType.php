<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Signature subpacket type enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum SignatureSubpacketType: string
{
    /**
     * Signature Creation Time
     */
    case SignatureCreationTime = "\x02";

    /**
     * Signature Expiration Time
     */
    case SignatureExpirationTime = "\x03";

    /**
     * Exportable Certification
     */
    case ExportableCertification = "\x04";

    /**
     * Trust Signature
     */
    case TrustSignature = "\x05";

    /**
     * Regular Expression
     */
    case RegularExpression = "\x06";

    /**
     * Revocable
     */
    case Revocable = "\x07";

    /**
     * Key Expiration Time
     */
    case KeyExpirationTime = "\x09";

    /**
     * Placeholder for backward compatibility
     */
    case PlaceholderBackwardCompatibility = "\x0A";

    /**
     * Preferred Symmetric Ciphers for v1 SEIPD
     */
    case PreferredSymmetricAlgorithms = "\x0B";

    /**
     * Revocation Key (deprecated)
     */
    case RevocationKey = "\x0C";

    /**
     * Issuer Key ID
     */
    case IssuerKeyID = "\x10";

    /**
     * Notation Data
     */
    case NotationData = "\x14";

    /**
     * Preferred Hash Algorithms
     */
    case PreferredHashAlgorithms = "\x15";

    /**
     * Preferred Compression Algorithms
     */
    case PreferredCompressionAlgorithms = "\x16";

    /**
     * Key Server Preferences
     */
    case KeyServerPreferences = "\x17";

    /**
     * Preferred Key Server
     */
    case PreferredKeyServer = "\x18";

    /**
     * Primary User ID
     */
    case PrimaryUserID = "\x19";

    /**
     * Policy URI
     */
    case PolicyURI = "\x1A";

    /**
     * Key Flags
     */
    case KeyFlags = "\x1B";

    /**
     * Signer's User ID
     */
    case SignerUserID = "\x1C";

    /**
     * Reason for Revocation
     */
    case RevocationReason = "\x1D";

    /**
     * Features
     */
    case Features = "\x1E";

    /**
     * Signature Target
     */
    case SignatureTarget = "\x1F";

    /**
     * Embedded Signature
     */
    case EmbeddedSignature = "\x20";

    /**
     * Issuer Fingerprint
     */
    case IssuerFingerprint = "\x21";

    /**
     * Preferred Aead Algorithms
     */
    case PreferredAeadAlgorithms = "\x22";

    /**
     * Intended Recipient Fingerprint
     */
    case IntendedRecipientFingerprint = "\x23";

    /**
     * Attested Certifications
     */
    case AttestedCertifications = "\x25";

    /**
     * Key Block
     */
    case KeyBlock = "\x26";

    /**
     * Preferred AEAD Ciphers
     */
    case PreferredAeadCiphers = "\27";
}
