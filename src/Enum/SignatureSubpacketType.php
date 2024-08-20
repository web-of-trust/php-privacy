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
enum SignatureSubpacketType: int
{
    /**
     * Signature Creation Time
     */
    case SignatureCreationTime = 2;

    /**
     * Signature Expiration Time
     */
    case SignatureExpirationTime = 3;

    /**
     * Exportable Certification
     */
    case ExportableCertification = 4;

    /**
     * Trust Signature
     */
    case TrustSignature = 5;

    /**
     * Regular Expression
     */
    case RegularExpression = 6;

    /**
     * Revocable
     */
    case Revocable = 7;

    /**
     * Key Expiration Time
     */
    case KeyExpirationTime = 9;

    /**
     * Placeholder for backward compatibility
     */
    case PlaceholderBackwardCompatibility = 10;

    /**
     * Preferred Symmetric Ciphers for v1 SEIPD
     */
    case PreferredSymmetricAlgorithms = 11;

    /**
     * Revocation Key (deprecated)
     */
    case RevocationKey = 12;

    /**
     * Issuer Key ID
     */
    case IssuerKeyID = 16;

    /**
     * Notation Data
     */
    case NotationData = 20;

    /**
     * Preferred Hash Algorithms
     */
    case PreferredHashAlgorithms = 21;

    /**
     * Preferred Compression Algorithms
     */
    case PreferredCompressionAlgorithms = 22;

    /**
     * Key Server Preferences
     */
    case KeyServerPreferences = 23;

    /**
     * Preferred Key Server
     */
    case PreferredKeyServer = 24;

    /**
     * Primary User ID
     */
    case PrimaryUserID = 25;

    /**
     * Policy URI
     */
    case PolicyURI = 26;

    /**
     * Key Flags
     */
    case KeyFlags = 27;

    /**
     * Signer's User ID
     */
    case SignerUserID = 28;

    /**
     * Reason for Revocation
     */
    case RevocationReason = 29;

    /**
     * Features
     */
    case Features = 30;

    /**
     * Signature Target
     */
    case SignatureTarget = 31;

    /**
     * Embedded Signature
     */
    case EmbeddedSignature = 32;

    /**
     * Issuer Fingerprint
     */
    case IssuerFingerprint = 33;

    /**
     * Preferred Aead Algorithms
     */
    case PreferredAeadAlgorithms = 34;

    /**
     * Intended Recipient Fingerprint
     */
    case IntendedRecipientFingerprint = 35;

    /**
     * Attested Certifications
     */
    case AttestedCertifications = 37;

    /**
     * Key Block
     */
    case KeyBlock = 38;

    /**
     * Preferred AEAD Ciphersuites
     */
    case PreferredAEADCiphersuites = 39;
}
