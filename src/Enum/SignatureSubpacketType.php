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
    case SignatureCreationTime = 0x02;

    /**
     * Signature Expiration Time
     */
    case SignatureExpirationTime = 0x03;

    /**
     * Exportable Certification
     */
    case ExportableCertification = 0x04;

    /**
     * Trust Signature
     */
    case TrustSignature = 0x05;

    /**
     * Regular Expression
     */
    case RegularExpression = 0x06;

    /**
     * Revocable
     */
    case Revocable = 0x07;

    /**
     * Key Expiration Time
     */
    case KeyExpirationTime = 0x09;

    /**
     * Placeholder for backward compatibility
     */
    case PlaceholderBackwardCompatibility = 0x0A;

    /**
     * Preferred Symmetric Ciphers for v1 SEIPD
     */
    case PreferredSymmetricAlgorithms = 0x0B;

    /**
     * Revocation Key (deprecated)
     */
    case RevocationKey = 0x0C;

    /**
     * Issuer Key ID
     */
    case IssuerKeyID = 0x10;

    /**
     * Notation Data
     */
    case NotationData = 0x14;

    /**
     * Preferred Hash Algorithms
     */
    case PreferredHashAlgorithms = 0x15;

    /**
     * Preferred Compression Algorithms
     */
    case PreferredCompressionAlgorithms = 0x16;

    /**
     * Key Server Preferences
     */
    case KeyServerPreferences = 0x17;

    /**
     * Preferred Key Server
     */
    case PreferredKeyServer = 0x18;

    /**
     * Primary User ID
     */
    case PrimaryUserID = 0x19;

    /**
     * Policy URI
     */
    case PolicyURI = 0x1A;

    /**
     * Key Flags
     */
    case KeyFlags = 0x1B;

    /**
     * Signer's User ID
     */
    case SignerUserID = 0x1C;

    /**
     * Reason for Revocation
     */
    case RevocationReason = 0x1D;

    /**
     * Features
     */
    case Features = 0x1E;

    /**
     * Signature Target
     */
    case SignatureTarget = 0x1F;

    /**
     * Embedded Signature
     */
    case EmbeddedSignature = 0x20;

    /**
     * Issuer Fingerprint
     */
    case IssuerFingerprint = 0x21;

    /**
     * Preferred Aead Algorithms
     */
    case PreferredAeadAlgorithms = 0x22;

    /**
     * Intended Recipient Fingerprint
     */
    case IntendedRecipientFingerprint = 0x23;

    /**
     * Attested Certifications
     */
    case AttestedCertifications = 0x25;

    /**
     * Key Block
     */
    case KeyBlock = 0x26;

    /**
     * Preferred AEAD Ciphers
     */
    case PreferredAeadCiphers = 0x27;
}
