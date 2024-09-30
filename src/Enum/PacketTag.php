<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Packet tag enum
 * A list of packet types and numeric tags associated with them.
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum PacketTag: int
{
    /**
     * PKESK - Public Key Encrypted Session Key Packet
     */
    case PublicKeyEncryptedSessionKey = 1;

    /**
     * SIG - Signature Packet
     */
    case Signature = 2;

    /**
     * SKESK - Symmetric Key Encrypted Session Key Packet
     */
    case SymmetricallyEncryptedSessionKey = 3;

    /**
     * OPS - One-Pass Signature Packet
     */
    case OnePassSignature = 4;

    /**
     * SECKEY - Secret Key Packet
     */
    case SecretKey = 5;

    /**
     * PUBKEY - Public Key Packet
     */
    case PublicKey = 6;

    /**
     * SECSUBKEY - Secret Subkey Packet
     */
    case SecretSubkey = 7;

    /**
     * COMP - Compressed Data Packet
     */
    case CompressedData = 8;

    /**
     * SED - Symmetrically Encrypted Data Packet
     */
    case SymmetricallyEncryptedData = 9;

    /**
     * MARKER - Marker Packet
     */
    case Marker = 10;

    /**
     * LIT - Literal Data Packet
     */
    case LiteralData = 11;

    /**
     * TRUST - Trust Packet
     */
    case Trust = 12;

    /**
     * UID - User ID Packet
     */
    case UserID = 13;

    /**
     * PUBSUBKEY - Public Subkey Packet
     */
    case PublicSubkey = 14;

    /**
     * UAT - User Attribute Packet
     */
    case UserAttribute = 17;

    /**
     * SEIPD - Symmetrically Encrypted and Integrity Protected Data Packet
     */
    case SymmetricallyEncryptedIntegrityProtectedData = 18;

    /**
     * MDC - Modification Detection Code Packet
     */
    case ModificationDetectionCode = 19;

    /**
     * AEPD - Aead Encrypted Protected Data Packet
     */
    case AeadEncryptedData = 20;

    /**
     * PADDING - Padding Packet
     */
    case Padding = 21;
}
