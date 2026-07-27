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
enum PacketTag: string
{
    /**
     * PKESK - Public Key Encrypted Session Key Packet
     */
    case PublicKeyEncryptedSessionKey = "\x01";

    /**
     * SIG - Signature Packet
     */
    case Signature = "\x02";

    /**
     * SKESK - Symmetric Key Encrypted Session Key Packet
     */
    case SymmetricKeyEncryptedSessionKey = "\x03";

    /**
     * OPS - One-Pass Signature Packet
     */
    case OnePassSignature = "\x04";

    /**
     * SECKEY - Secret Key Packet
     */
    case SecretKey = "\x05";

    /**
     * PUBKEY - Public Key Packet
     */
    case PublicKey = "\x06";

    /**
     * SECSUBKEY - Secret Subkey Packet
     */
    case SecretSubkey = "\x07";

    /**
     * COMP - Compressed Data Packet
     */
    case CompressedData = "\x08";

    /**
     * SED - Symmetrically Encrypted Data Packet
     */
    case SymEncryptedData = "\x09";

    /**
     * MARKER - Marker Packet
     */
    case Marker = "\x0A";

    /**
     * LIT - Literal Data Packet
     */
    case LiteralData = "\x0B";

    /**
     * TRUST - Trust Packet
     */
    case Trust = "\x0C";

    /**
     * UID - User ID Packet
     */
    case UserID = "\x0D";

    /**
     * PUBSUBKEY - Public Subkey Packet
     */
    case PublicSubkey = "\x0E";

    /**
     * UAT - User Attribute Packet
     */
    case UserAttribute = "\x11";

    /**
     * SEIPD - Symmetrically Encrypted and Integrity Protected Data Packet
     */
    case SymEncryptedIntegrityProtectedData = "\x12";

    /**
     * MDC - Modification Detection Code Packet
     */
    case ModificationDetectionCode = "\x13";

    /**
     * AEPD - Aead Encrypted Protected Data Packet
     */
    case AeadEncryptedData = "\x14";

    /**
     * PADDING - Padding Packet
     */
    case Padding = "\x15";
}
