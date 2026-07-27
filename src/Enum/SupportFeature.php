<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Support feature enum
 *
 * See https://www.rfc-editor.org/rfc/rfc9580#name-features
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum SupportFeature: string
{
    /**
     * Version 1 Symmetrically Encrypted and Integrity Protected Data packet
     */
    case Version1SEIPD = "\x01";

    /**
     * AEAD Encrypted Data packet (packet 20).
     * Version 5 Symmetric Encrypted Session Key packet.
     */
    case AeadEncrypted = "\x02";

    /**
     * Version 5 PublicKey packet.
     */
    case Version5PublicKey = "\x04";

    /**
     * Version 2 Symmetrically Encrypted and Integrity Protected Data packet
     */
    case Version2SEIPD = "\x08";
}
