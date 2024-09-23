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
enum SupportFeature: int
{
    /**
     * Version 1 Symmetrically Encrypted and Integrity Protected Data packet
     */
    case Version1SEIPD = 1;

    /**
     * AEAD Encrypted Data packet (packet 20). 
     * Version 5 Symmetric Encrypted Session Key packet.
     */
    case AeadEncrypted = 2;

    /**
     * Version 5 PublicKey packet.
     */
    case Version5PublicKey = 4;

    /**
     * Version 2 Symmetrically Encrypted and Integrity Protected Data packet
     */
    case Version2SEIPD = 8;
}
