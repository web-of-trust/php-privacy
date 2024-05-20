<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Enum;

/**
 * Armor type enum
 *
 * @package  OpenPGP
 * @category Enum
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
enum ArmorType {
    case MultipartSection;

    case MultipartLast;

    case SignedMessage;

    case Message;

    case PublicKey;

    case PrivateKey;

    case Signature;

    const BEGIN_PATTERN = '/^-----BEGIN PGP (MESSAGE, PART \d+\/\d+|MESSAGE, PART \d+|SIGNED MESSAGE|MESSAGE|PUBLIC KEY BLOCK|PRIVATE KEY BLOCK|SIGNATURE)-----$/';

    /**
     * Construct armor type from begin armored text.
     * 
     * @param string $text
     * @return self
     */
    public static function fromBegin(string $text): self
    {
        preg_match(self::BEGIN_PATTERN, $text, $matches);
        if (empty($matches)) {
            throw new \UnexpectedValueException('Unknown ASCII armor type');
        }
        return match (1) {
            preg_match('/MESSAGE, PART \d+\/\d+/', $matches[0]) => self::MultipartSection,
            preg_match('/MESSAGE, PART \d+/', $matches[0]) => self::MultipartLast,
            preg_match('/SIGNED MESSAGE/', $matches[0]) => self::SignedMessage,
            preg_match('/MESSAGE/', $matches[0]) => self::Message,
            preg_match('/PUBLIC KEY BLOCK/', $matches[0]) => self::PublicKey,
            preg_match('/PRIVATE KEY BLOCK/', $matches[0]) => self::PrivateKey,
            preg_match('/SIGNATURE/', $matches[0]) => self::Signature,
            default => self::MultipartSection,
        };
    }
}
