<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;

/**
 * Packet reader class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PacketReader
{
    /**
     * Constructor
     *
     * @param PacketTag $tag
     * @param string $data
     * @param int $offset
     * @return self
     */
    public function __construct(
        private PacketTag $tag,
        private string $data = '',
        private int $offset = 0
    )
    {
    }

    /**
     * Gets packet tag
     * 
     * @return PacketTag
     */
    public function getTag(): PacketTag
    {
        return $this->tag;
    }

    /**
     * Gets packet data
     * 
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Gets offset
     * 
     * @return int
     */
    public function getOffset(): int
    {
        return $this->offset;
    }

    /**
     * Read packet from byte string
     *
     * @param string $bytes
     * @param int $offset
     * @return PacketReader
     */
    public static function read(string $bytes, int $offset = 0): PacketReader
    {
        if (strlen($bytes) <= $offset || strlen(substr($bytes, $offset)) < 2 || (ord($bytes[$offset]) & 0x80) == 0) {
          throw new StateError(
            'Error during parsing. This data probably does not conform to a valid OpenPGP format.',
          );
        }

        $pos = $offset;
        $headerByte = ord($bytes[$pos++]);
        $oldFormat = (($headerByte & 0x40) != 0) ? false : true;
        $tagByte = $oldFormat ? ($headerByte & 0x3f) >> 2 : $headerByte & 0x3f;
        $tag = PacketTag::from($tagByte);

        $packetLength = strlen($bytes) - $offset;
        if ($oldFormat) {
            $lengthType = $headerByte & 0x03;
            switch ($lengthType) {
                case 0:
                    $packetLength = ord($bytes[$pos++]);
                    break;
                case 1:
                    $packetLength = (ord($bytes[$pos++]) << 8) | ord($bytes[$pos++]);
                    break;
                case 2:
                    $packetLength = unpack('N', substr($bytes, $pos++, 4));
                    $pos += 4;
                    break;
            }
        }
        else {
            if (ord($bytes[$pos]) < 192) {
                $packetLength = ord($bytes[$pos++]);
            }
            elseif (ord($bytes[$pos]) > 191 && ord($bytes[$pos]) < 224) {
                $packetLength = ((ord($bytes[$pos++]) - 192) << 8) + (ord($bytes[$pos++])) + 192;
            }
            elseif (ord($bytes[$pos]) > 223 && ord($bytes[$pos]) < 255) {
                $partialPos = $pos + 1 << (ord($bytes[$pos++]) & 0x1f);
                while (true) {
                  if (ord($bytes[$pos]) < 192) {
                    $partialLen = ord($bytes[$partialPos++]);
                    $partialPos += $partialLen;
                    break;
                  }
                  elseif (ord($bytes[$partialPos]) > 191 && ord($bytes[$partialPos]) < 224) {
                    $partialLen = ((ord($bytes[$partialPos++]) - 192) << 8) + (ord($bytes[$partialPos++])) + 192;
                    $partialPos += $partialLen;
                    break;
                  }
                  elseif (ord($bytes[$partialPos]) > 223 && ord($bytes[$partialPos]) < 255) {
                    $partialLen = 1 << (ord($bytes[$partialPos++]) & 0x1f);
                    $partialPos += $partialLen;
                    break;
                  }
                  else {
                    $partialLen = unpack('N', substr($bytes, $partialPos++, 4));
                    $partialPos += $partialLen + 4;
                  }
                }
                $packetLength = $partialPos - $pos;
            }
            else {
                $packetLength = unpack('N', substr($bytes, $pos++, 4));
                $pos += 4;
            }
        }

        return PacketReader(
            $tag,
            substr($bytes, $pos, $packetLength),
            $pos + $packetLength
        );
    }
}
