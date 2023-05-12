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
     * @param PacketTag $packetTag
     * @param string $data
     * @param int $offset
     * @return self
     */
    public function __construct(
        private readonly PacketTag $packetTag,
        private readonly string $data = '',
        private readonly int $offset = 0
    )
    {
    }

    /**
     * Gets packet tag
     * 
     * @return PacketTag
     */
    public function getPacketTag(): PacketTag
    {
        return $this->packetTag;
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

        $headerByte = ord($bytes[$offset++]);
        $oldFormat = (($headerByte & 0x40) != 0) ? false : true;
        $tagByte = $oldFormat ? ($headerByte & 0x3f) >> 2 : $headerByte & 0x3f;
        $tag = PacketTag::from($tagByte);

        $packetLength = strlen($bytes) - $offset - 1;
        if ($oldFormat) {
            $lengthType = $headerByte & 0x03;
            switch ($lengthType) {
                case 0:
                    $packetLength = ord($bytes[$offset++]);
                    break;
                case 1:
                    $packetLength = (ord($bytes[$offset++]) << 8) | ord($bytes[$offset++]);
                    break;
                case 2:
                    $unpacked = unpack('N', substr($bytes, $offset++, 4));
                    $packetLength = reset($unpacked);
                    $offset += 4;
                    break;
            }
        }
        else {
            if (ord($bytes[$offset]) < 192) {
                $packetLength = ord($bytes[$offset++]);
            }
            elseif (ord($bytes[$offset]) > 191 && ord($bytes[$offset]) < 224) {
                $packetLength = ((ord($bytes[$offset++]) - 192) << 8) + (ord($bytes[$offset++])) + 192;
            }
            elseif (ord($bytes[$offset]) > 223 && ord($bytes[$offset]) < 255) {
                $pos = $offset + 1 << (ord($bytes[$offset++]) & 0x1f);
                while (true) {
                  if (ord($bytes[$offset]) < 192) {
                    $partialLen = ord($bytes[$pos++]);
                    $pos += $partialLen;
                    break;
                  }
                  elseif (ord($bytes[$pos]) > 191 && ord($bytes[$pos]) < 224) {
                    $partialLen = ((ord($bytes[$pos++]) - 192) << 8) + (ord($bytes[$pos++])) + 192;
                    $pos += $partialLen;
                    break;
                  }
                  elseif (ord($bytes[$pos]) > 223 && ord($bytes[$pos]) < 255) {
                    $partialLen = 1 << (ord($bytes[$pos++]) & 0x1f);
                    $pos += $partialLen;
                    break;
                  }
                  else {
                    $unpacked = unpack('N', substr($bytes, $pos++, 4));
                    $partialLen = reset($unpacked);
                    $pos += $partialLen + 4;
                  }
                }
                $packetLength = $pos - $offset;
            }
            else {
                $unpacked = unpack('N', substr($bytes, $offset++, 4));
                $packetLength = reset($unpacked);
                $offset += 4;
            }
        }

        return new PacketReader(
            $tag,
            substr($bytes, $offset, $packetLength),
            $offset + $packetLength
        );
    }
}
