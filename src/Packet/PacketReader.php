<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Helper;
use OpenPGP\Enum\PacketTag;

/**
 * Packet reader class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
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
        private readonly string $data = "",
        private readonly int $offset = 0
    ) {
    }

    /**
     * Get packet tag
     *
     * @return PacketTag
     */
    public function getPacketTag(): PacketTag
    {
        return $this->packetTag;
    }

    /**
     * Get packet data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Get offset
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
     * @return self
     */
    public static function read(string $bytes, int $offset = 0): self
    {
        if (
            strlen($bytes) <= $offset ||
            strlen(substr($bytes, $offset)) < 2 ||
            (ord($bytes[$offset]) & 0x80) === 0
        ) {
            throw new \UnexpectedValueException(
                "Error during parsing. This data probably does not conform to a valid OpenPGP format."
            );
        }

        $headerByte = ord($bytes[$offset++]);
        $oldFormat = ($headerByte & 0x40) != 0 ? false : true;
        $tagByte = $oldFormat ? ($headerByte & 0x3f) >> 2 : $headerByte & 0x3f;
        $tag = PacketTag::from($tagByte);

        $packetData = "";
        if ($oldFormat) {
            $lengthType = $headerByte & 0x03;
            switch ($lengthType) {
                case 0:
                    $packetLength = ord($bytes[$offset++]);
                    break;
                case 1:
                    $packetLength = Helper::bytesToShort($bytes, $offset);
                    $offset += 2;
                    break;
                case 2:
                    $packetLength = Helper::bytesToLong($bytes, $offset);
                    $offset += 4;
                    break;
                default:
                    $packetLength = strlen($bytes) - $offset;
            }
            $packetData = substr($bytes, $offset, $packetLength);
        } else {
            $length = ord($bytes[$offset++]);
            if ($length < 192) {
                $packetLength = $length;
                $packetData = substr($bytes, $offset, $packetLength);
            } elseif ($length < 224) {
                $packetLength =
                    ($length - 192 << 8) + ord($bytes[$offset++]) + 192;
                $packetData = substr($bytes, $offset, $packetLength);
            } elseif ($length < 255) {
                $partialLength = 1 << ($length & 0x1f);
                $partialData = [substr($bytes, $offset, $partialLength)];
                $pos = $offset + $partialLength;
                while (true) {
                    $length = ord($bytes[$pos++]);
                    if ($length < 192) {
                        $partialLength = $length;
                        $partialData[] = substr($bytes, $pos, $partialLength);
                        $pos += $partialLength;
                        break;
                    } elseif ($length < 224) {
                        $partialLength =
                            ($length - 192 << 8) + ord($bytes[$pos++]) + 192;
                        $partialData[] = substr($bytes, $pos, $partialLength);
                        $pos += $partialLength;
                        break;
                    } elseif ($length < 255) {
                        $partialLength = 1 << ($length & 0x1f);
                        $partialData[] = substr($bytes, $pos, $partialLength);
                        $pos += $partialLength;
                    } else {
                        $partialLength = Helper::bytesToLong($bytes, $pos);
                        $pos += 4;
                        $partialData[] = substr($bytes, $pos, $partialLength);
                        $pos += $partialLength;
                        break;
                    }
                }
                $packetData = implode($partialData);
                $packetLength = $pos - $offset;
            } else {
                $packetLength = Helper::bytesToLong($bytes, $offset);
                $offset += 4;
                $packetData = substr($bytes, $offset, $packetLength);
            }
        }

        return new self($tag, $packetData, $offset + $packetLength);
    }
}
