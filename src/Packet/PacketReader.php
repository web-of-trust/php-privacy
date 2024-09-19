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
     * @param int $packetLength
     * @return self
     */
    public function __construct(
        private readonly PacketTag $packetTag,
        private readonly string $data = '',
        private readonly int $packetLength = 0
    )
    {
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
     * Get packet length
     *
     * @return int
     */
    public function getPacketLength(): int
    {
        return $this->packetLength;
    }

    /**
     * Read packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function read(string $bytes): self
    {
        $offset = 0;
        if (strlen(substr($bytes, $offset)) < 2 || (ord($bytes[$offset]) & 0x80) === 0) {
            throw new \RuntimeException(
                'Error during parsing. This data probably does not conform to a valid OpenPGP format.',
            );
        }

        $headerByte = ord($bytes[$offset++]);
        $oldFormat = (($headerByte & 0x40) != 0) ? false : true;
        $tagByte = $oldFormat ? ($headerByte & 0x3f) >> 2 : $headerByte & 0x3f;
        $tag = PacketTag::from($tagByte);

        $packetData = '';
        if ($oldFormat) {
            $lengthType = $headerByte & 0x03;
            switch ($lengthType) {
                case 0:
                    $dataLength = ord($bytes[$offset++]);
                    break;
                case 1:
                    $dataLength = Helper::bytesToShort($bytes, $offset);
                    $offset += 2;
                    break;
                case 2:
                    $dataLength = Helper::bytesToLong($bytes, $offset);
                    $offset += 4;
                    break;
                default:
                    $dataLength = strlen($bytes) - $offset;
            }
            $packetData = substr($bytes, $offset, $dataLength);
        }
        else {
            $dataLength = ord($bytes[$offset++]);
            if ($dataLength < 192) {
                $packetData = substr($bytes, $offset, $dataLength);
            }
            elseif ($dataLength < 224) {
                $dataLength = (($dataLength - 192) << 8) + (ord($bytes[$offset++])) + 192;
                $packetData = substr($bytes, $offset, $dataLength);
            }
            elseif ($dataLength < 255) {
                $partialLen = 1 << ($dataLength & 0x1f);
                $partialData = [substr($bytes, $offset, $partialLen)];
                $partialPos = $offset + $partialLen;
                while (true) {
                    $partialLen = ord($bytes[$partialPos++]);
                    if ($partialLen < 192) {
                        $partialData[] = substr($bytes, $partialPos, $partialLen);
                        $partialPos += $partialLen;
                        break;
                    }
                    elseif ($partialLen < 224) {
                        $partialLen = (($partialLen - 192) << 8) + (ord($bytes[$partialPos++])) + 192;
                        $partialData[] = substr($bytes, $partialPos, $partialLen);
                        $partialPos += $partialLen;
                        break;
                    }
                    elseif ($partialLen < 255) {
                        $partialLen = 1 << ($partialLen & 0x1f);
                        $partialData[] = substr($bytes, $partialPos, $partialLen);
                        $partialPos += $partialLen;
                    }
                    else {
                        $partialLen = Helper::bytesToLong($bytes, $partialPos);
                        $partialPos += 4;
                        $partialData[] = substr($bytes, $partialPos, $partialLen);
                        $partialPos += $partialLen;
                        break;
                    }
                }
                $packetData = implode($partialData);
                $dataLength = $partialPos - $offset;
            }
            else {
                $dataLength = Helper::bytesToLong($bytes, $offset);
                $offset += 4;
                $packetData = substr($bytes, $offset, $dataLength);
            }
        }

        return new self(
            $tag,
            $packetData,
            $offset + $dataLength
        );
    }
}
