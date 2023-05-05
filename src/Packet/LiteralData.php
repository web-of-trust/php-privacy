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

use OpenPGP\Enum\LiteralFormat;
use OpenPGP\Enum\PacketTag;

/**
 * Implementation of the Literal Data Packet (Tag 11)
 * See RFC 4880, section 5.9.
 * 
 * A Literal Data packet contains the body of a message; data that is not to be further interpreted.
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class LiteralData extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $data
     * @param LiteralFormat $format
     * @param string $text
     * @return self
     */
    public function __construct(
        private string $data,
        private LiteralFormat $format = LiteralFormat::Utf8,
        private int $time = 0,
        private string $text = '',
        private string $filename = ''
    )
    {
        parent::__construct(PacketTag::LiteralData);
    }

    /**
     * Reads literal data packet from byte string
     *
     * @param string $bytes
     * @return LiteralData
     */
    public static function fromBytes(string $bytes): LiteralData
    {
        $offset = 0;
        $format = LiteralFormat::from(ord($bytes[$offset++]));
        $length = ord($bytes[$offset++]);
        $filename = substr($bytes, $offset, $length);

        $offset += $length;
        $time = unpack('N', substr($bytes, $offset, 4));

        $offset += 4;
        $data = substr($bytes, $offset);
        $text = ($format == LiteralFormat::Text || $format == LiteralFormat::Utf8) ? $data : '';

        return LiteralData(
            $data, $format, $time, $text, $filename
        );
    }

    /**
     * Builds literal data packet from text
     *
     * @param string $text
     * @param int $time
     * @return LiteralData
     */
    public static function fromText(string $text, int $time = 0): LiteralData
    {
        return LiteralData(
            $text, LiteralFormat::Utf8, $time, $text
        );
    }

    /**
     * Gets data
     *
     * @return string
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * Gets literal format
     *
     * @return LiteralFormat
     */
    public function getFormat(): LiteralFormat
    {
        return $this->format;
    }

    /**
     * Gets time
     *
     * @return int
     */
    public function getTime(): int
    {
        return $this->time;
    }

    /**
     * Gets text
     *
     * @return string
     */
    public function getText(): string
    {
        return $this->text;
    }

    /**
     * Gets filename
     *
     * @return string
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->headerBytes(),
            $this->signBytes(),
        ]);
    }

    public function headerBytes(): string
    {
        return implode([
            chr($this->format->value),
            chr(strlen($this->filename)),
            $this->filename,
            pack('N', $this->time),
        ]);
    }

    /**
     * Gets bytes for sign
     *
     * @return string
     */
    public function signBytes(): string
    {
        return !empty($this->data) ? $this->data : preg_replace('/\r?\n/', "\r\n", $this->text);
    }
}
