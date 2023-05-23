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

use DateTime;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\LiteralFormat as Format;
use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\{
    ForSigningInterface,
    LiteralDataPacketInterface,
};

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
class LiteralData extends AbstractPacket implements ForSigningInterface, LiteralDataPacketInterface
{
    private readonly DateTime $time;

    /**
     * Constructor
     *
     * @param string $data
     * @param Format $format
     * @param string $filename
     * @param DateTime $time
     * @return self
     */
    public function __construct(
        private readonly string $data,
        private readonly Format $format = Format::Utf8,
        private readonly string $filename = '',
        ?DateTime $time = null
    )
    {
        parent::__construct(PacketTag::LiteralData);
        $this->time = $time ?? (new DateTime())->setTimestamp(time());
    }

    /**
     * Reads literal data packet from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        $format = Format::from(ord($bytes[$offset++]));
        $length = ord($bytes[$offset++]);
        $filename = substr($bytes, $offset, $length);

        $offset += $length;
        $time = (new DateTime())->setTimestamp(
            Helper::bytesToLong($bytes, $offset)
        );

        $offset += 4;
        $data = substr($bytes, $offset);

        return new self(
            $data, $format, $filename, $time
        );
    }

    /**
     * Builds literal data packet from text
     *
     * @param string $text
     * @param DateTime $time
     * @return self
     */
    public static function fromText(
        string $text, ?DateTime $time = null
    ): self
    {
        return new self(
            $text, Format::Utf8, '', $time
        );
    }

    /**
     * {@inheritdoc}
     */
    public function getFormat(): Format
    {
        return $this->format;
    }

    /**
     * {@inheritdoc}
     */
    public function getFilename(): string
    {
        return $this->filename;
    }

    /**
     * {@inheritdoc}
     */
    public function getTime(): DateTime
    {
        return $this->time;
    }

    /**
     * {@inheritdoc}
     */
    public function getData(): string
    {
        return $this->data;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            chr($this->format->value),
            chr(strlen($this->filename)),
            $this->filename,
            pack('N', $this->time->getTimestamp()),
            $this->getSignBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        if ($this->format == Format::Text || $this->format == Format::Utf8) {
            return preg_replace('/\r?\n/m', "\r\n", $this->data);
        }
        else {
            return $this->data;
        }
    }
}
