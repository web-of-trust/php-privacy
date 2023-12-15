<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use DateTimeInterface;
use OpenPGP\Common\Helper;
use OpenPGP\Enum\LiteralFormat as Format;
use OpenPGP\Enum\PacketTag;
use OpenPGP\Type\{
    ForSigningInterface,
    LiteralDataInterface,
};

/**
 * Implementation of the Literal Data Packet (Tag 11)
 * See RFC 4880, section 5.9.
 * 
 * A Literal Data packet contains the body of a message; data that is not to be further interpreted.
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class LiteralData extends AbstractPacket implements ForSigningInterface, LiteralDataInterface
{
    private readonly DateTimeInterface $time;

    /**
     * Constructor
     *
     * @param string $data
     * @param Format $format
     * @param string $filename
     * @param DateTimeInterface $time
     * @return self
     */
    public function __construct(
        private readonly string $data,
        private readonly Format $format = Format::Utf8,
        private readonly string $filename = '',
        ?DateTimeInterface $time = null
    )
    {
        parent::__construct(PacketTag::LiteralData);
        $this->time = $time ?? (new \DateTime())->setTimestamp(time());
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        $offset = 0;
        $format = Format::from(ord($bytes[$offset++]));
        $length = ord($bytes[$offset++]);
        $filename = substr($bytes, $offset, $length);

        $offset += $length;
        $time = (new \DateTime())->setTimestamp(
            Helper::bytesToLong($bytes, $offset)
        );

        $offset += 4;
        $data = substr($bytes, $offset);

        return new self(
            $data, $format, $filename, $time
        );
    }

    /**
     * Build literal data packet from text
     *
     * @param string $text
     * @param DateTimeInterface $time
     * @return self
     */
    public static function fromText(
        string $text, ?DateTimeInterface $time = null
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
    public function getTime(): DateTimeInterface
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
    public function getHeader(): string
    {
        return implode([
            chr($this->format->value),
            chr(strlen($this->filename)),
            $this->filename,
            pack('N', $this->time->getTimestamp()),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([
            $this->getHeader(),
            $this->getSignBytes(),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        if ($this->format == Format::Text || $this->format == Format::Utf8) {
            return preg_replace('/\r?\n/m', "\r\n", $this->data) ?? $this->data;
        }
        else {
            return $this->data;
        }
    }
}
