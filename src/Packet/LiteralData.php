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
use OpenPGP\Type\{ForSigningInterface, LiteralDataInterface};

/**
 * Implementation of the Literal Data Packet (Tag 11)
 *
 * See RFC 9580, section 5.9.
 *
 * A Literal Data packet contains the body of a message; data that is not to be further interpreted.
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class LiteralData extends AbstractPacket implements
    ForSigningInterface,
    LiteralDataInterface
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
        private readonly string $filename = "",
        ?DateTimeInterface $time = null,
    ) {
        parent::__construct(PacketTag::LiteralData);
        $this->time = $time ?? new \DateTime()->setTimestamp(time());
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
        $time = new \DateTime()->setTimestamp(
            Helper::bytesToLong($bytes, $offset),
        );

        $offset += 4;
        $data = substr($bytes, $offset);

        return new self($data, $format, $filename, $time);
    }

    /**
     * Build literal data packet from text
     *
     * @param string $text
     * @param Format $format
     * @param DateTimeInterface $time
     * @return self
     */
    public static function fromText(
        string $text,
        Format $format = Format::Utf8,
        ?DateTimeInterface $time = null,
    ): self {
        return new self($text, $format, "", $time);
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
            pack("N", $this->time->getTimestamp()),
        ]);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return implode([$this->getHeader(), $this->getSignBytes()]);
    }

    /**
     * {@inheritdoc}
     */
    public function getSignBytes(): string
    {
        if ($this->format === Format::Text || $this->format === Format::Utf8) {
            // Remove trailing whitespace and normalize EOL to canonical form <CR><LF>
            $data = Helper::removeTrailingSpaces(
                mb_convert_encoding($this->data, "UTF-8"),
            );
            return preg_replace(Helper::EOL_PATTERN, Helper::CRLF, $data) ??
                $data;
        } else {
            return $this->data;
        }
    }
}
