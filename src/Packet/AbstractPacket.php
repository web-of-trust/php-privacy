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
 * Abstract packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
abstract class AbstractPacket implements PacketInterface
{
    /**
     * Constructor
     *
     * @return self
     */
    public function __construct(private PacketTag $tag)
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getTag(): PacketTag
    {
        return $this->tag;
    }

    /**
     * Sets packet tag
     * 
     * @param PacketTag $tag
     * @return self
     */
    protected function setTag(PacketTag $tag): self
    {
        $this->tag = $tag;
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(): string
    {
        $bodyBytes = $this->toBytes();
        $bodyLen = strlen($bodyBytes);
        $data = [];

        $hdr = 0x80 | 0x40 | $this->tag->value;
        if ($bodyLen < 192) {
            $data = [chr($hdr), chr($bodyLen)];
        }
        else if ($bodyLen <= 8383) {
            $data = [
              chr($hdr),
              chr(((($bodyLen - 192) >> 8) & 0xff) + 192),
              chr($bodyLen - 192),
            ];
        }
        else {
            $data = [chr($hdr), "\xff", pack('N', $bodyLen)];
        }
        $data[] = $bodyBytes;

        return implode($data);
    }

    /**
     * Serializes packet data to bytes
     * 
     * @return string
     */
    abstract function toBytes(): string;
}
