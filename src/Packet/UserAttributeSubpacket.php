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

use OpenPGP\Type\SubpacketInterface;

/**
 * User attribute subpacket class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class UserAttributeSubpacket implements SubpacketInterface
{
    /**
     * Constructor
     *
     * @param int $type
     * @param string $data
     * @param bool $isLong
     * @return self
     */
    public function __construct(
        private readonly int $type = 0,
        private readonly string $data = '',
        private readonly bool $isLong = false
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getType(): int
    {
        return $this->type;
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
    public function isLong(): bool
    {
        return $this->isLong;
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        $data = [];
        $bodyLen = strlen($this->data) + 1;
        if ($bodyLen < 192 && !$this->isLong) {
            $data = [
                chr($bodyLen),
                chr($this->type),
                $this->data,
            ];
        }
        elseif ($bodyLen <= 8383 && !$this->isLong) {
            $data = [
                chr(((($bodyLen - 192) >> 8) & 0xff) + 192),
                chr($bodyLen - 192),
                chr($this->type),
                $this->data,
            ];
        }
        else {
            $data = [
                "\xff",
                pack('N', $bodyLen),
                chr($this->type),
                $this->data,
            ];
        }
        return implode($data);
    }
}
