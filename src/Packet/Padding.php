<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Enum\PacketTag;
use phpseclib3\Crypt\Random;

/**
 * Implementation of the Padding Packet Packet (Tag 21)
 * 
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class Padding extends AbstractPacket
{
    /**
     * Constructor
     *
     * @param string $padding
     * @return self
     */
    public function __construct(private string $padding)
    {
        parent::__construct(PacketTag::Padding);
    }

    /**
     * Create random padding.
     *
     * @param int $length - The length of padding to be generated.
     * @return self
     */
    public function createPadding(int $length): self
    {
        $this->padding = Random::string($length);
        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        return new self($bytes);
    }

    /**
     * {@inheritdoc}
     */
    public function toBytes(): string
    {
        return $this->padding;
    }
}
