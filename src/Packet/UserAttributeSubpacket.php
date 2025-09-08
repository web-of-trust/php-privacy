<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Common\Helper;
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
     * @return self
     */
    public function __construct(
        private readonly int $type = 0,
        private readonly string $data = "",
    ) {}

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
    public function toBytes(): string
    {
        return implode([
            Helper::simpleLength(strlen($this->data) + 1),
            chr($this->type),
            $this->data,
        ]);
    }
}
