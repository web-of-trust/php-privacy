<?php declare(strict_types=1);
/**
 * This file is part of the PHP Privacy project.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Packet;

use OpenPGP\Type\SubkeyPacketInterface;

/**
 * Public sub key packet class
 *
 * @package  OpenPGP
 * @category Packet
 * @author   Nguyen Van Nguyen - nguyennv1981@gmail.com
 */
class PublicSubkey extends PublicKey implements SubkeyPacketInterface
{
    /**
     * {@inheritdoc}
     */
    public static function fromBytes(string $bytes): self
    {
        [$version, $creationTime, $keyAlgorithm, $keyMaterial] = self::decode(
            $bytes
        );
        return new self($version, $creationTime, $keyMaterial, $keyAlgorithm);
    }
}
