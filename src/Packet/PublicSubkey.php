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

use OpenPGP\Enum\{KeyAlgorithm, PacketTag};

/**
 * Public sub key packet class
 * 
 * @package   OpenPGP
 * @category  Packet
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class PublicSubkey extends PublicKey implements SubkeyPacketInterface
{
    /**
     * Constructor
     *
     * @param int $creationTime
     * @param Key\KeyParametersInterface $keyParameters
     * @param KeyAlgorithm $algorithm
     * @return self
     */
    public function __construct(
        int $creationTime,
        Key\KeyParametersInterface $keyParameters,
        KeyAlgorithm $algorithm = KeyAlgorithm::RsaEncryptSign
    )
    {
        parent::__construct($creationTime, $keyParameters, $algorithm);
        $this->setTag(PacketTag::PublicSubkey);
    }

    /**
     * Read public subkey packets from byte string
     *
     * @param string $bytes
     * @return SubkeyPacketInterface
     */
    public static function fromBytes(string $bytes): SubkeyPacketInterface
    {
        $publicKey = PublicKey::fromBytes($bytes);
        return new PublicSubkey(
            $publicKey->getCreationTime(),
            $publicKey->getKeyParameters(),
            $publicKey->getKeyAlgorithm(),
        );
    }
}
