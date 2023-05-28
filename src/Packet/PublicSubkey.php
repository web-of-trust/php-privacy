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
use OpenPGP\Enum\KeyAlgorithm;
use OpenPGP\Type\{
    KeyParametersInterface,
    SubkeyPacketInterface,
};

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
     * @param DateTime $creationTime
     * @param KeyParametersInterface $keyParameters
     * @param KeyAlgorithm $algorithm
     * @return self
     */
    public function __construct(
        DateTime $creationTime,
        ?KeyParametersInterface $keyParameters = null,
        KeyAlgorithm $algorithm = KeyAlgorithm::RsaEncryptSign
    )
    {
        parent::__construct(
            $creationTime,
            $keyParameters,
            $algorithm
        );
    }

    /**
     * Read public subkey packets from byte string
     *
     * @param string $bytes
     * @return self
     */
    public static function fromBytes(string $bytes): self
    {
        $publicKey = PublicKey::fromBytes($bytes);
        return new self(
            $publicKey->getCreationTime(),
            $publicKey->getKeyParameters(),
            $publicKey->getKeyAlgorithm()
        );
    }
}
