<?php declare(strict_types=1);
/**
 * This file is part of the PHP PG library.
 *
 * © Nguyen Van Nguyen <nguyennv1981@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace OpenPGP\Message;

use OpenPGP\Enum\SymmetricAlgorithm;
use OpenPGP\Type\{
    EncryptedMessageInterface,
    LiteralMessageInterface,
    LiteralDataPacketInterface,
};

/**
 * OpenPGP literal message class
 *
 * @package   OpenPGP
 * @category  Message
 * @author    Nguyen Van Nguyen - nguyennv1981@gmail.com
 * @copyright Copyright © 2023-present by Nguyen Van Nguyen.
 */
class LiteralMessage implements LiteralMessageInterface
{
    /**
     * Constructor
     *
     * @param LiteralDataPacketInterface $literalDataPacket
     * @return self
     */
    public function __construct(
        private readonly LiteralDataPacketInterface $literalDataPacket
    )
    {
    }

    /**
     * {@inheritdoc}
     */
    public function getLiteralDataPacket(): LiteralDataPacketInterface
    {
        return this->literalDataPacket;
    }

    /**
     * {@inheritdoc}
     */
    public function sign(
        array $signingKeys, ?DateTime $time = null
    ): SignedMessageInterface
    {
    }

    /**
     * {@inheritdoc}
     */
    public function signDetached(
        array $signingKeys, ?DateTime $time = null
    ): SignatureInterface
    {
        $signingKeys = array_filter(
            $signingKeys, static fn ($key) => $key instanceof PrivateKey
        );
        if (empty($signingKeys)) {
            throw new \InvalidArgumentException('No signing keys provided');
        }
        $packets = array_map(
            fn ($key) => SignaturePacket::createLiteralData(
                $key->getSigningKeyPacket(),
                $this->literalDataPacket,
                $time
            ),
            $signingKeys
        );
        return new Signature($packets);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(
        array $encryptionKeys,
        array $passwords = [],
        SymmetricAlgorithm $sessionKeySymmetric = SymmetricAlgorithm::Aes128,
        SymmetricAlgorithm $encryptionKeySymmetric = SymmetricAlgorithm::Aes128
    ): EncryptedMessageInterface
    {
    }
}
